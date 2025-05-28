use crate::rpc::methods::*;
use crate::rpc::protocol::{
    Encoding, ProtocolId, RPCError, SupportedProtocol, ERROR_TYPE_MAX, ERROR_TYPE_MIN,
};
use crate::rpc::RequestType;
use crate::types::ForkContext;
use libp2p::bytes::BufMut;
use libp2p::bytes::BytesMut;
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use ssz::{ContiguousList, DynamicList, SszRead as _, SszReadDefault, SszWrite as _, H256};
use std::io::Cursor;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder};
use types::{
    altair::containers::SignedBeaconBlock as AltairSignedBeaconBlock,
    bellatrix::containers::SignedBeaconBlock as BellatrixSignedBeaconBlock,
    capella::containers::SignedBeaconBlock as CapellaSignedBeaconBlock,
    combined::{
        LightClientBootstrap, LightClientFinalityUpdate, LightClientOptimisticUpdate,
        LightClientUpdate, SignedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::containers::{BlobSidecar, SignedBeaconBlock as DenebSignedBeaconBlock},
    eip7594::DataColumnSidecar,
    electra::containers::SignedBeaconBlock as ElectraSignedBeaconBlock,
    nonstandard::Phase,
    phase0::{containers::SignedBeaconBlock as Phase0SignedBeaconBlock, primitives::ForkDigest},
    preset::Preset,
};

use unsigned_varint::codec::Uvi;

const CONTEXT_BYTES_LEN: usize = 4;

/* Inbound Codec */

pub struct SSZSnappyInboundCodec<P: Preset> {
    chain_config: Arc<ChainConfig>,
    protocol: ProtocolId,
    inner: Uvi<usize>,
    len: Option<usize>,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    fork_context: Arc<ForkContext>,
    phantom: PhantomData<P>,
}

impl<P: Preset> SSZSnappyInboundCodec<P> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        protocol: ProtocolId,
        max_packet_size: usize,
        fork_context: Arc<ForkContext>,
    ) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyInboundCodec {
            chain_config,
            inner: uvi_codec,
            protocol,
            len: None,
            phantom: PhantomData,
            fork_context,
            max_packet_size,
        }
    }

    /// Encodes RPC Responses sent to peers.
    fn encode_response(
        &mut self,
        item: RpcResponse<P>,
        dst: &mut BytesMut,
    ) -> Result<(), RPCError> {
        let bytes = match &item {
            RpcResponse::Success(resp) => match &resp {
                RpcSuccessResponse::Status(res) => res.to_ssz()?,
                RpcSuccessResponse::BlocksByRange(res) => res.to_ssz()?,
                RpcSuccessResponse::BlocksByRoot(res) => res.to_ssz()?,
                RpcSuccessResponse::BlobsByRange(res) => res.to_ssz()?,
                RpcSuccessResponse::BlobsByRoot(res) => res.to_ssz()?,
                RpcSuccessResponse::DataColumnsByRoot(res) => res.to_ssz()?,
                RpcSuccessResponse::DataColumnsByRange(res) => res.to_ssz()?,
                RpcSuccessResponse::LightClientBootstrap(res) => res.to_ssz()?,
                RpcSuccessResponse::LightClientOptimisticUpdate(res) => res.to_ssz()?,
                RpcSuccessResponse::LightClientFinalityUpdate(res) => res.to_ssz()?,
                RpcSuccessResponse::LightClientUpdatesByRange(res) => res.to_ssz()?,
                RpcSuccessResponse::Pong(res) => res.data.to_ssz()?,
                RpcSuccessResponse::MetaData(res) =>
                // Encode the correct version of the MetaData response based on the negotiated version.
                {
                    match self.protocol.versioned_protocol {
                        SupportedProtocol::MetaDataV1 => res.metadata_v1().to_ssz()?,
                        SupportedProtocol::MetaDataV2 => res.metadata_v2().to_ssz()?,
                        SupportedProtocol::MetaDataV3 => res
                            .metadata_v3(&self.fork_context.chain_config())
                            .to_ssz()?,
                        _ => unreachable!(
                            "We only send metadata responses on negotiating metadata requests"
                        ),
                    }
                }
            },
            RpcResponse::Error(_, err) => err.to_ssz()?,
            RpcResponse::StreamTermination(_) => {
                unreachable!("Code error - attempting to encode a stream termination")
            }
        };

        // SSZ encoded bytes should be within `max_packet_size`
        if bytes.len() > self.max_packet_size {
            return Err(RPCError::InternalError(
                "attempting to encode data > max_packet_size",
            ));
        }

        // Add context bytes if required
        if let Some(ref context_bytes) = context_bytes(&self.protocol, &self.fork_context, &item) {
            dst.extend_from_slice(context_bytes.as_bytes());
        }

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        self.inner
            .encode(bytes.len(), dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());
        Ok(())
    }
}

// Encoder for inbound streams: Encodes RPC Responses sent to peers.
impl<P: Preset> Encoder<RpcResponse<P>> for SSZSnappyInboundCodec<P> {
    type Error = RPCError;

    fn encode(&mut self, item: RpcResponse<P>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.clear();
        dst.reserve(1);
        dst.put_u8(
            item.as_u8()
                .expect("Should never encode a stream termination"),
        );

        let result = self.encode_response(item, dst);
        let count: u64 = dst
            .len()
            .try_into()
            .map_err(|_| RPCError::InvalidData("byte count does not fit in u64".into()))?;

        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_SENT_BYTES, count);
        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_TOTAL_BYTES, count);

        result
    }
}

// Decoder for inbound streams: Decodes RPC requests from peers
impl<P: Preset> Decoder for SSZSnappyInboundCodec<P> {
    type Item = RequestType<P>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let count: u64 = src
            .len()
            .try_into()
            .map_err(|_| RPCError::InvalidData("byte count does not fit in u64".into()))?;

        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_RECV_BYTES, count);
        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_TOTAL_BYTES, count);

        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV1 {
            return Ok(Some(RequestType::MetaData(MetadataRequest::new_v1())));
        }
        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV2 {
            return Ok(Some(RequestType::MetaData(MetadataRequest::new_v2())));
        }
        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV3 {
            return Ok(Some(RequestType::MetaData(MetadataRequest::new_v3())));
        }
        let Some(length) = handle_length(&mut self.inner, &mut self.len, src)? else {
            return Ok(None);
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self
            .protocol
            .rpc_request_limits(&self.chain_config, self.fork_context.current_fork())?;

        if ssz_limits.is_out_of_bounds(length, self.max_packet_size) {
            return Err(RPCError::InvalidData(format!(
                "RPC request length for protocol {:?} is out of bounds, length {}",
                self.protocol.versioned_protocol, length
            )));
        }
        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;

        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);
        let mut decoded_buffer = vec![0; length];

        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                handle_rpc_request(
                    &self.chain_config,
                    self.protocol.versioned_protocol,
                    &decoded_buffer,
                    self.fork_context.current_fork(),
                )
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

/* Outbound Codec: Codec for initiating RPC requests */
pub struct SSZSnappyOutboundCodec<P: Preset> {
    inner: Uvi<usize>,
    len: Option<usize>,
    protocol: ProtocolId,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    /// The phase corresponding to the received context bytes.
    phase: Option<Phase>,
    fork_context: Arc<ForkContext>,
    /// Keeps track of the current response code for a chunk.
    current_response_code: Option<u8>,
    phantom: PhantomData<P>,
}

impl<P: Preset> SSZSnappyOutboundCodec<P> {
    pub fn new(
        protocol: ProtocolId,
        max_packet_size: usize,
        fork_context: Arc<ForkContext>,
    ) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyOutboundCodec {
            inner: uvi_codec,
            protocol,
            max_packet_size,
            len: None,
            phase: None,
            fork_context,
            phantom: PhantomData,
            current_response_code: None,
        }
    }

    // Decode an Rpc response.
    fn decode_response(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<RpcSuccessResponse<P>>, RPCError> {
        // Read the context bytes if required
        if self.protocol.has_context_bytes() && self.phase.is_none() {
            if src.len() >= CONTEXT_BYTES_LEN {
                let context_bytes = ForkDigest::from_slice(&src.split_to(CONTEXT_BYTES_LEN));
                self.phase = Some(context_bytes_to_phase(
                    context_bytes,
                    self.fork_context.clone(),
                )?);
            } else {
                return Ok(None);
            }
        }
        let Some(length) = handle_length(&mut self.inner, &mut self.len, src)? else {
            return Ok(None);
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self.protocol.rpc_response_limits::<P>(&self.fork_context)?;
        if ssz_limits.is_out_of_bounds(length, self.max_packet_size) {
            return Err(RPCError::InvalidData(format!(
                "RPC response length is out of bounds, length {}, max {}, min {}, max_packet_size: {}",
                length, ssz_limits.max, ssz_limits.min, self.max_packet_size,
            )));
        }
        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;
        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);

        let mut decoded_buffer = vec![0; length];

        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                // Safe to `take` from `self.fork_name` as we have all the bytes we need to
                // decode an ssz object at this point.
                let phase = self.phase;
                self.phase = None;
                handle_rpc_response(self.protocol.versioned_protocol, &decoded_buffer, phase)
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }

    fn decode_error(&mut self, src: &mut BytesMut) -> Result<Option<ErrorType>, RPCError> {
        let Some(length) = handle_length(&mut self.inner, &mut self.len, src)? else {
            return Ok(None);
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `ErrorType`.
        if length > self.max_packet_size || length > ERROR_TYPE_MAX || length < ERROR_TYPE_MIN {
            return Err(RPCError::InvalidData(format!(
                "RPC Error length is out of bounds, length {}",
                length
            )));
        }

        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;
        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);
        let mut decoded_buffer = vec![0; length];
        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                Ok(Some(ErrorType(ContiguousList::from_ssz_default(
                    &decoded_buffer,
                )?)))
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

// Encoder for outbound streams: Encodes RPC Requests to peers
impl<P: Preset> Encoder<RequestType<P>> for SSZSnappyOutboundCodec<P> {
    type Error = RPCError;

    fn encode(&mut self, item: RequestType<P>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RequestType::Status(req) => req.to_ssz()?,
            RequestType::Goodbye(req) => req.to_ssz()?,
            RequestType::BlocksByRange(r) => match r {
                OldBlocksByRangeRequest::V1(req) => req.to_ssz()?,
                OldBlocksByRangeRequest::V2(req) => req.to_ssz()?,
            },
            RequestType::BlocksByRoot(r) => match r {
                BlocksByRootRequest::V1(req) => req.block_roots.to_ssz()?,
                BlocksByRootRequest::V2(req) => req.block_roots.to_ssz()?,
            },
            RequestType::BlobsByRange(req) => req.to_ssz()?,
            RequestType::BlobsByRoot(req) => req.blob_ids.to_ssz()?,
            RequestType::DataColumnsByRange(req) => req.to_ssz()?,
            RequestType::DataColumnsByRoot(req) => req.data_column_ids.to_ssz()?,
            RequestType::Ping(req) => req.to_ssz()?,
            RequestType::LightClientBootstrap(req) => req.to_ssz()?,
            RequestType::LightClientUpdatesByRange(req) => req.to_ssz()?,
            // no metadata to encode
            RequestType::MetaData(_)
            | RequestType::LightClientOptimisticUpdate
            | RequestType::LightClientFinalityUpdate => return Ok(()),
        };

        // SSZ encoded bytes should be within `max_packet_size`
        if bytes.len() > self.max_packet_size {
            return Err(RPCError::InternalError(
                "attempting to encode data > max_packet_size",
            ));
        }

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        self.inner
            .encode(bytes.len(), dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());

        let count: u64 = dst
            .len()
            .try_into()
            .map_err(|_| RPCError::InvalidData("byte count does not fit in u64".into()))?;

        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_SENT_BYTES, count);
        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_TOTAL_BYTES, count);

        Ok(())
    }
}

// Decoder for outbound streams: Decodes RPC responses from peers.
//
// The majority of the decoding has now been pushed upstream due to the changing specification.
// We prefer to decode blocks and attestations with extra knowledge about the chain to perform
// faster verification checks before decoding entire blocks/attestations.
impl<P: Preset> Decoder for SSZSnappyOutboundCodec<P> {
    type Item = RpcResponse<P>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // if we have only received the response code, wait for more bytes
        if src.len() <= 1 {
            return Ok(None);
        }

        let count: u64 = src
            .len()
            .try_into()
            .map_err(|_| RPCError::InvalidData("byte count does not fit in u64".into()))?;

        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_RECV_BYTES, count);
        crate::common::metrics::inc_counter_by(&crate::metrics::RPC_TOTAL_BYTES, count);

        // using the response code determine which kind of payload needs to be decoded.
        let response_code = self.current_response_code.unwrap_or_else(|| {
            let resp_code = src.split_to(1)[0];
            self.current_response_code = Some(resp_code);
            resp_code
        });

        let inner_result = {
            if RpcResponse::<P>::is_response(response_code) {
                // decode an actual response and mutates the buffer if enough bytes have been read
                // returning the result.
                self.decode_response(src)
                    .map(|r| r.map(RpcResponse::Success))
            } else {
                // decode an error
                self.decode_error(src)
                    .map(|r| r.map(|resp| RpcResponse::from_error(response_code, resp)))
            }
        };
        // if the inner decoder was capable of decoding a chunk, we need to reset the current
        // response code for the next chunk
        if let Ok(Some(_)) = inner_result {
            self.current_response_code = None;
        }
        // return the result
        inner_result
    }
}

/// Handle errors that we get from decoding an RPC message from the stream.
/// `num_bytes_read` is the number of bytes the snappy decoder has read from the underlying stream.
/// `max_compressed_len` is the maximum compressed size for a given uncompressed size.
fn handle_error<T>(
    err: std::io::Error,
    num_bytes: u64,
    max_compressed_len: u64,
) -> Result<Option<T>, RPCError> {
    match err.kind() {
        ErrorKind::UnexpectedEof => {
            // If snappy has read `max_compressed_len` from underlying stream and still can't fill buffer, we have a malicious message.
            // Report as `InvalidData` so that malicious peer gets banned.
            if num_bytes >= max_compressed_len {
                Err(RPCError::InvalidData(format!(
                    "Received malicious snappy message, num_bytes {}, max_compressed_len {}",
                    num_bytes, max_compressed_len
                )))
            } else {
                // Haven't received enough bytes to decode yet, wait for more
                Ok(None)
            }
        }
        _ => Err(RPCError::from(err)),
    }
}

/// Returns `Some(context_bytes)` for encoding RPC responses that require context bytes.
/// Returns `None` when context bytes are not required.
fn context_bytes<P: Preset>(
    protocol: &ProtocolId,
    fork_context: &ForkContext,
    resp: &RpcResponse<P>,
) -> Option<ForkDigest> {
    // Add the context bytes if required
    if protocol.has_context_bytes() {
        if let RpcResponse::Success(rpc_variant) = resp {
            match rpc_variant {
                RpcSuccessResponse::BlocksByRange(ref_box_block)
                | RpcSuccessResponse::BlocksByRoot(ref_box_block) => {
                    return match **ref_box_block {
                        // NOTE: If you are adding another fork type here, be sure to modify the
                        //       `fork_context.to_context_bytes()` function to support it as well!
                        SignedBeaconBlock::Electra { .. } => {
                            fork_context.to_context_bytes(Phase::Electra)
                        }
                        SignedBeaconBlock::Deneb { .. } => {
                            fork_context.to_context_bytes(Phase::Deneb)
                        }
                        SignedBeaconBlock::Capella { .. } => {
                            fork_context.to_context_bytes(Phase::Capella)
                        }
                        SignedBeaconBlock::Bellatrix { .. } => {
                            // Bellatrix context being `None` implies that "merge never happened".
                            fork_context.to_context_bytes(Phase::Bellatrix)
                        }
                        SignedBeaconBlock::Altair { .. } => {
                            // Altair context being `None` implies that "altair never happened".
                            // This code should be unreachable if altair is disabled since only Version::V1 would be valid in that case.
                            fork_context.to_context_bytes(Phase::Altair)
                        }
                        SignedBeaconBlock::Phase0 { .. } => {
                            Some(fork_context.genesis_context_bytes())
                        }
                    };
                }
                RpcSuccessResponse::BlobsByRange(_) | RpcSuccessResponse::BlobsByRoot(_) => {
                    return fork_context.to_context_bytes(Phase::Deneb);
                }
                RpcSuccessResponse::DataColumnsByRoot(d)
                | RpcSuccessResponse::DataColumnsByRange(d) => {
                    // TODO(das): Remove deneb fork after `peerdas-devnet-2`.
                    return if matches!(
                        fork_context.chain_config().phase_at_slot::<P>(d.slot()),
                        Phase::Deneb
                    ) {
                        fork_context.to_context_bytes(Phase::Deneb)
                    } else {
                        fork_context.to_context_bytes(Phase::Electra)
                    };
                }
                RpcSuccessResponse::LightClientBootstrap(lc_bootstrap) => {
                    return match **lc_bootstrap {
                        LightClientBootstrap::Electra(_) => {
                            fork_context.to_context_bytes(Phase::Electra)
                        }
                        LightClientBootstrap::Deneb(_) => {
                            fork_context.to_context_bytes(Phase::Deneb)
                        }
                        LightClientBootstrap::Capella(_) => {
                            fork_context.to_context_bytes(Phase::Capella)
                        }
                        LightClientBootstrap::Altair(_) => {
                            fork_context.to_context_bytes(Phase::Altair)
                        }
                    }
                }
                RpcSuccessResponse::LightClientOptimisticUpdate(lc_optimistic_update) => {
                    return match **lc_optimistic_update {
                        LightClientOptimisticUpdate::Electra(_) => {
                            fork_context.to_context_bytes(Phase::Electra)
                        }
                        LightClientOptimisticUpdate::Deneb(_) => {
                            fork_context.to_context_bytes(Phase::Deneb)
                        }
                        LightClientOptimisticUpdate::Capella(_) => {
                            fork_context.to_context_bytes(Phase::Capella)
                        }
                        LightClientOptimisticUpdate::Altair(_) => {
                            fork_context.to_context_bytes(Phase::Altair)
                        }
                    }
                }
                RpcSuccessResponse::LightClientFinalityUpdate(lc_finality_update) => {
                    return match **lc_finality_update {
                        LightClientFinalityUpdate::Electra(_) => {
                            fork_context.to_context_bytes(Phase::Electra)
                        }
                        LightClientFinalityUpdate::Deneb(_) => {
                            fork_context.to_context_bytes(Phase::Deneb)
                        }
                        LightClientFinalityUpdate::Capella(_) => {
                            fork_context.to_context_bytes(Phase::Capella)
                        }
                        LightClientFinalityUpdate::Altair(_) => {
                            fork_context.to_context_bytes(Phase::Altair)
                        }
                    }
                }
                RpcSuccessResponse::LightClientUpdatesByRange(lc_update) => {
                    return match **lc_update {
                        LightClientUpdate::Electra(_) => {
                            fork_context.to_context_bytes(Phase::Electra)
                        }
                        LightClientUpdate::Deneb(_) => fork_context.to_context_bytes(Phase::Deneb),
                        LightClientUpdate::Capella(_) => {
                            fork_context.to_context_bytes(Phase::Capella)
                        }
                        LightClientUpdate::Altair(_) => {
                            fork_context.to_context_bytes(Phase::Altair)
                        }
                    }
                }
                // These will not pass the has_context_bytes() check
                RpcSuccessResponse::Status(_)
                | RpcSuccessResponse::Pong(_)
                | RpcSuccessResponse::MetaData(_) => {
                    return None;
                }
            }
        }
    }

    None
}

/// Decodes the length-prefix from the bytes as an unsigned protobuf varint.
///
/// Returns `Ok(Some(length))` by decoding the bytes if required.
/// Returns `Ok(None)` if more bytes are needed to decode the length-prefix.
/// Returns an `RPCError` for a decoding error.
fn handle_length(
    uvi_codec: &mut Uvi<usize>,
    len: &mut Option<usize>,
    bytes: &mut BytesMut,
) -> Result<Option<usize>, RPCError> {
    if let Some(length) = len {
        Ok(Some(*length))
    } else {
        // Decode the length of the uncompressed bytes from an unsigned varint
        // Note: length-prefix of > 10 bytes(uint64) would be a decoding error
        match uvi_codec.decode(bytes).map_err(RPCError::from)? {
            Some(length) => {
                *len = Some(length);
                Ok(Some(length))
            }
            None => Ok(None), // need more bytes to decode length
        }
    }
}

/// Decodes an `InboundRequest` from the byte stream.
/// `decoded_buffer` should be an ssz-encoded bytestream with
// length = length-prefix received in the beginning of the stream.
fn handle_rpc_request<P: Preset>(
    config: &ChainConfig,
    versioned_protocol: SupportedProtocol,
    decoded_buffer: &[u8],
    current_phase: Phase,
) -> Result<Option<RequestType<P>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(RequestType::Status(
            StatusMessage::from_ssz_default(decoded_buffer)?,
        ))),
        SupportedProtocol::GoodbyeV1 => Ok(Some(RequestType::Goodbye(
            GoodbyeReason::from_ssz_default(decoded_buffer)?,
        ))),
        SupportedProtocol::BlocksByRangeV2 => Ok(Some(RequestType::BlocksByRange(
            OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2::from_ssz_default(
                decoded_buffer,
            )?),
        ))),
        SupportedProtocol::BlocksByRangeV1 => Ok(Some(RequestType::BlocksByRange(
            OldBlocksByRangeRequest::V1(OldBlocksByRangeRequestV1::from_ssz_default(
                decoded_buffer,
            )?),
        ))),
        SupportedProtocol::BlocksByRootV2 => Ok(Some(RequestType::BlocksByRoot(
            BlocksByRootRequest::V2(BlocksByRootRequestV2 {
                block_roots: DynamicList::from_ssz(
                    &(config.max_request_blocks(current_phase) as usize),
                    decoded_buffer,
                )?,
            }),
        ))),
        SupportedProtocol::BlocksByRootV1 => Ok(Some(RequestType::BlocksByRoot(
            BlocksByRootRequest::V1(BlocksByRootRequestV1 {
                block_roots: DynamicList::from_ssz(
                    &(config.max_request_blocks(current_phase) as usize),
                    decoded_buffer,
                )?,
            }),
        ))),
        SupportedProtocol::BlobsByRangeV1 => Ok(Some(RequestType::BlobsByRange(
            BlobsByRangeRequest::from_ssz_default(decoded_buffer)?,
        ))),
        SupportedProtocol::BlobsByRootV1 => {
            Ok(Some(RequestType::BlobsByRoot(BlobsByRootRequest {
                blob_ids: DynamicList::from_ssz(
                    &(config.max_request_blob_sidecars(current_phase) as usize),
                    decoded_buffer,
                )?,
            })))
        }
        SupportedProtocol::DataColumnsByRangeV1 => Ok(Some(RequestType::DataColumnsByRange(
            DataColumnsByRangeRequest::from_ssz_default(decoded_buffer)?,
        ))),
        SupportedProtocol::DataColumnsByRootV1 => Ok(Some(RequestType::DataColumnsByRoot(
            DataColumnsByRootRequest {
                data_column_ids: DynamicList::from_ssz(
                    &(config.max_request_data_column_sidecars as usize),
                    decoded_buffer,
                )?,
            },
        ))),
        SupportedProtocol::PingV1 => Ok(Some(RequestType::Ping(Ping {
            data: u64::from_ssz_default(decoded_buffer)?,
        }))),
        SupportedProtocol::LightClientBootstrapV1 => Ok(Some(RequestType::LightClientBootstrap(
            LightClientBootstrapRequest {
                root: H256::from_ssz_default(decoded_buffer)?,
            },
        ))),
        SupportedProtocol::LightClientOptimisticUpdateV1 => {
            Ok(Some(RequestType::LightClientOptimisticUpdate))
        }
        SupportedProtocol::LightClientFinalityUpdateV1 => {
            Ok(Some(RequestType::LightClientFinalityUpdate))
        }
        SupportedProtocol::LightClientUpdatesByRangeV1 => {
            Ok(Some(RequestType::LightClientUpdatesByRange(
                LightClientUpdatesByRangeRequest::from_ssz_default(decoded_buffer)?,
            )))
        }
        // MetaData requests return early from InboundUpgrade and do not reach the decoder.
        // Handle this case just for completeness.
        SupportedProtocol::MetaDataV3 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InternalError(
                    "Metadata requests shouldn't reach decoder",
                ))
            } else {
                Ok(Some(RequestType::MetaData(MetadataRequest::new_v3())))
            }
        }
        SupportedProtocol::MetaDataV2 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InternalError(
                    "Metadata requests shouldn't reach decoder",
                ))
            } else {
                Ok(Some(RequestType::MetaData(MetadataRequest::new_v2())))
            }
        }
        SupportedProtocol::MetaDataV1 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InvalidData("Metadata request".to_string()))
            } else {
                Ok(Some(RequestType::MetaData(MetadataRequest::new_v1())))
            }
        }
    }
}

/// Decodes a `RPCResponse` from the byte stream.
/// `decoded_buffer` should be an ssz-encoded bytestream with
/// length = length-prefix received in the beginning of the stream.
///
/// For BlocksByRange/BlocksByRoot reponses, decodes the appropriate response
/// according to the received `ForkName`.
fn handle_rpc_response<P: Preset>(
    versioned_protocol: SupportedProtocol,
    decoded_buffer: &[u8],
    fork_name: Option<Phase>,
) -> Result<Option<RpcSuccessResponse<P>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(RpcSuccessResponse::Status(
            StatusMessage::from_ssz_default(decoded_buffer)?,
        ))),
        // This case should be unreachable as `Goodbye` has no response.
        SupportedProtocol::GoodbyeV1 => Err(RPCError::InvalidData(
            "Goodbye RPC message has no valid response".to_string(),
        )),
        SupportedProtocol::BlocksByRangeV1 => Ok(Some(RpcSuccessResponse::BlocksByRange(
            Arc::new(SignedBeaconBlock::Phase0(
                Phase0SignedBeaconBlock::from_ssz_default(decoded_buffer)?,
            )),
        ))),
        SupportedProtocol::BlocksByRootV1 => Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
            SignedBeaconBlock::Phase0(Phase0SignedBeaconBlock::from_ssz_default(decoded_buffer)?),
        )))),
        SupportedProtocol::BlobsByRangeV1 => match fork_name {
            Some(Phase::Deneb | Phase::Electra) => Ok(Some(RpcSuccessResponse::BlobsByRange(
                Arc::new(BlobSidecar::from_ssz_default(decoded_buffer)?),
            ))),
            Some(Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella) => {
                Err(RPCError::ErrorResponse(
                    RpcErrorResponse::InvalidRequest,
                    "Invalid fork name for blobs by range".to_string(),
                ))
            }
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::BlobsByRootV1 => match fork_name {
            Some(Phase::Deneb | Phase::Electra) => Ok(Some(RpcSuccessResponse::BlobsByRoot(
                Arc::new(BlobSidecar::from_ssz_default(decoded_buffer)?),
            ))),
            Some(Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella) => {
                Err(RPCError::ErrorResponse(
                    RpcErrorResponse::InvalidRequest,
                    "Invalid fork name for blobs by root".to_string(),
                ))
            }
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::DataColumnsByRootV1 => match fork_name {
            // TODO(das): PeerDAS is currently supported for both deneb and electra. This check
            // does not advertise the topic on deneb, simply allows it to decode it. Advertise
            // logic is in `SupportedTopic::currently_supported`.
            Some(Phase::Deneb | Phase::Electra) => Ok(Some(RpcSuccessResponse::DataColumnsByRoot(
                Arc::new(DataColumnSidecar::from_ssz_default(decoded_buffer)?),
            ))),
            Some(Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella) => {
                Err(RPCError::ErrorResponse(
                    RpcErrorResponse::InvalidRequest,
                    "Invalid fork name for data columns by root".to_string(),
                ))
            }
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::DataColumnsByRangeV1 => match fork_name {
            Some(Phase::Deneb | Phase::Electra) => {
                Ok(Some(RpcSuccessResponse::DataColumnsByRange(Arc::new(
                    DataColumnSidecar::from_ssz_default(decoded_buffer)?,
                ))))
            }
            Some(Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella) => {
                Err(RPCError::ErrorResponse(
                    RpcErrorResponse::InvalidRequest,
                    "Invalid fork name for data columns by range".to_string(),
                ))
            }
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::PingV1 => Ok(Some(RpcSuccessResponse::Pong(Ping {
            data: u64::from_ssz_default(decoded_buffer)?,
        }))),
        SupportedProtocol::MetaDataV1 => Ok(Some(RpcSuccessResponse::MetaData(MetaData::V1(
            MetaDataV1::from_ssz_default(decoded_buffer)?,
        )))),
        SupportedProtocol::LightClientBootstrapV1 => match fork_name {
            Some(Phase::Phase0) => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!("light_client_bootstrap topic invalid for given fork {fork_name:?}",),
            )),
            Some(Phase::Altair | Phase::Bellatrix) => {
                Ok(Some(RpcSuccessResponse::LightClientBootstrap(
                    SszReadDefault::from_ssz_default(decoded_buffer)
                        .map(LightClientBootstrap::Altair)
                        .map(Arc::new)?,
                )))
            }
            Some(Phase::Capella) => Ok(Some(RpcSuccessResponse::LightClientBootstrap(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientBootstrap::Capella)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Deneb) => Ok(Some(RpcSuccessResponse::LightClientBootstrap(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientBootstrap::Deneb)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Electra) => Ok(Some(RpcSuccessResponse::LightClientBootstrap(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientBootstrap::Electra)
                    .map(Arc::new)?,
            ))),
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::LightClientOptimisticUpdateV1 => match fork_name {
            Some(Phase::Phase0) => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "light_client_optimistic_update topic invalid for given fork {fork_name:?}",
                ),
            )),
            Some(Phase::Altair | Phase::Bellatrix) => {
                Ok(Some(RpcSuccessResponse::LightClientOptimisticUpdate(
                    SszReadDefault::from_ssz_default(decoded_buffer)
                        .map(LightClientOptimisticUpdate::Altair)
                        .map(Arc::new)?,
                )))
            }
            Some(Phase::Capella) => Ok(Some(RpcSuccessResponse::LightClientOptimisticUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientOptimisticUpdate::Capella)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Deneb) => Ok(Some(RpcSuccessResponse::LightClientOptimisticUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientOptimisticUpdate::Deneb)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Electra) => Ok(Some(RpcSuccessResponse::LightClientOptimisticUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientOptimisticUpdate::Electra)
                    .map(Arc::new)?,
            ))),
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::LightClientFinalityUpdateV1 => match fork_name {
            Some(Phase::Phase0) => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!("light_client_finality_update topic invalid for given fork {fork_name:?}",),
            )),
            Some(Phase::Altair | Phase::Bellatrix) => {
                Ok(Some(RpcSuccessResponse::LightClientFinalityUpdate(
                    SszReadDefault::from_ssz_default(decoded_buffer)
                        .map(LightClientFinalityUpdate::Altair)
                        .map(Arc::new)?,
                )))
            }
            Some(Phase::Capella) => Ok(Some(RpcSuccessResponse::LightClientFinalityUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientFinalityUpdate::Capella)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Deneb) => Ok(Some(RpcSuccessResponse::LightClientFinalityUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientFinalityUpdate::Deneb)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Electra) => Ok(Some(RpcSuccessResponse::LightClientFinalityUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientFinalityUpdate::Electra)
                    .map(Arc::new)?,
            ))),
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::LightClientUpdatesByRangeV1 => match fork_name {
            Some(Phase::Phase0) => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!("light_client_updates topic invalid for given fork {fork_name:?}",),
            )),
            Some(Phase::Altair | Phase::Bellatrix) => {
                Ok(Some(RpcSuccessResponse::LightClientUpdatesByRange(
                    SszReadDefault::from_ssz_default(decoded_buffer)
                        .map(LightClientUpdate::Altair)
                        .map(Arc::new)?,
                )))
            }
            Some(Phase::Capella) => Ok(Some(RpcSuccessResponse::LightClientUpdatesByRange(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientUpdate::Capella)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Deneb) => Ok(Some(RpcSuccessResponse::LightClientUpdatesByRange(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientUpdate::Deneb)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Electra) => Ok(Some(RpcSuccessResponse::LightClientUpdatesByRange(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientUpdate::Electra)
                    .map(Arc::new)?,
            ))),
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        // MetaData V2/V3 responses have no context bytes, so behave similarly to V1 responses
        SupportedProtocol::MetaDataV3 => Ok(Some(RpcSuccessResponse::MetaData(MetaData::V3(
            MetaDataV3::from_ssz_default(decoded_buffer)?,
        )))),
        SupportedProtocol::MetaDataV2 => Ok(Some(RpcSuccessResponse::MetaData(MetaData::V2(
            MetaDataV2::from_ssz_default(decoded_buffer)?,
        )))),
        SupportedProtocol::BlocksByRangeV2 => match fork_name {
            Some(Phase::Altair) => Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Altair(AltairSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Phase0) => Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Phase0(Phase0SignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Bellatrix) => Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Bellatrix(BellatrixSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Capella) => Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Capella(CapellaSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Deneb) => Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Deneb(DenebSignedBeaconBlock::from_ssz_default(decoded_buffer)?),
            )))),
            Some(Phase::Electra) => Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Electra(ElectraSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::BlocksByRootV2 => match fork_name {
            Some(Phase::Altair) => Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Altair(AltairSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Phase0) => Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Phase0(Phase0SignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Bellatrix) => Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Bellatrix(BellatrixSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Capella) => Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Capella(CapellaSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Deneb) => Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Deneb(DenebSignedBeaconBlock::from_ssz_default(decoded_buffer)?),
            )))),
            Some(Phase::Electra) => Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Electra(ElectraSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            None => Err(RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
    }
}

/// Takes the context bytes and a fork_context and returns the corresponding phase.
fn context_bytes_to_phase(
    context_bytes: ForkDigest,
    fork_context: Arc<ForkContext>,
) -> Result<Phase, RPCError> {
    fork_context
        .from_context_bytes(context_bytes)
        .cloned()
        .ok_or_else(|| {
            let encoded = hex::encode(context_bytes);
            RPCError::ErrorResponse(
                RpcErrorResponse::InvalidRequest,
                format!(
                    "Context bytes {} do not correspond to a valid fork",
                    encoded
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        factory,
        rpc::{methods::StatusMessage, protocol::*, Ping},
        types::{EnrAttestationBitfield, ForkContext},
        EnrSyncCommitteeBitfield,
    };
    use anyhow::Result;
    use snap::write::FrameEncoder;
    use ssz::{ByteList, DynamicList};
    use std::io::Write;
    use std::sync::Arc;
    use std_ext::ArcExt as _;
    use try_from_iterator::TryFromIterator as _;
    use types::{
        bellatrix::containers::{
            BeaconBlock as BellatrixBeaconBlock, BeaconBlockBody as BellatrixBeaconBlockBody,
            ExecutionPayload, SignedBeaconBlock as BellatrixSignedBeaconBlock,
        },
        combined::SignedBeaconBlock,
        config::Config,
        deneb::containers::BlobIdentifier,
        eip7594::DataColumnIdentifier,
        phase0::primitives::{ForkDigest, H256},
        preset::Mainnet,
    };

    fn phase0_block<P: Preset>() -> SignedBeaconBlock<P> {
        factory::full_phase0_signed_beacon_block().into()
    }
    fn altair_block<P: Preset>() -> SignedBeaconBlock<P> {
        factory::full_altair_signed_beacon_block().into()
    }

    /// Smallest sized block across all current forks. Useful for testing
    /// min length check conditions.
    fn empty_base_block<P: Preset>() -> SignedBeaconBlock<P> {
        factory::empty_phase0_signed_beacon_block().into()
    }

    fn empty_blob_sidecar<P: Preset>() -> Arc<BlobSidecar<P>> {
        Arc::new(BlobSidecar::default())
    }

    fn empty_data_column_sidecar<P: Preset>() -> Arc<DataColumnSidecar<P>> {
        Arc::new(DataColumnSidecar::default())
    }

    /// Bellatrix block with length < max_rpc_size.
    fn bellatrix_block_small<P: Preset>() -> BellatrixSignedBeaconBlock<P> {
        let tx = ByteList::<P::MaxBytesPerTransaction>::from_ssz_default([0; 1024]).unwrap();
        let txs = Arc::new(ContiguousList::try_from_iter(std::iter::repeat_n(tx, 5000)).unwrap());

        let block = BellatrixSignedBeaconBlock {
            message: BellatrixBeaconBlock {
                body: BellatrixBeaconBlockBody {
                    execution_payload: ExecutionPayload {
                        transactions: txs,
                        ..ExecutionPayload::default()
                    },
                    ..BellatrixBeaconBlockBody::default()
                },
                ..BellatrixBeaconBlock::default()
            },
            ..BellatrixSignedBeaconBlock::default()
        };

        assert!(block.to_ssz().unwrap().len() <= Config::mainnet().max_payload_size);
        block
    }

    /// Bellatrix block with length > MAX_RPC_SIZE.
    /// The max limit for a merge block is in the order of ~16GiB which wouldn't fit in memory.
    /// Hence, we generate a merge block just greater than `MAX_RPC_SIZE` to test rejection on the rpc layer.
    fn bellatrix_block_large<P: Preset>() -> BellatrixSignedBeaconBlock<P> {
        let tx = ByteList::<P::MaxBytesPerTransaction>::from_ssz_default([0; 1024]).unwrap();
        let txs = Arc::new(ContiguousList::try_from_iter(std::iter::repeat_n(tx, 100000)).unwrap());

        let block = BellatrixSignedBeaconBlock {
            message: BellatrixBeaconBlock {
                body: BellatrixBeaconBlockBody {
                    execution_payload: ExecutionPayload {
                        transactions: txs,
                        ..ExecutionPayload::default()
                    },
                    ..BellatrixBeaconBlockBody::default()
                },
                ..BellatrixBeaconBlock::default()
            },
            ..BellatrixSignedBeaconBlock::default()
        };

        assert!(block.to_ssz().unwrap().len() > Config::mainnet().max_payload_size);
        block
    }

    fn status_message() -> StatusMessage {
        StatusMessage {
            fork_digest: ForkDigest::zero(),
            finalized_root: H256::zero(),
            finalized_epoch: 1,
            head_root: H256::zero(),
            head_slot: 1,
        }
    }

    fn dcbrange_request() -> DataColumnsByRangeRequest {
        DataColumnsByRangeRequest {
            start_slot: 0,
            count: 10,
            columns: ContiguousList::try_from(vec![1, 2, 3])
                .expect("ColumnIndex list can be created from list of numbers"),
        }
    }

    fn dcbroot_request() -> DataColumnsByRootRequest {
        DataColumnsByRootRequest {
            data_column_ids: DynamicList::single(DataColumnIdentifier {
                block_root: H256::zero(),
                index: 0,
            }),
        }
    }

    fn bbrange_request_v1() -> OldBlocksByRangeRequest {
        OldBlocksByRangeRequest::new_v1(0, 10, 1)
    }

    fn bbrange_request_v2() -> OldBlocksByRangeRequest {
        OldBlocksByRangeRequest::new(0, 10, 1)
    }

    fn blbrange_request() -> BlobsByRangeRequest {
        BlobsByRangeRequest {
            start_slot: 0,
            count: 10,
        }
    }

    fn bbroot_request_v1(config: &Config, phase: Phase) -> BlocksByRootRequest {
        BlocksByRootRequest::new_v1(config, phase, core::iter::once(H256::zero()))
    }

    fn bbroot_request_v2(config: &Config, phase: Phase) -> BlocksByRootRequest {
        BlocksByRootRequest::new(config, phase, core::iter::once(H256::zero()))
    }

    fn blbroot_request() -> BlobsByRootRequest {
        BlobsByRootRequest {
            blob_ids: DynamicList::single(BlobIdentifier {
                block_root: H256::zero(),
                index: 0,
            }),
        }
    }

    fn ping_message() -> Ping {
        Ping { data: 1 }
    }

    fn metadata() -> MetaData {
        MetaData::V1(MetaDataV1 {
            seq_number: 1,
            attnets: EnrAttestationBitfield::default(),
        })
    }

    fn metadata_v2() -> MetaData {
        MetaData::V2(MetaDataV2 {
            seq_number: 1,
            attnets: EnrAttestationBitfield::default(),
            syncnets: EnrSyncCommitteeBitfield::default(),
        })
    }

    fn metadata_v3() -> MetaData {
        MetaData::V3(MetaDataV3 {
            seq_number: 1,
            attnets: EnrAttestationBitfield::default(),
            syncnets: EnrSyncCommitteeBitfield::default(),
            custody_subnet_count: 1,
        })
    }

    /// Encodes the given protocol response as bytes.
    fn encode_response<P: Preset>(
        config: &Arc<Config>,
        protocol: SupportedProtocol,
        message: RpcResponse<P>,
        fork_name: Phase,
    ) -> Result<BytesMut, RPCError> {
        let snappy_protocol_id = ProtocolId::new(protocol, Encoding::SSZSnappy);
        let fork_context = Arc::new(ForkContext::dummy::<P>(config, fork_name));

        let mut buf = BytesMut::new();
        let mut snappy_inbound_codec = SSZSnappyInboundCodec::<P>::new(
            config.clone_arc(),
            snappy_protocol_id,
            config.max_payload_size,
            fork_context,
        );

        snappy_inbound_codec.encode_response(message, &mut buf)?;
        Ok(buf)
    }

    fn encode_without_length_checks<P: Preset>(
        config: &Arc<Config>,
        bytes: Vec<u8>,
        fork_name: Phase,
    ) -> Result<BytesMut, RPCError> {
        let fork_context = ForkContext::dummy::<P>(config, fork_name);
        let mut dst = BytesMut::new();

        // Add context bytes if required
        dst.extend_from_slice(&fork_context.to_context_bytes(fork_name).unwrap().as_bytes());

        let mut uvi_codec: Uvi<usize> = Uvi::default();

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        uvi_codec
            .encode(bytes.len(), &mut dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());

        Ok(dst)
    }

    /// Attempts to decode the given protocol bytes as an rpc response
    fn decode_response<P: Preset>(
        config: &Arc<Config>,
        protocol: SupportedProtocol,
        message: &mut BytesMut,
        fork_name: Phase,
    ) -> Result<Option<RpcSuccessResponse<P>>, RPCError> {
        let snappy_protocol_id = ProtocolId::new(protocol, Encoding::SSZSnappy);
        let fork_context = Arc::new(ForkContext::dummy::<P>(config, fork_name));

        let mut snappy_outbound_codec = SSZSnappyOutboundCodec::<P>::new(
            snappy_protocol_id,
            config.max_payload_size,
            fork_context,
        );

        // decode message just as snappy message
        snappy_outbound_codec.decode_response(message)
    }

    /// Encodes the provided protocol message as bytes and tries to decode the encoding bytes.
    fn encode_then_decode_response<P: Preset>(
        config: &Arc<Config>,
        protocol: SupportedProtocol,
        message: RpcResponse<P>,
        fork_name: Phase,
    ) -> Result<Option<RpcSuccessResponse<P>>, RPCError> {
        let mut encoded = encode_response(config, protocol, message, fork_name)?;
        decode_response(config, protocol, &mut encoded, fork_name)
    }

    /// Verifies that requests we send are encoded in a way that we would correctly decode too.
    fn encode_then_decode_request<P: Preset>(
        config: &Arc<Config>,
        req: RequestType<P>,
        fork_name: Phase,
    ) {
        let fork_context = Arc::new(ForkContext::dummy::<P>(config, fork_name));
        let protocol = ProtocolId::new(req.versioned_protocol(), Encoding::SSZSnappy);
        // Encode a request we send
        let mut buf = BytesMut::new();
        let mut outbound_codec = SSZSnappyOutboundCodec::<P>::new(
            protocol.clone(),
            config.max_payload_size,
            fork_context.clone(),
        );
        outbound_codec.encode(req.clone(), &mut buf).unwrap();

        let mut inbound_codec = SSZSnappyInboundCodec::<P>::new(
            config.clone_arc(),
            protocol.clone(),
            config.max_payload_size,
            fork_context.clone(),
        );

        let decoded = inbound_codec.decode(&mut buf).unwrap().unwrap_or_else(|| {
            panic!(
                "Should correctly decode the request {} over protocol {:?} and fork {:?}",
                req, protocol, fork_name
            )
        });

        match req {
            RequestType::Status(status) => {
                assert_eq!(decoded, RequestType::Status(status))
            }
            RequestType::Goodbye(goodbye) => {
                assert_eq!(decoded, RequestType::Goodbye(goodbye))
            }
            RequestType::BlocksByRange(bbrange) => {
                assert_eq!(decoded, RequestType::BlocksByRange(bbrange))
            }
            RequestType::BlocksByRoot(bbroot) => {
                assert_eq!(decoded, RequestType::BlocksByRoot(bbroot))
            }
            RequestType::BlobsByRange(blbrange) => {
                assert_eq!(decoded, RequestType::BlobsByRange(blbrange))
            }
            RequestType::BlobsByRoot(bbroot) => {
                assert_eq!(decoded, RequestType::BlobsByRoot(bbroot))
            }
            RequestType::DataColumnsByRoot(dcbroot) => {
                assert_eq!(decoded, RequestType::DataColumnsByRoot(dcbroot))
            }
            RequestType::DataColumnsByRange(dcbrange) => {
                assert_eq!(decoded, RequestType::DataColumnsByRange(dcbrange))
            }
            RequestType::Ping(ping) => {
                assert_eq!(decoded, RequestType::Ping(ping))
            }
            RequestType::MetaData(metadata) => {
                assert_eq!(decoded, RequestType::MetaData(metadata))
            }
            RequestType::LightClientBootstrap(light_client_bootstrap_request) => {
                assert_eq!(
                    decoded,
                    RequestType::LightClientBootstrap(light_client_bootstrap_request)
                )
            }
            RequestType::LightClientOptimisticUpdate | RequestType::LightClientFinalityUpdate => {}
            RequestType::LightClientUpdatesByRange(light_client_updates_by_range) => {
                assert_eq!(
                    decoded,
                    RequestType::LightClientUpdatesByRange(light_client_updates_by_range)
                )
            }
        }
    }

    // Test RPCResponse encoding/decoding for V1 messages
    #[test]
    fn test_encode_then_decode_v1() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::StatusV1,
                RpcResponse::Success(RpcSuccessResponse::Status(status_message())),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::Status(status_message())))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::PingV1,
                RpcResponse::Success(RpcSuccessResponse::Pong(ping_message())),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::Pong(ping_message())))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV1,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(
                    empty_base_block()
                ))),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        assert!(
            matches!(
                encode_then_decode_response::<Mainnet>(
                    &config,
                    SupportedProtocol::BlocksByRangeV1,
                    RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(
                        altair_block()
                    ))),
                    Phase::Altair,
                )
                .unwrap_err(),
                RPCError::SszReadError(_)
            ),
            "altair block cannot be decoded with blocks by range V1 version"
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRootV1,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(
                    empty_base_block()
                ))),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                empty_base_block()
            ))))
        );

        assert!(
            matches!(
                encode_then_decode_response::<Mainnet>(
                    &config,
                    SupportedProtocol::BlocksByRootV1,
                    RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(
                        Arc::new(altair_block())
                    )),
                    Phase::Altair,
                )
                .unwrap_err(),
                RPCError::SszReadError(_)
            ),
            "altair block cannot be decoded with blocks by range V1 version"
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV1,
                RpcResponse::Success(RpcSuccessResponse::MetaData(metadata())),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::MetaData(metadata()))),
        );

        // A MetaDataV2 still encodes as a MetaDataV1 since version is Version::V1
        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV1,
                RpcResponse::Success(RpcSuccessResponse::MetaData(metadata_v2())),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::MetaData(metadata()))),
        );

        // A MetaDataV3 still encodes as a MetaDataV2 since version is Version::V2
        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV2,
                RpcResponse::Success(RpcSuccessResponse::MetaData(metadata_v3())),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::MetaData(metadata_v2()))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlobsByRangeV1,
                RpcResponse::Success(RpcSuccessResponse::BlobsByRange(empty_blob_sidecar())),
                Phase::Deneb,
            ),
            Ok(Some(RpcSuccessResponse::BlobsByRange(empty_blob_sidecar()))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlobsByRangeV1,
                RpcResponse::Success(RpcSuccessResponse::BlobsByRange(empty_blob_sidecar())),
                Phase::Electra,
            ),
            Ok(Some(RpcSuccessResponse::BlobsByRange(empty_blob_sidecar()))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlobsByRootV1,
                RpcResponse::Success(RpcSuccessResponse::BlobsByRoot(empty_blob_sidecar())),
                Phase::Deneb,
            ),
            Ok(Some(RpcSuccessResponse::BlobsByRoot(empty_blob_sidecar()))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlobsByRootV1,
                RpcResponse::Success(RpcSuccessResponse::BlobsByRoot(empty_blob_sidecar())),
                Phase::Electra,
            ),
            Ok(Some(RpcSuccessResponse::BlobsByRoot(empty_blob_sidecar()))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::DataColumnsByRangeV1,
                RpcResponse::Success(RpcSuccessResponse::DataColumnsByRange(
                    empty_data_column_sidecar()
                )),
                Phase::Deneb,
            ),
            Ok(Some(RpcSuccessResponse::DataColumnsByRange(
                empty_data_column_sidecar()
            ))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::DataColumnsByRangeV1,
                RpcResponse::Success(RpcSuccessResponse::DataColumnsByRange(
                    empty_data_column_sidecar()
                )),
                Phase::Electra,
            ),
            Ok(Some(RpcSuccessResponse::DataColumnsByRange(
                empty_data_column_sidecar()
            ))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::DataColumnsByRootV1,
                RpcResponse::Success(RpcSuccessResponse::DataColumnsByRoot(
                    empty_data_column_sidecar()
                )),
                Phase::Deneb,
            ),
            Ok(Some(RpcSuccessResponse::DataColumnsByRoot(
                empty_data_column_sidecar()
            ))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::DataColumnsByRootV1,
                RpcResponse::Success(RpcSuccessResponse::DataColumnsByRoot(
                    empty_data_column_sidecar()
                )),
                Phase::Electra,
            ),
            Ok(Some(RpcSuccessResponse::DataColumnsByRoot(
                empty_data_column_sidecar()
            ))),
        );
    }

    // Test RPCResponse encoding/decoding for V1 messages
    #[test]
    fn test_encode_then_decode_v2() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(
                    empty_base_block()
                ))),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        // Decode the smallest possible base block when current fork is altair
        // This is useful for checking that we allow for blocks smaller than
        // the current_fork's rpc limit
        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(
                    empty_base_block()
                ))),
                Phase::Altair,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(altair_block()))),
                Phase::Altair,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                altair_block()
            ))))
        );

        let bellatrix_block_small = bellatrix_block_small::<Mainnet>();
        let bellatrix_block_large = bellatrix_block_large::<Mainnet>();

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(
                    types::combined::SignedBeaconBlock::Bellatrix(bellatrix_block_small.clone())
                ))),
                Phase::Bellatrix,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                types::combined::SignedBeaconBlock::Bellatrix(bellatrix_block_small.clone())
            ))))
        );

        let mut encoded = encode_without_length_checks::<Mainnet>(
            &config,
            bellatrix_block_large.to_ssz().unwrap(),
            Phase::Bellatrix,
        )
        .unwrap();

        assert!(
            matches!(
                decode_response::<Mainnet>(
                    &config,
                    SupportedProtocol::BlocksByRangeV2,
                    &mut encoded,
                    Phase::Bellatrix,
                )
                .unwrap_err(),
                RPCError::InvalidData(_)
            ),
            "Decoding a block larger than max_rpc_size should fail"
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRootV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(
                    empty_base_block()
                ))),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                empty_base_block()
            ))))
        );

        // Decode the smallest possible base block when current fork is altair
        // This is useful for checking that we allow for blocks smaller than
        // the current_fork's rpc limit
        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRootV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(
                    empty_base_block()
                ))),
                Phase::Altair,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                empty_base_block()
            ))))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(altair_block()))),
                Phase::Altair,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRange(Arc::new(
                altair_block()
            ))))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRootV2,
                RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(
                    types::combined::SignedBeaconBlock::Bellatrix(bellatrix_block_small.clone())
                ))),
                Phase::Bellatrix,
            ),
            Ok(Some(RpcSuccessResponse::BlocksByRoot(Arc::new(
                types::combined::SignedBeaconBlock::Bellatrix(bellatrix_block_small)
            ))))
        );

        let mut encoded = encode_without_length_checks::<Mainnet>(
            &config,
            bellatrix_block_large.to_ssz().unwrap(),
            Phase::Bellatrix,
        )
        .unwrap();

        assert!(
            matches!(
                decode_response::<Mainnet>(
                    &config,
                    SupportedProtocol::BlocksByRootV2,
                    &mut encoded,
                    Phase::Bellatrix,
                )
                .unwrap_err(),
                RPCError::InvalidData(_)
            ),
            "Decoding a block larger than max_rpc_size should fail"
        );

        // A MetaDataV1 still encodes as a MetaDataV2 since version is Version::V2
        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV2,
                RpcResponse::Success(RpcSuccessResponse::MetaData(metadata())),
                Phase::Phase0,
            ),
            Ok(Some(RpcSuccessResponse::MetaData(metadata_v2())))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV2,
                RpcResponse::Success(RpcSuccessResponse::MetaData(metadata_v2())),
                Phase::Altair,
            ),
            Ok(Some(RpcSuccessResponse::MetaData(metadata_v2())))
        );
    }

    // Test RPCResponse encoding/decoding for V2 messages
    #[test]
    fn test_context_bytes_v2() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());

        let fork_context = ForkContext::dummy::<Mainnet>(&config, Phase::Altair);

        // Removing context bytes for v2 messages should error
        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRangeV2,
            RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(
                empty_base_block(),
            ))),
            Phase::Phase0,
        )
        .unwrap();

        let _ = encoded_bytes.split_to(4);

        assert!(matches!(
            decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                &mut encoded_bytes,
                Phase::Phase0
            )
            .unwrap_err(),
            RPCError::ErrorResponse(RpcErrorResponse::InvalidRequest, _),
        ));

        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRootV2,
            RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(
                empty_base_block(),
            ))),
            Phase::Phase0,
        )
        .unwrap();

        let _ = encoded_bytes.split_to(4);

        assert!(matches!(
            decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                &mut encoded_bytes,
                Phase::Phase0
            )
            .unwrap_err(),
            RPCError::ErrorResponse(RpcErrorResponse::InvalidRequest, _),
        ));

        // Trying to decode a base block with altair context bytes should give ssz decoding error
        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRangeV2,
            RpcResponse::Success(RpcSuccessResponse::BlocksByRange(Arc::new(
                empty_base_block(),
            ))),
            Phase::Altair,
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes.extend_from_slice(
            fork_context
                .to_context_bytes(Phase::Altair)
                .unwrap()
                .as_bytes(),
        );
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                &mut wrong_fork_bytes,
                Phase::Altair
            )
            .unwrap_err(),
            RPCError::SszReadError(_),
        ));

        // Trying to decode an altair block with base context bytes should give ssz decoding error
        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRootV2,
            RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(
                empty_base_block(),
            ))),
            Phase::Altair,
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes.extend_from_slice(
            fork_context
                .to_context_bytes(Phase::Phase0)
                .unwrap()
                .as_bytes(),
        );
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(decode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRangeV2,
            &mut wrong_fork_bytes,
            Phase::Altair
        )
        .is_ok());

        // assert!(matches!(
        //     decode_response::<Mainnet>(
        //         &config,
        //         SupportedProtocol::BlocksByRangeV2,
        //         &mut wrong_fork_bytes,
        //         Phase::Altair,
        //     )
        //     .unwrap_err(),
        //     RPCError::SszReadError(_),
        // ));

        // Adding context bytes to Protocols that don't require it should return an error
        let mut encoded_bytes = BytesMut::new();
        encoded_bytes.extend_from_slice(
            fork_context
                .to_context_bytes(Phase::Altair)
                .unwrap()
                .as_bytes(),
        );
        encoded_bytes.extend_from_slice(
            &encode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV2,
                RpcResponse::Success(RpcSuccessResponse::MetaData(metadata())),
                Phase::Altair,
            )
            .unwrap(),
        );

        assert!(decode_response::<Mainnet>(
            &config,
            SupportedProtocol::MetaDataV2,
            &mut encoded_bytes,
            Phase::Altair
        )
        .is_err());

        // Sending context bytes which do not correspond to any fork should return an error
        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRootV2,
            RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(
                empty_base_block(),
            ))),
            Phase::Altair,
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes.extend_from_slice(&[42, 42, 42, 42]);
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                &mut wrong_fork_bytes,
                Phase::Altair
            )
            .unwrap_err(),
            RPCError::ErrorResponse(RpcErrorResponse::InvalidRequest, _),
        ));

        // Sending bytes less than context bytes length should wait for more bytes by returning `Ok(None)`
        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRootV2,
            RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(Arc::new(phase0_block()))),
            Phase::Altair,
        )
        .unwrap();

        let mut part = encoded_bytes.split_to(3);

        assert_eq!(
            decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                &mut part,
                Phase::Altair
            ),
            Ok(None)
        )
    }

    #[test]
    fn test_encode_then_decode_request() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());

        let requests: &[RequestType<Mainnet>] = &[
            RequestType::Ping(ping_message()),
            RequestType::Status(status_message()),
            RequestType::Goodbye(GoodbyeReason::Fault),
            RequestType::BlocksByRange(bbrange_request_v1()),
            RequestType::BlocksByRange(bbrange_request_v2()),
            RequestType::MetaData(MetadataRequest::new_v1()),
            RequestType::DataColumnsByRange(dcbrange_request()),
            RequestType::DataColumnsByRoot(dcbroot_request()),
            RequestType::MetaData(MetadataRequest::new_v2()),
            RequestType::MetaData(MetadataRequest::new_v3()),
        ];
        for req in requests.iter() {
            for fork_name in enum_iterator::all::<Phase>() {
                encode_then_decode_request(&config, req.clone(), fork_name);
            }
        }

        let requests: &[RequestType<Mainnet>] = &[
            RequestType::BlobsByRange(blbrange_request()),
            RequestType::BlobsByRoot(blbroot_request()),
        ];
        for req in requests.iter() {
            for fork_name in enum_iterator::all::<Phase>().filter(|phase| *phase > Phase::Capella) {
                encode_then_decode_request(&config, req.clone(), fork_name);
            }
        }

        // Request types that have different length limits depending on the fork
        // Handled separately to have consistent `Phase` across request and responses
        let fork_dependent_requests = |phase| {
            [
                RequestType::BlocksByRoot(bbroot_request_v1(&config, phase)),
                RequestType::BlocksByRoot(bbroot_request_v2(&config, phase)),
            ]
        };
        for fork_name in enum_iterator::all::<Phase>() {
            let requests: [RequestType<Mainnet>; 2] = fork_dependent_requests(fork_name);
            for req in requests {
                encode_then_decode_request(&config, req.clone(), fork_name);
            }
        }
    }

    /// Test a malicious snappy encoding for a V1 `Status` message where the attacker
    /// sends a valid message filled with a stream of useless padding before the actual message.
    #[test]
    fn test_decode_malicious_v1_message() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());

        // 10 byte snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        assert_eq!(stream_identifier.len(), 10);

        // byte 0(0xFE) is padding chunk type identifier for snappy messages
        // byte 1,2,3 are chunk length (little endian)
        let malicious_padding: &'static [u8] = b"\xFE\x00\x00\x00";

        // Status message is 84 bytes uncompressed. `max_compressed_len` is 32 + 84 + 84/6 = 130.
        let status_message_bytes = StatusMessage {
            fork_digest: ForkDigest::zero(),
            finalized_root: H256::zero(),
            finalized_epoch: 1,
            head_root: H256::zero(),
            head_slot: 1,
        }
        .to_ssz()
        .unwrap();

        assert_eq!(status_message_bytes.len(), 84);
        assert_eq!(snap::raw::max_compress_len(status_message_bytes.len()), 130);

        let mut uvi_codec: Uvi<usize> = Uvi::default();
        let mut dst = BytesMut::with_capacity(1024);

        // Insert length-prefix
        uvi_codec
            .encode(config.max_payload_size + 1, &mut dst)
            .unwrap();

        // Insert snappy stream identifier
        dst.extend_from_slice(stream_identifier);

        // Insert malicious padding of 80 bytes.
        for _ in 0..20 {
            dst.extend_from_slice(malicious_padding);
        }

        // Insert payload (42 bytes compressed)
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&status_message_bytes).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().len(), 42);
        dst.extend_from_slice(writer.get_ref());

        // 10 (for stream identifier) + 80 + 42 = 132 > `max_compressed_len`. Hence, decoding should fail with `InvalidData`.
        assert!(matches!(
            decode_response::<Mainnet>(
                &Config::mainnet().rapid_upgrade().into(),
                SupportedProtocol::StatusV1,
                &mut dst,
                Phase::Phase0,
            )
            .unwrap_err(),
            RPCError::InvalidData(_)
        ));
    }

    /// Test a malicious snappy encoding for a V2 `BlocksByRange` message where the attacker
    /// sends a valid message filled with a stream of useless padding before the actual message.
    #[test]
    fn test_decode_malicious_v2_message() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());
        let fork_context = Arc::new(ForkContext::dummy::<Mainnet>(&config, Phase::Altair));

        // 10 byte snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        assert_eq!(stream_identifier.len(), 10);

        // byte 0(0xFE) is padding chunk type identifier for snappy messages
        // byte 1,2,3 are chunk length (little endian)
        let malicious_padding: &'static [u8] = b"\xFE\x00\x00\x00";

        // Full altair block is 157916 bytes uncompressed. `max_compressed_len` is 32 + 157916 + 157916/6 = 184267.
        let block_message_bytes = altair_block::<Mainnet>().to_ssz().unwrap();

        assert_eq!(block_message_bytes.len(), 157916);
        assert_eq!(
            snap::raw::max_compress_len(block_message_bytes.len()),
            184267
        );

        let mut uvi_codec: Uvi<usize> = Uvi::default();
        let mut dst = BytesMut::with_capacity(1024);

        // Insert context bytes
        dst.extend_from_slice(
            fork_context
                .to_context_bytes(Phase::Altair)
                .unwrap()
                .as_bytes(),
        );

        // Insert length-prefix
        uvi_codec
            .encode(block_message_bytes.len(), &mut dst)
            .unwrap();

        // Insert snappy stream identifier
        dst.extend_from_slice(stream_identifier);

        // Insert malicious padding of 176156 bytes.
        for _ in 0..44039 {
            dst.extend_from_slice(malicious_padding);
        }

        // Insert payload (8103 bytes compressed)
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&block_message_bytes).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().len(), 8103);
        dst.extend_from_slice(writer.get_ref());

        // 10 (for stream identifier) + 176156 + 8103 = 184269 > `max_compressed_len`. Hence, decoding should fail with `InvalidData`.
        assert!(matches!(
            decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                &mut dst,
                Phase::Altair
            )
            .unwrap_err(),
            RPCError::InvalidData(_)
        ));
    }

    /// Test sending a message with encoded length prefix > max_rpc_size.
    #[test]
    fn test_decode_invalid_length() -> Result<()> {
        // 10 byte snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        assert_eq!(stream_identifier.len(), 10);

        // Status message is 84 bytes uncompressed. `max_compressed_len` is 32 + 84 + 84/6 = 130.
        let status_message_bytes = StatusMessage {
            fork_digest: ForkDigest::zero(),
            finalized_root: H256::zero(),
            finalized_epoch: 1,
            head_root: H256::zero(),
            head_slot: 1,
        }
        .to_ssz()?;

        let mut uvi_codec: Uvi<usize> = Uvi::default();
        let mut dst = BytesMut::with_capacity(1024);

        // Insert length-prefix
        uvi_codec
            .encode(Config::default().max_payload_size + 1, &mut dst)
            .unwrap();

        // Insert snappy stream identifier
        dst.extend_from_slice(stream_identifier);

        // Insert payload
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&status_message_bytes).unwrap();
        writer.flush().unwrap();
        dst.extend_from_slice(writer.get_ref());

        assert!(matches!(
            decode_response::<Mainnet>(
                &Config::mainnet().rapid_upgrade().into(),
                SupportedProtocol::StatusV1,
                &mut dst,
                Phase::Phase0,
            )
            .unwrap_err(),
            RPCError::InvalidData(_)
        ));

        Ok(())
    }

    #[test]
    fn test_decode_status_message() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());
        let message = hex::decode("0054ff060000734e615070590032000006e71e7b54989925efd6c9cbcb8ceb9b5f71216f5137282bf6a1e3b50f64e42d6c7fb347abe07eb0db8200000005029e2800").unwrap();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&message);

        let snappy_protocol_id = ProtocolId::new(SupportedProtocol::StatusV1, Encoding::SSZSnappy);

        let fork_context = Arc::new(ForkContext::dummy::<Mainnet>(&config, Phase::Phase0));

        let mut snappy_outbound_codec = SSZSnappyOutboundCodec::<Mainnet>::new(
            snappy_protocol_id,
            config.max_payload_size,
            fork_context,
        );

        // remove response code
        let mut snappy_buf = buf.clone();
        let _ = snappy_buf.split_to(1);

        // decode message just as snappy message
        let _snappy_decoded_message = snappy_outbound_codec
            .decode_response(&mut snappy_buf)
            .unwrap();

        // decode message as ssz snappy chunk
        let _snappy_decoded_chunk = snappy_outbound_codec.decode(&mut buf).unwrap();
    }

    #[test]
    fn test_invalid_length_prefix() {
        let config = Arc::new(Config::mainnet().rapid_upgrade());
        let mut uvi_codec: Uvi<u128> = Uvi::default();
        let mut dst = BytesMut::with_capacity(1024);

        // Smallest > 10 byte varint
        let len: u128 = 2u128.pow(70);

        // Insert length-prefix
        uvi_codec.encode(len, &mut dst).unwrap();

        let snappy_protocol_id = ProtocolId::new(SupportedProtocol::StatusV1, Encoding::SSZSnappy);

        let fork_context = Arc::new(ForkContext::dummy::<Mainnet>(&config, Phase::Phase0));

        let mut snappy_outbound_codec = SSZSnappyOutboundCodec::<Mainnet>::new(
            snappy_protocol_id,
            config.max_payload_size,
            fork_context,
        );

        let snappy_decoded_message = snappy_outbound_codec.decode_response(&mut dst).unwrap_err();

        assert_eq!(
            snappy_decoded_message,
            RPCError::IoError("input bytes exceed maximum".to_string()),
            "length-prefix of > 10 bytes is invalid"
        );
    }

    #[test]
    fn test_length_limits() {
        fn encode_len(len: usize) -> BytesMut {
            let mut uvi_codec: Uvi<usize> = Uvi::default();
            let mut dst = BytesMut::with_capacity(1024);
            uvi_codec.encode(len, &mut dst).unwrap();
            dst
        }

        let protocol_id = ProtocolId::new(SupportedProtocol::BlocksByRangeV1, Encoding::SSZSnappy);

        // Response limits
        let config = Arc::new(Config::mainnet().rapid_upgrade());
        let fork_context = Arc::new(ForkContext::dummy::<Mainnet>(&config, Phase::Phase0));

        let limit = protocol_id
            .rpc_response_limits::<Mainnet>(&fork_context)
            .unwrap();
        let mut max = encode_len(limit.max + 1);
        let mut codec = SSZSnappyOutboundCodec::<Mainnet>::new(
            protocol_id.clone(),
            config.max_payload_size,
            fork_context.clone(),
        );
        assert!(matches!(
            codec.decode_response(&mut max).unwrap_err(),
            RPCError::InvalidData(_)
        ));

        let mut min = encode_len(limit.min - 1);
        let mut codec = SSZSnappyOutboundCodec::<Mainnet>::new(
            protocol_id.clone(),
            config.max_payload_size,
            fork_context.clone(),
        );
        assert!(matches!(
            codec.decode_response(&mut min).unwrap_err(),
            RPCError::InvalidData(_)
        ));

        // Request limits
        let limit = protocol_id
            .rpc_request_limits(&config, Phase::Deneb)
            .unwrap();
        let mut max = encode_len(limit.max + 1);
        let mut codec = SSZSnappyOutboundCodec::<Mainnet>::new(
            protocol_id.clone(),
            config.max_payload_size,
            fork_context.clone(),
        );
        assert!(matches!(
            codec.decode_response(&mut max).unwrap_err(),
            RPCError::InvalidData(_)
        ));

        let mut min = encode_len(limit.min - 1);
        let mut codec = SSZSnappyOutboundCodec::<Mainnet>::new(
            protocol_id,
            config.max_payload_size,
            fork_context,
        );
        assert!(matches!(
            codec.decode_response(&mut min).unwrap_err(),
            RPCError::InvalidData(_)
        ));
    }
}
