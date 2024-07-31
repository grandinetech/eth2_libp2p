use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{Encoding, ProtocolId, RPCError, SupportedProtocol, ERROR_TYPE_MAX, ERROR_TYPE_MIN},
};
use crate::rpc::{InboundRequest, OutboundRequest, RPCCodedResponse, RPCResponse};
use crate::types::ForkContext;
use libp2p::bytes::BytesMut;
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use ssz::{ContiguousList, SszReadDefault, SszWrite as _, H256};
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
        BlobSidecar, LightClientBootstrap, LightClientFinalityUpdate, LightClientOptimisticUpdate,
        SignedBeaconBlock,
    },
    deneb::containers::SignedBeaconBlock as DenebSignedBeaconBlock,
    electra::containers::SignedBeaconBlock as ElectraSignedBeaconBlock,
    nonstandard::Phase,
    phase0::{containers::SignedBeaconBlock as Phase0SignedBeaconBlock, primitives::ForkDigest},
    preset::Preset,
};

use unsigned_varint::codec::Uvi;

const CONTEXT_BYTES_LEN: usize = 4;

/* Inbound Codec */

pub struct SSZSnappyInboundCodec<P: Preset> {
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
        protocol: ProtocolId,
        max_packet_size: usize,
        fork_context: Arc<ForkContext>,
    ) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyInboundCodec {
            inner: uvi_codec,
            protocol,
            len: None,
            phantom: PhantomData,
            fork_context,
            max_packet_size,
        }
    }
}

// Encoder for inbound streams: Encodes RPC Responses sent to peers.
impl<P: Preset> Encoder<RPCCodedResponse<P>> for SSZSnappyInboundCodec<P> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCCodedResponse<P>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match &item {
            RPCCodedResponse::Success(resp) => match &resp {
                RPCResponse::Status(res) => res.to_ssz()?,
                RPCResponse::BlocksByRange(res) => res.to_ssz()?,
                RPCResponse::BlocksByRoot(res) => res.to_ssz()?,
                RPCResponse::BlobsByRange(res) => res.to_ssz()?,
                RPCResponse::BlobsByRoot(res) => res.to_ssz()?,
                RPCResponse::LightClientBootstrap(res) => res.to_ssz()?,
                RPCResponse::LightClientOptimisticUpdate(res) => res.to_ssz()?,
                RPCResponse::LightClientFinalityUpdate(res) => res.to_ssz()?,
                RPCResponse::Pong(res) => res.data.to_ssz()?,
                RPCResponse::MetaData(res) =>
                // Encode the correct version of the MetaData response based on the negotiated version.
                {
                    match self.protocol.versioned_protocol {
                        SupportedProtocol::MetaDataV1 => res.metadata_v1().to_ssz()?,
                        // We always send V2 metadata responses from the behaviour
                        // No change required.
                        SupportedProtocol::MetaDataV2 => res.metadata_v2().to_ssz()?,
                        _ => unreachable!(
                            "We only send metadata responses on negotiating metadata requests"
                        ),
                    }
                }
            },
            RPCCodedResponse::Error(_, err) => err.to_ssz()?,
            RPCCodedResponse::StreamTermination(_) => {
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

// Decoder for inbound streams: Decodes RPC requests from peers
impl<P: Preset> Decoder for SSZSnappyInboundCodec<P> {
    type Item = InboundRequest<P>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV1 {
            return Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v1())));
        }
        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV2 {
            return Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v2())));
        }
        let Some(length) = handle_length(&mut self.inner, &mut self.len, src)? else {
            return Ok(None);
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self.protocol.rpc_request_limits();
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
                handle_rpc_request(self.protocol.versioned_protocol, &decoded_buffer)
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
        }
    }
}

// Encoder for outbound streams: Encodes RPC Requests to peers
impl<P: Preset> Encoder<OutboundRequest<P>> for SSZSnappyOutboundCodec<P> {
    type Error = RPCError;

    fn encode(&mut self, item: OutboundRequest<P>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            OutboundRequest::Status(req) => req.to_ssz()?,
            OutboundRequest::Goodbye(req) => req.to_ssz()?,
            OutboundRequest::BlocksByRange(r) => match r {
                OldBlocksByRangeRequest::V1(req) => req.to_ssz()?,
                OldBlocksByRangeRequest::V2(req) => req.to_ssz()?,
            },
            OutboundRequest::BlocksByRoot(r) => match r {
                BlocksByRootRequest::V1(req) => req.block_roots.to_ssz()?,
                BlocksByRootRequest::V2(req) => req.block_roots.to_ssz()?,
            },
            OutboundRequest::BlobsByRange(req) => req.to_ssz()?,
            OutboundRequest::BlobsByRoot(req) => req.blob_ids.to_ssz()?,
            OutboundRequest::Ping(req) => req.to_ssz()?,
            OutboundRequest::MetaData(_) => return Ok(()), // no metadata to encode
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
        Ok(())
    }
}

// Decoder for outbound streams: Decodes RPC responses from peers.
//
// The majority of the decoding has now been pushed upstream due to the changing specification.
// We prefer to decode blocks and attestations with extra knowledge about the chain to perform
// faster verification checks before decoding entire blocks/attestations.
impl<P: Preset> Decoder for SSZSnappyOutboundCodec<P> {
    type Item = RPCResponse<P>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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
        let ssz_limits = self.protocol.rpc_response_limits::<P>(&self.fork_context);
        if ssz_limits.is_out_of_bounds(length, self.max_packet_size) {
            return Err(RPCError::InvalidData(format!(
                "RPC response length is out of bounds, length {}, max {}, min {}",
                length, ssz_limits.max, ssz_limits.min
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
}

impl<P: Preset> OutboundCodec<OutboundRequest<P>> for SSZSnappyOutboundCodec<P> {
    type CodecErrorType = ErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::CodecErrorType>, RPCError> {
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
    resp: &RPCCodedResponse<P>,
) -> Option<ForkDigest> {
    // Add the context bytes if required
    if protocol.has_context_bytes() {
        if let RPCCodedResponse::Success(rpc_variant) = resp {
            match rpc_variant {
                RPCResponse::BlocksByRange(ref_box_block)
                | RPCResponse::BlocksByRoot(ref_box_block) => {
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
                RPCResponse::BlobsByRange(_) | RPCResponse::BlobsByRoot(_) => {
                    return fork_context.to_context_bytes(Phase::Deneb);
                }
                RPCResponse::LightClientBootstrap(lc_bootstrap) => {
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
                RPCResponse::LightClientOptimisticUpdate(lc_optimistic_update) => {
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
                RPCResponse::LightClientFinalityUpdate(lc_finality_update) => {
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
                // These will not pass the has_context_bytes() check
                RPCResponse::Status(_) | RPCResponse::Pong(_) | RPCResponse::MetaData(_) => {
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
    versioned_protocol: SupportedProtocol,
    decoded_buffer: &[u8],
) -> Result<Option<InboundRequest<P>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(InboundRequest::Status(
            StatusMessage::from_ssz_default(decoded_buffer)?,
        ))),
        SupportedProtocol::GoodbyeV1 => Ok(Some(InboundRequest::Goodbye(
            GoodbyeReason::from_ssz_default(decoded_buffer)?,
        ))),
        SupportedProtocol::BlocksByRangeV2 => Ok(Some(InboundRequest::BlocksByRange(
            OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2::from_ssz_default(
                decoded_buffer,
            )?),
        ))),
        SupportedProtocol::BlocksByRangeV1 => Ok(Some(InboundRequest::BlocksByRange(
            OldBlocksByRangeRequest::V1(OldBlocksByRangeRequestV1::from_ssz_default(
                decoded_buffer,
            )?),
        ))),
        SupportedProtocol::BlocksByRootV2 => Ok(Some(InboundRequest::BlocksByRoot(
            BlocksByRootRequest::V2(BlocksByRootRequestV2 {
                block_roots: ContiguousList::from_ssz_default(decoded_buffer)?,
            }),
        ))),
        SupportedProtocol::BlocksByRootV1 => Ok(Some(InboundRequest::BlocksByRoot(
            BlocksByRootRequest::V1(BlocksByRootRequestV1 {
                block_roots: ContiguousList::from_ssz_default(decoded_buffer)?,
            }),
        ))),
        SupportedProtocol::BlobsByRangeV1 => Ok(Some(InboundRequest::BlobsByRange(
            BlobsByRangeRequest::from_ssz_default(decoded_buffer)?,
        ))),
        SupportedProtocol::BlobsByRootV1 => {
            Ok(Some(InboundRequest::BlobsByRoot(BlobsByRootRequest {
                blob_ids: ContiguousList::from_ssz_default(decoded_buffer)?,
            })))
        }
        SupportedProtocol::PingV1 => Ok(Some(InboundRequest::Ping(Ping {
            data: u64::from_ssz_default(decoded_buffer)?,
        }))),
        SupportedProtocol::LightClientBootstrapV1 => Ok(Some(
            InboundRequest::LightClientBootstrap(LightClientBootstrapRequest {
                root: H256::from_ssz_default(decoded_buffer)?,
            }),
        )),
        SupportedProtocol::LightClientOptimisticUpdateV1 => {
            Ok(Some(InboundRequest::LightClientOptimisticUpdate))
        }
        SupportedProtocol::LightClientFinalityUpdateV1 => {
            Ok(Some(InboundRequest::LightClientFinalityUpdate))
        }
        // MetaData requests return early from InboundUpgrade and do not reach the decoder.
        // Handle this case just for completeness.
        SupportedProtocol::MetaDataV2 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InternalError(
                    "Metadata requests shouldn't reach decoder",
                ))
            } else {
                Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v2())))
            }
        }
        SupportedProtocol::MetaDataV1 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InvalidData("Metadata request".to_string()))
            } else {
                Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v1())))
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
) -> Result<Option<RPCResponse<P>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(RPCResponse::Status(
            StatusMessage::from_ssz_default(decoded_buffer)?,
        ))),
        // This case should be unreachable as `Goodbye` has no response.
        SupportedProtocol::GoodbyeV1 => Err(RPCError::InvalidData(
            "Goodbye RPC message has no valid response".to_string(),
        )),
        SupportedProtocol::BlocksByRangeV1 => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
            SignedBeaconBlock::Phase0(Phase0SignedBeaconBlock::from_ssz_default(decoded_buffer)?),
        )))),
        SupportedProtocol::BlocksByRootV1 => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
            SignedBeaconBlock::Phase0(Phase0SignedBeaconBlock::from_ssz_default(decoded_buffer)?),
        )))),
        SupportedProtocol::BlobsByRangeV1 => match fork_name {
            Some(Phase::Deneb) => SszReadDefault::from_ssz_default(decoded_buffer)
                .map(BlobSidecar::Deneb)
                .map(Arc::new)
                .map(RPCResponse::BlobsByRange)
                .map(Some)
                .map_err(Into::into),
            Some(Phase::Electra) => SszReadDefault::from_ssz_default(decoded_buffer)
                .map(BlobSidecar::Electra)
                .map(Arc::new)
                .map(RPCResponse::BlobsByRange)
                .map(Some)
                .map_err(Into::into),
            Some(_) => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                "Invalid fork name for blobs by range".to_string(),
            )),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::BlobsByRootV1 => match fork_name {
            Some(Phase::Deneb) => SszReadDefault::from_ssz_default(decoded_buffer)
                .map(BlobSidecar::Deneb)
                .map(Arc::new)
                .map(RPCResponse::BlobsByRoot)
                .map(Some)
                .map_err(Into::into),
            Some(Phase::Electra) => SszReadDefault::from_ssz_default(decoded_buffer)
                .map(BlobSidecar::Electra)
                .map(Arc::new)
                .map(RPCResponse::BlobsByRoot)
                .map(Some)
                .map_err(Into::into),
            Some(_) => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                "Invalid fork name for blobs by root".to_string(),
            )),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::PingV1 => Ok(Some(RPCResponse::Pong(Ping {
            data: u64::from_ssz_default(decoded_buffer)?,
        }))),
        SupportedProtocol::MetaDataV1 => Ok(Some(RPCResponse::MetaData(MetaData::V1(
            MetaDataV1::from_ssz_default(decoded_buffer)?,
        )))),
        SupportedProtocol::LightClientBootstrapV1 => match fork_name {
            Some(Phase::Phase0) => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!("light_client_bootstrap topic invalid for given fork {fork_name:?}",),
            )),
            Some(Phase::Altair | Phase::Bellatrix) => Ok(Some(RPCResponse::LightClientBootstrap(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientBootstrap::Altair)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Capella) => Ok(Some(RPCResponse::LightClientBootstrap(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientBootstrap::Capella)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Deneb) => Ok(Some(RPCResponse::LightClientBootstrap(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientBootstrap::Deneb)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Electra) => Ok(Some(RPCResponse::LightClientBootstrap(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientBootstrap::Electra)
                    .map(Arc::new)?,
            ))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::LightClientOptimisticUpdateV1 => match fork_name {
            Some(Phase::Phase0) => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "light_client_optimistic_update topic invalid for given fork {fork_name:?}",
                ),
            )),
            Some(Phase::Altair | Phase::Bellatrix) => {
                Ok(Some(RPCResponse::LightClientOptimisticUpdate(
                    SszReadDefault::from_ssz_default(decoded_buffer)
                        .map(LightClientOptimisticUpdate::Altair)
                        .map(Arc::new)?,
                )))
            }
            Some(Phase::Capella) => Ok(Some(RPCResponse::LightClientOptimisticUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientOptimisticUpdate::Capella)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Deneb) => Ok(Some(RPCResponse::LightClientOptimisticUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientOptimisticUpdate::Deneb)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Electra) => Ok(Some(RPCResponse::LightClientOptimisticUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientOptimisticUpdate::Electra)
                    .map(Arc::new)?,
            ))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::LightClientFinalityUpdateV1 => match fork_name {
            Some(Phase::Phase0) => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!("light_client_finality_update topic invalid for given fork {fork_name:?}",),
            )),
            Some(Phase::Altair | Phase::Bellatrix) => {
                Ok(Some(RPCResponse::LightClientFinalityUpdate(
                    SszReadDefault::from_ssz_default(decoded_buffer)
                        .map(LightClientFinalityUpdate::Altair)
                        .map(Arc::new)?,
                )))
            }
            Some(Phase::Capella) => Ok(Some(RPCResponse::LightClientFinalityUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientFinalityUpdate::Capella)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Deneb) => Ok(Some(RPCResponse::LightClientFinalityUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientFinalityUpdate::Deneb)
                    .map(Arc::new)?,
            ))),
            Some(Phase::Electra) => Ok(Some(RPCResponse::LightClientFinalityUpdate(
                SszReadDefault::from_ssz_default(decoded_buffer)
                    .map(LightClientFinalityUpdate::Electra)
                    .map(Arc::new)?,
            ))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        // MetaData V2 responses have no context bytes, so behave similarly to V1 responses
        SupportedProtocol::MetaDataV2 => Ok(Some(RPCResponse::MetaData(MetaData::V2(
            MetaDataV2::from_ssz_default(decoded_buffer)?,
        )))),
        SupportedProtocol::BlocksByRangeV2 => match fork_name {
            Some(Phase::Altair) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Altair(AltairSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Phase0) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Phase0(Phase0SignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Bellatrix) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Bellatrix(BellatrixSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Capella) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Capella(CapellaSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Deneb) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Deneb(DenebSignedBeaconBlock::from_ssz_default(decoded_buffer)?),
            )))),
            Some(Phase::Electra) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Electra(ElectraSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::BlocksByRootV2 => match fork_name {
            Some(Phase::Altair) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Altair(AltairSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Phase0) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Phase0(Phase0SignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Bellatrix) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Bellatrix(BellatrixSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Capella) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Capella(CapellaSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            Some(Phase::Deneb) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Deneb(DenebSignedBeaconBlock::from_ssz_default(decoded_buffer)?),
            )))),
            Some(Phase::Electra) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Electra(ElectraSignedBeaconBlock::from_ssz_default(
                    decoded_buffer,
                )?),
            )))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
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
                RPCResponseErrorCode::InvalidRequest,
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
        rpc::{methods::StatusMessage, protocol::*, Ping, RPCResponseErrorCode},
        types::{EnrAttestationBitfield, ForkContext},
        EnrSyncCommitteeBitfield,
    };
    use anyhow::Result;
    use snap::write::FrameEncoder;
    use ssz::ByteList;
    use std::io::Write;
    use std::sync::Arc;
    use try_from_iterator::TryFromIterator as _;
    use types::{
        bellatrix::containers::{
            BeaconBlock as BellatrixBeaconBlock, BeaconBlockBody as BellatrixBeaconBlockBody,
            ExecutionPayload, SignedBeaconBlock as BellatrixSignedBeaconBlock,
        },
        combined::SignedBeaconBlock,
        config::Config,
        deneb::containers::{BlobIdentifier, BlobSidecar as DenebBlobSidecar},
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

    fn empty_deneb_blob_sidecar<P: Preset>() -> Arc<BlobSidecar<P>> {
        Arc::new(DenebBlobSidecar::default().into())
    }

    /// Bellatrix block with length < max_rpc_size.
    fn bellatrix_block_small<P: Preset>(
        fork_context: &ForkContext,
    ) -> BellatrixSignedBeaconBlock<P> {
        let tx = ByteList::<P::MaxBytesPerTransaction>::from_ssz_default([0; 1024]).unwrap();
        let txs =
            Arc::new(ContiguousList::try_from_iter(std::iter::repeat(tx).take(5000)).unwrap());

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

        assert!(
            block.to_ssz().unwrap().len()
                <= max_rpc_size(fork_context, Config::mainnet().max_chunk_size)
        );
        block
    }

    /// Bellatrix block with length > MAX_RPC_SIZE.
    /// The max limit for a merge block is in the order of ~16GiB which wouldn't fit in memory.
    /// Hence, we generate a merge block just greater than `MAX_RPC_SIZE` to test rejection on the rpc layer.
    fn bellatrix_block_large<P: Preset>(
        fork_context: &ForkContext,
    ) -> BellatrixSignedBeaconBlock<P> {
        let tx = ByteList::<P::MaxBytesPerTransaction>::from_ssz_default([0; 1024]).unwrap();
        let txs =
            Arc::new(ContiguousList::try_from_iter(std::iter::repeat(tx).take(100000)).unwrap());

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

        assert!(
            block.to_ssz().unwrap().len()
                > max_rpc_size(fork_context, Config::mainnet().max_chunk_size)
        );
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

    fn bbroot_request_v1() -> BlocksByRootRequest {
        BlocksByRootRequest::new_v1(ContiguousList::full(H256::zero()))
    }

    fn bbroot_request_v2() -> BlocksByRootRequest {
        BlocksByRootRequest::new(ContiguousList::full(H256::zero()))
    }

    fn blbroot_request() -> BlobsByRootRequest {
        BlobsByRootRequest {
            blob_ids: ContiguousList::try_from(vec![BlobIdentifier {
                block_root: H256::zero(),
                index: 0,
            }])
            .expect("BlobIds list can be created from single identifier"),
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

    /// Encodes the given protocol response as bytes.
    fn encode_response<P: Preset>(
        config: &Arc<Config>,
        protocol: SupportedProtocol,
        message: RPCCodedResponse<P>,
        fork_name: Phase,
    ) -> Result<BytesMut, RPCError> {
        let snappy_protocol_id = ProtocolId::new(protocol, Encoding::SSZSnappy);
        let fork_context = Arc::new(ForkContext::dummy::<P>(config, fork_name));
        let max_packet_size = max_rpc_size(&fork_context, config.max_chunk_size);

        let mut buf = BytesMut::new();
        let mut snappy_inbound_codec =
            SSZSnappyInboundCodec::<P>::new(snappy_protocol_id, max_packet_size, fork_context);

        snappy_inbound_codec.encode(message, &mut buf)?;
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
    ) -> Result<Option<RPCResponse<P>>, RPCError> {
        let snappy_protocol_id = ProtocolId::new(protocol, Encoding::SSZSnappy);
        let fork_context = Arc::new(ForkContext::dummy::<P>(config, fork_name));

        let max_packet_size = max_rpc_size(&fork_context, config.max_chunk_size);
        let mut snappy_outbound_codec =
            SSZSnappyOutboundCodec::<P>::new(snappy_protocol_id, max_packet_size, fork_context);
        // decode message just as snappy message
        snappy_outbound_codec.decode(message)
    }

    /// Encodes the provided protocol message as bytes and tries to decode the encoding bytes.
    fn encode_then_decode_response<P: Preset>(
        config: &Arc<Config>,
        protocol: SupportedProtocol,
        message: RPCCodedResponse<P>,
        fork_name: Phase,
    ) -> Result<Option<RPCResponse<P>>, RPCError> {
        let mut encoded = encode_response(config, protocol, message, fork_name)?;
        decode_response(config, protocol, &mut encoded, fork_name)
    }

    /// Verifies that requests we send are encoded in a way that we would correctly decode too.
    fn encode_then_decode_request<P: Preset>(
        config: &Arc<Config>,
        req: OutboundRequest<P>,
        fork_name: Phase,
    ) {
        let fork_context = Arc::new(ForkContext::dummy::<P>(config, fork_name));
        let max_packet_size = max_rpc_size(&fork_context, config.max_chunk_size);
        let protocol = ProtocolId::new(req.versioned_protocol(), Encoding::SSZSnappy);
        // Encode a request we send
        let mut buf = BytesMut::new();
        let mut outbound_codec = SSZSnappyOutboundCodec::<P>::new(
            protocol.clone(),
            max_packet_size,
            fork_context.clone(),
        );
        outbound_codec.encode(req.clone(), &mut buf).unwrap();

        let mut inbound_codec = SSZSnappyInboundCodec::<P>::new(
            protocol.clone(),
            max_packet_size,
            fork_context.clone(),
        );

        let decoded = inbound_codec.decode(&mut buf).unwrap().unwrap_or_else(|| {
            panic!(
                "Should correctly decode the request {} over protocol {:?} and fork {:?}",
                req, protocol, fork_name
            )
        });

        match req {
            OutboundRequest::Status(status) => {
                assert_eq!(decoded, InboundRequest::Status(status))
            }
            OutboundRequest::Goodbye(goodbye) => {
                assert_eq!(decoded, InboundRequest::Goodbye(goodbye))
            }
            OutboundRequest::BlocksByRange(bbrange) => {
                assert_eq!(decoded, InboundRequest::BlocksByRange(bbrange))
            }
            OutboundRequest::BlocksByRoot(bbroot) => {
                assert_eq!(decoded, InboundRequest::BlocksByRoot(bbroot))
            }
            OutboundRequest::BlobsByRange(blbrange) => {
                assert_eq!(decoded, InboundRequest::BlobsByRange(blbrange))
            }
            OutboundRequest::BlobsByRoot(bbroot) => {
                assert_eq!(decoded, InboundRequest::BlobsByRoot(bbroot))
            }
            OutboundRequest::Ping(ping) => {
                assert_eq!(decoded, InboundRequest::Ping(ping))
            }
            OutboundRequest::MetaData(metadata) => {
                assert_eq!(decoded, InboundRequest::MetaData(metadata))
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
                RPCCodedResponse::Success(RPCResponse::Status(status_message())),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::Status(status_message())))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::PingV1,
                RPCCodedResponse::Success(RPCResponse::Pong(ping_message())),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::Pong(ping_message())))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV1,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        assert!(
            matches!(
                encode_then_decode_response::<Mainnet>(
                    &config,
                    SupportedProtocol::BlocksByRangeV1,
                    RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(altair_block()))),
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
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(
                Arc::new(empty_base_block())
            )))
        );

        assert!(
            matches!(
                encode_then_decode_response::<Mainnet>(
                    &config,
                    SupportedProtocol::BlocksByRootV1,
                    RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(altair_block()))),
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
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::MetaData(metadata()))),
        );

        // A MetaDataV2 still encodes as a MetaDataV1 since version is Version::V1
        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV1,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata_v2())),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::MetaData(metadata()))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlobsByRangeV1,
                RPCCodedResponse::Success(RPCResponse::BlobsByRange(empty_deneb_blob_sidecar())),
                Phase::Deneb,
            ),
            Ok(Some(RPCResponse::BlobsByRange(empty_deneb_blob_sidecar()))),
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlobsByRootV1,
                RPCCodedResponse::Success(RPCResponse::BlobsByRoot(empty_deneb_blob_sidecar())),
                Phase::Deneb,
            ),
            Ok(Some(RPCResponse::BlobsByRoot(empty_deneb_blob_sidecar()))),
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
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
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
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
                Phase::Altair,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        let fork_context = ForkContext::dummy::<Mainnet>(&config, Phase::Bellatrix);
        let bellatrix_block_small = bellatrix_block_small::<Mainnet>(&fork_context);
        let bellatrix_block_large = bellatrix_block_large::<Mainnet>(&fork_context);

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(
                    types::combined::SignedBeaconBlock::Bellatrix(bellatrix_block_small.clone())
                ))),
                Phase::Bellatrix,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
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
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(
                Arc::new(empty_base_block())
            )))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRangeV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(altair_block()))),
                Phase::Altair,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(altair_block()))))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::BlocksByRootV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(
                    types::combined::SignedBeaconBlock::Bellatrix(bellatrix_block_small.clone())
                ))),
                Phase::Bellatrix,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
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
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
                Phase::Phase0,
            ),
            Ok(Some(RPCResponse::MetaData(metadata_v2())))
        );

        assert_eq!(
            encode_then_decode_response::<Mainnet>(
                &config,
                SupportedProtocol::MetaDataV2,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata_v2())),
                Phase::Altair,
            ),
            Ok(Some(RPCResponse::MetaData(metadata_v2())))
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
            RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
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
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRootV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
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
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        // Trying to decode a base block with altair context bytes should give ssz decoding error
        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRangeV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
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
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
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
        //         Protocol::BlocksByRange,
        //         Version::V2,
        //         &mut wrong_fork_bytes,
        //         Phase::Altair
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
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
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
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
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
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        // Sending bytes less than context bytes length should wait for more bytes by returning `Ok(None)`
        let mut encoded_bytes = encode_response::<Mainnet>(
            &config,
            SupportedProtocol::BlocksByRootV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(phase0_block()))),
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

        let requests: &[OutboundRequest<Mainnet>] = &[
            OutboundRequest::Ping(ping_message()),
            OutboundRequest::Status(status_message()),
            OutboundRequest::Goodbye(GoodbyeReason::Fault),
            OutboundRequest::BlocksByRange(bbrange_request_v1()),
            OutboundRequest::BlocksByRange(bbrange_request_v2()),
            OutboundRequest::BlocksByRoot(bbroot_request_v1()),
            OutboundRequest::BlocksByRoot(bbroot_request_v2()),
            OutboundRequest::MetaData(MetadataRequest::new_v1()),
            OutboundRequest::BlobsByRange(blbrange_request()),
            OutboundRequest::BlobsByRoot(blbroot_request()),
            OutboundRequest::MetaData(MetadataRequest::new_v2()),
        ];
        for req in requests.iter() {
            for fork_name in enum_iterator::all::<Phase>() {
                encode_then_decode_request(&config, req.clone(), fork_name);
            }
        }
    }

    /// Test a malicious snappy encoding for a V1 `Status` message where the attacker
    /// sends a valid message filled with a stream of useless padding before the actual message.
    #[test]
    fn test_decode_malicious_v1_message() {
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
            .encode(status_message_bytes.len(), &mut dst)
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
            .encode(Config::default().max_chunk_size + 1, &mut dst)
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
}
