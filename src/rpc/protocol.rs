use super::methods::*;
use crate::rpc::{
    codec::{base::BaseInboundCodec, ssz_snappy::SSZSnappyInboundCodec, InboundCodec},
    methods::ResponseTermination,
};
use crate::types::ForkContext;
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, StreamExt};
use libp2p::core::{InboundUpgrade, UpgradeInfo};
use ssz::{ReadError, SszSize as _, SszWrite as _, WriteError};
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use strum::{AsRefStr, Display, EnumString, IntoStaticStr};
use tokio_io_timeout::TimeoutStream;
use tokio_util::{
    codec::Framed,
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use typenum::Unsigned as _;
use types::{
    altair::containers::{
        LightClientBootstrap as AltairLightClientBootstrap,
        LightClientFinalityUpdate as AltairLightClientFinalityUpdate,
        LightClientOptimisticUpdate as AltairLightClientOptimisticUpdate,
    },
    eip7594::DataColumnSidecar,
    nonstandard::Phase,
    preset::{Mainnet, Preset},
};

pub const SIGNED_BEACON_BLOCK_PHASE0_MIN: usize = 404;
pub const SIGNED_BEACON_BLOCK_PHASE0_MAX: usize = 157756;
pub const SIGNED_BEACON_BLOCK_ALTAIR_MAX: usize = 157916;
pub const SIGNED_BEACON_BLOCK_BELLATRIX_MAX: usize = 1125899911195388;
pub const SIGNED_BEACON_BLOCK_CAPELLA_MAX: usize = 1125899911199368;
pub const SIGNED_BEACON_BLOCK_DENEB_MAX: usize = 1125899911199676;
// TODO(feature/electra):
pub const SIGNED_BEACON_BLOCK_ELECTRA_MAX: usize = 1125899911199676;

pub const BLOB_SIDECAR_MIN: usize = 131928;
pub const BLOB_SIDECAR_MAX: usize = 131928;

static DATA_COLUMN_MIN: LazyLock<usize> = LazyLock::new(|| {
    DataColumnSidecar::<Mainnet>::default()
        .to_ssz()
        .expect("default DataColumnSidecar must be available in SSZ")
        .len()
});
static DATA_COLUMN_MAX: LazyLock<usize> = LazyLock::new(|| {
    DataColumnSidecar::<Mainnet>::full()
        .to_ssz()
        .expect("default DataColumnSidecar must be available in SSZ")
        .len()
});

pub const BLOBS_BY_ROOT_REQUEST_MIN: usize = 0;
pub const BLOBS_BY_ROOT_REQUEST_MAX: usize = 24576;

pub const BLOCKS_BY_ROOT_REQUEST_MIN: usize = 0;
pub const BLOCKS_BY_ROOT_REQUEST_MAX: usize = 32768;

pub const ERROR_TYPE_MIN: usize = 0;
pub const ERROR_TYPE_MAX: usize = 256;

// pub(crate) const MAX_RPC_SIZE_POST_EIP4844: usize = 10 * 1_048_576; // 10M
/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth2/beacon_chain/req";
/// The number of seconds to wait for the first bytes of a request once a protocol has been
/// established before the stream is terminated.
const REQUEST_TIMEOUT: u64 = 15;

/// Returns the maximum bytes that can be sent across the RPC.
pub fn max_rpc_size(fork_context: &ForkContext, max_chunk_size: usize) -> usize {
    match fork_context.current_fork() {
        Phase::Altair | Phase::Phase0 => max_chunk_size / 10,
        Phase::Bellatrix => max_chunk_size,
        Phase::Capella => max_chunk_size,
        Phase::Deneb => max_chunk_size,
        Phase::Electra => max_chunk_size,
    }
}

/// Returns the rpc limits for beacon_block_by_range and beacon_block_by_root responses.
///
/// Note: This function should take care to return the min/max limits accounting for all
/// previous valid forks when adding a new fork variant.
pub fn rpc_block_limits_by_fork(current_fork: Phase) -> RpcLimits {
    match &current_fork {
        Phase::Phase0 => RpcLimits::new(
            SIGNED_BEACON_BLOCK_PHASE0_MIN,
            SIGNED_BEACON_BLOCK_PHASE0_MAX,
        ),
        Phase::Altair => RpcLimits::new(
            SIGNED_BEACON_BLOCK_PHASE0_MIN, // Base block is smaller than altair blocks
            SIGNED_BEACON_BLOCK_ALTAIR_MAX, // Altair block is larger than base blocks
        ),
        Phase::Bellatrix => RpcLimits::new(
            SIGNED_BEACON_BLOCK_PHASE0_MIN, // Base block is smaller than altair and merge blocks
            SIGNED_BEACON_BLOCK_BELLATRIX_MAX, // Merge block is larger than base and altair blocks
        ),
        Phase::Capella => RpcLimits::new(
            SIGNED_BEACON_BLOCK_PHASE0_MIN, // Base block is smaller than altair and merge blocks
            SIGNED_BEACON_BLOCK_CAPELLA_MAX, // Capella block is larger than base, altair and merge blocks
        ),
        Phase::Deneb => RpcLimits::new(
            SIGNED_BEACON_BLOCK_PHASE0_MIN, // Base block is smaller than altair and merge blocks
            SIGNED_BEACON_BLOCK_DENEB_MAX,  // EIP 4844 block is larger than all prior fork blocks
        ),
        Phase::Electra => RpcLimits::new(
            SIGNED_BEACON_BLOCK_PHASE0_MIN, // Base block is smaller than altair and merge blocks
            SIGNED_BEACON_BLOCK_ELECTRA_MAX, // Electra block is larger than Deneb block
        ),
    }
}

fn rpc_light_client_finality_update_limits_by_fork<P: Preset>(current_fork: Phase) -> RpcLimits {
    let altair_fixed_len = AltairLightClientFinalityUpdate::<Mainnet>::SIZE.get();

    match &current_fork {
        Phase::Phase0 => RpcLimits::new(0, 0),
        Phase::Altair | Phase::Bellatrix => RpcLimits::new(altair_fixed_len, altair_fixed_len),
        Phase::Capella => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
        Phase::Deneb => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
        Phase::Electra => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
    }
}

fn rpc_light_client_optimistic_update_limits_by_fork<P: Preset>(current_fork: Phase) -> RpcLimits {
    let altair_fixed_len = AltairLightClientOptimisticUpdate::<Mainnet>::SIZE.get();

    match &current_fork {
        Phase::Phase0 => RpcLimits::new(0, 0),
        Phase::Altair | Phase::Bellatrix => RpcLimits::new(altair_fixed_len, altair_fixed_len),
        Phase::Capella => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
        Phase::Deneb => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
        Phase::Electra => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
    }
}

fn rpc_light_client_bootstrap_limits_by_fork<P: Preset>(current_fork: Phase) -> RpcLimits {
    let altair_fixed_len = AltairLightClientBootstrap::<Mainnet>::SIZE.get();

    match &current_fork {
        Phase::Phase0 => RpcLimits::new(0, 0),
        Phase::Altair | Phase::Bellatrix => RpcLimits::new(altair_fixed_len, altair_fixed_len),
        Phase::Capella => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
        Phase::Deneb => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
        Phase::Electra => RpcLimits::new(
            altair_fixed_len,
            altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
        ),
    }
}

/// Protocol names to be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, AsRefStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Protocol {
    /// The Status protocol name.
    Status,
    /// The Goodbye protocol name.
    Goodbye,
    /// The `BlocksByRange` protocol name.
    #[strum(serialize = "beacon_blocks_by_range")]
    BlocksByRange,
    /// The `BlocksByRoot` protocol name.
    #[strum(serialize = "beacon_blocks_by_root")]
    BlocksByRoot,
    /// The `BlobsByRange` protocol name.
    #[strum(serialize = "blob_sidecars_by_range")]
    BlobsByRange,
    /// The `BlobsByRoot` protocol name.
    #[strum(serialize = "blob_sidecars_by_root")]
    BlobsByRoot,
    /// The `DataColumnSidecarsByRoot` protocol name.
    #[strum(serialize = "data_column_sidecars_by_root")]
    DataColumnsByRoot,
    /// The `DataColumnSidecarsByRange` protocol name.
    #[strum(serialize = "data_column_sidecars_by_range")]
    DataColumnsByRange,
    /// The `Ping` protocol name.
    Ping,
    /// The `MetaData` protocol name.
    #[strum(serialize = "metadata")]
    MetaData,
    /// The `LightClientBootstrap` protocol name.
    #[strum(serialize = "light_client_bootstrap")]
    LightClientBootstrap,
    /// The `LightClientOptimisticUpdate` protocol name.
    #[strum(serialize = "light_client_optimistic_update")]
    LightClientOptimisticUpdate,
    /// The `LightClientFinalityUpdate` protocol name.
    #[strum(serialize = "light_client_finality_update")]
    LightClientFinalityUpdate,
}

impl Protocol {
    pub(crate) fn terminator(self) -> Option<ResponseTermination> {
        match self {
            Protocol::Status => None,
            Protocol::Goodbye => None,
            Protocol::BlocksByRange => Some(ResponseTermination::BlocksByRange),
            Protocol::BlocksByRoot => Some(ResponseTermination::BlocksByRoot),
            Protocol::BlobsByRange => Some(ResponseTermination::BlobsByRange),
            Protocol::BlobsByRoot => Some(ResponseTermination::BlobsByRoot),
            Protocol::DataColumnsByRoot => Some(ResponseTermination::DataColumnsByRoot),
            Protocol::DataColumnsByRange => Some(ResponseTermination::DataColumnsByRange),
            Protocol::Ping => None,
            Protocol::MetaData => None,
            Protocol::LightClientBootstrap => None,
            Protocol::LightClientOptimisticUpdate => None,
            Protocol::LightClientFinalityUpdate => None,
        }
    }
}

/// Protocol names to be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, AsRefStr)]
#[strum(serialize_all = "snake_case")]
/// RPC Encondings supported.
pub enum Encoding {
    SSZSnappy,
}

/// All valid protocol name and version combinations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SupportedProtocol {
    StatusV1,
    GoodbyeV1,
    BlocksByRangeV1,
    BlocksByRangeV2,
    BlocksByRootV1,
    BlocksByRootV2,
    BlobsByRangeV1,
    BlobsByRootV1,
    DataColumnsByRootV1,
    DataColumnsByRangeV1,
    PingV1,
    MetaDataV1,
    MetaDataV2,
    MetaDataV3,
    LightClientBootstrapV1,
    LightClientOptimisticUpdateV1,
    LightClientFinalityUpdateV1,
}

impl SupportedProtocol {
    pub fn version_string(&self) -> &'static str {
        match self {
            SupportedProtocol::StatusV1 => "1",
            SupportedProtocol::GoodbyeV1 => "1",
            SupportedProtocol::BlocksByRangeV1 => "1",
            SupportedProtocol::BlocksByRangeV2 => "2",
            SupportedProtocol::BlocksByRootV1 => "1",
            SupportedProtocol::BlocksByRootV2 => "2",
            SupportedProtocol::BlobsByRangeV1 => "1",
            SupportedProtocol::BlobsByRootV1 => "1",
            SupportedProtocol::DataColumnsByRootV1 => "1",
            SupportedProtocol::DataColumnsByRangeV1 => "1",
            SupportedProtocol::PingV1 => "1",
            SupportedProtocol::MetaDataV1 => "1",
            SupportedProtocol::MetaDataV2 => "2",
            SupportedProtocol::MetaDataV3 => "3",
            SupportedProtocol::LightClientBootstrapV1 => "1",
            SupportedProtocol::LightClientOptimisticUpdateV1 => "1",
            SupportedProtocol::LightClientFinalityUpdateV1 => "1",
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            SupportedProtocol::StatusV1 => Protocol::Status,
            SupportedProtocol::GoodbyeV1 => Protocol::Goodbye,
            SupportedProtocol::BlocksByRangeV1 => Protocol::BlocksByRange,
            SupportedProtocol::BlocksByRangeV2 => Protocol::BlocksByRange,
            SupportedProtocol::BlocksByRootV1 => Protocol::BlocksByRoot,
            SupportedProtocol::BlocksByRootV2 => Protocol::BlocksByRoot,
            SupportedProtocol::BlobsByRangeV1 => Protocol::BlobsByRange,
            SupportedProtocol::BlobsByRootV1 => Protocol::BlobsByRoot,
            SupportedProtocol::DataColumnsByRootV1 => Protocol::DataColumnsByRoot,
            SupportedProtocol::DataColumnsByRangeV1 => Protocol::DataColumnsByRange,
            SupportedProtocol::PingV1 => Protocol::Ping,
            SupportedProtocol::MetaDataV1 => Protocol::MetaData,
            SupportedProtocol::MetaDataV2 => Protocol::MetaData,
            SupportedProtocol::MetaDataV3 => Protocol::MetaData,
            SupportedProtocol::LightClientBootstrapV1 => Protocol::LightClientBootstrap,
            SupportedProtocol::LightClientOptimisticUpdateV1 => {
                Protocol::LightClientOptimisticUpdate
            }
            SupportedProtocol::LightClientFinalityUpdateV1 => Protocol::LightClientFinalityUpdate,
        }
    }

    fn currently_supported(fork_context: &Arc<ForkContext>) -> Vec<ProtocolId> {
        let mut supported = vec![
            ProtocolId::new(Self::StatusV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::GoodbyeV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRangeV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRangeV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::PingV1, Encoding::SSZSnappy),
        ];
        // metadata protocol negotiation, the `MetaDataV3` has higher preference.
        if fork_context.is_eip7594_enabled() {
            supported.extend_from_slice(&[
                ProtocolId::new(Self::MetaDataV3, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV1, Encoding::SSZSnappy),
            ])
        } else {
            supported.extend_from_slice(&[
                ProtocolId::new(Self::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV1, Encoding::SSZSnappy),
            ])
        }

        if fork_context.fork_exists(Phase::Deneb) {
            supported.extend_from_slice(&[
                ProtocolId::new(Self::BlobsByRootV1, Encoding::SSZSnappy),
                ProtocolId::new(Self::BlobsByRangeV1, Encoding::SSZSnappy),
            ]);
        }

        if fork_context.is_eip7594_enabled() {
            supported.extend_from_slice(&[
                ProtocolId::new(Self::DataColumnsByRootV1, Encoding::SSZSnappy),
                ProtocolId::new(Self::DataColumnsByRangeV1, Encoding::SSZSnappy),
            ])
        }
        supported
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Encoding::SSZSnappy => "ssz_snappy",
        };
        f.write_str(repr)
    }
}

#[derive(Debug, Clone)]
pub struct RPCProtocol<P: Preset> {
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
    pub enable_light_client_server: bool,
    pub phantom: PhantomData<P>,
    pub ttfb_timeout: Duration,
}

impl<P: Preset> UpgradeInfo for RPCProtocol<P> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    /// The list of supported RPC protocols.
    fn protocol_info(&self) -> Self::InfoIter {
        let mut supported_protocols = SupportedProtocol::currently_supported(&self.fork_context);
        if self.enable_light_client_server {
            supported_protocols.push(ProtocolId::new(
                SupportedProtocol::LightClientBootstrapV1,
                Encoding::SSZSnappy,
            ));
            supported_protocols.push(ProtocolId::new(
                SupportedProtocol::LightClientOptimisticUpdateV1,
                Encoding::SSZSnappy,
            ));
            supported_protocols.push(ProtocolId::new(
                SupportedProtocol::LightClientFinalityUpdateV1,
                Encoding::SSZSnappy,
            ));
        }
        supported_protocols
    }
}

/// Represents the ssz length bounds for RPC messages.
#[derive(Debug, PartialEq)]
pub struct RpcLimits {
    pub min: usize,
    pub max: usize,
}

impl RpcLimits {
    pub fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }

    /// Returns true if the given length is greater than `max_rpc_size` or out of
    /// bounds for the given ssz type, returns false otherwise.
    pub fn is_out_of_bounds(&self, length: usize, max_rpc_size: usize) -> bool {
        length > std::cmp::min(self.max, max_rpc_size) || length < self.min
    }
}

/// Tracks the types in a protocol id.
#[derive(Clone, Debug)]
pub struct ProtocolId {
    /// The protocol name and version
    pub versioned_protocol: SupportedProtocol,

    /// The encoding of the RPC.
    pub encoding: Encoding,

    /// The protocol id that is formed from the above fields.
    protocol_id: String,
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        self.protocol_id.as_ref()
    }
}

impl ProtocolId {
    /// Returns min and max size for messages of given protocol id requests.
    pub fn rpc_request_limits(&self) -> RpcLimits {
        match self.versioned_protocol.protocol() {
            Protocol::Status => {
                RpcLimits::new(StatusMessage::SIZE.get(), StatusMessage::SIZE.get())
            }
            Protocol::Goodbye => {
                RpcLimits::new(GoodbyeReason::SIZE.get(), GoodbyeReason::SIZE.get())
            }
            // V1 and V2 requests are the same
            Protocol::BlocksByRange => RpcLimits::new(
                OldBlocksByRangeRequestV2::SIZE.get(),
                OldBlocksByRangeRequestV2::SIZE.get(),
            ),
            Protocol::BlocksByRoot => {
                RpcLimits::new(BLOCKS_BY_ROOT_REQUEST_MIN, BLOCKS_BY_ROOT_REQUEST_MAX)
            }
            Protocol::BlobsByRange => RpcLimits::new(
                BlobsByRangeRequest::SIZE.get(),
                BlobsByRangeRequest::SIZE.get(),
            ),
            Protocol::DataColumnsByRoot => RpcLimits::new(0, MaxRequestDataColumnSidecars::USIZE),
            Protocol::DataColumnsByRange => RpcLimits::new(
                DataColumnsByRangeRequest::ssz_min_len(),
                DataColumnsByRangeRequest::ssz_max_len(),
            ),
            Protocol::BlobsByRoot => {
                RpcLimits::new(BLOBS_BY_ROOT_REQUEST_MIN, BLOBS_BY_ROOT_REQUEST_MAX)
            }
            Protocol::Ping => RpcLimits::new(Ping::SIZE.get(), Ping::SIZE.get()),
            Protocol::LightClientBootstrap => RpcLimits::new(
                LightClientBootstrapRequest::SIZE.get(),
                LightClientBootstrapRequest::SIZE.get(),
            ),
            Protocol::LightClientOptimisticUpdate => RpcLimits::new(0, 0),
            Protocol::LightClientFinalityUpdate => RpcLimits::new(0, 0),
            Protocol::MetaData => RpcLimits::new(0, 0), // Metadata requests are empty
        }
    }

    /// Returns min and max size for messages of given protocol id responses.
    pub fn rpc_response_limits<P: Preset>(&self, fork_context: &ForkContext) -> RpcLimits {
        match self.versioned_protocol.protocol() {
            Protocol::Status => {
                RpcLimits::new(StatusMessage::SIZE.get(), StatusMessage::SIZE.get())
            }
            Protocol::Goodbye => RpcLimits::new(0, 0), // Goodbye request has no response
            Protocol::BlocksByRange => rpc_block_limits_by_fork(fork_context.current_fork()),
            Protocol::BlocksByRoot => rpc_block_limits_by_fork(fork_context.current_fork()),
            Protocol::BlobsByRange => rpc_blob_limits::<P>(),
            Protocol::BlobsByRoot => rpc_blob_limits::<P>(),
            Protocol::DataColumnsByRoot => rpc_data_column_limits::<P>(),
            Protocol::DataColumnsByRange => rpc_data_column_limits::<P>(),
            Protocol::Ping => RpcLimits::new(Ping::SIZE.get(), Ping::SIZE.get()),
            Protocol::MetaData => RpcLimits::new(MetaDataV1::SIZE.get(), MetaDataV3::SIZE.get()),
            Protocol::LightClientBootstrap => {
                rpc_light_client_bootstrap_limits_by_fork::<P>(fork_context.current_fork())
            }
            Protocol::LightClientOptimisticUpdate => {
                rpc_light_client_optimistic_update_limits_by_fork::<P>(fork_context.current_fork())
            }
            Protocol::LightClientFinalityUpdate => {
                rpc_light_client_finality_update_limits_by_fork::<P>(fork_context.current_fork())
            }
        }
    }

    /// Returns `true` if the given `ProtocolId` should expect `context_bytes` in the
    /// beginning of the stream, else returns `false`.
    pub fn has_context_bytes(&self) -> bool {
        match self.versioned_protocol {
            SupportedProtocol::BlocksByRangeV2
            | SupportedProtocol::BlocksByRootV2
            | SupportedProtocol::BlobsByRangeV1
            | SupportedProtocol::BlobsByRootV1
            | SupportedProtocol::DataColumnsByRootV1
            | SupportedProtocol::DataColumnsByRangeV1
            | SupportedProtocol::LightClientBootstrapV1
            | SupportedProtocol::LightClientOptimisticUpdateV1
            | SupportedProtocol::LightClientFinalityUpdateV1 => true,
            SupportedProtocol::StatusV1
            | SupportedProtocol::BlocksByRootV1
            | SupportedProtocol::BlocksByRangeV1
            | SupportedProtocol::PingV1
            | SupportedProtocol::MetaDataV1
            | SupportedProtocol::MetaDataV2
            | SupportedProtocol::MetaDataV3
            | SupportedProtocol::GoodbyeV1 => false,
        }
    }
}

/// An RPC protocol ID.
impl ProtocolId {
    pub fn new(versioned_protocol: SupportedProtocol, encoding: Encoding) -> Self {
        let protocol_id = format!(
            "{}/{}/{}/{}",
            PROTOCOL_PREFIX,
            versioned_protocol.protocol(),
            versioned_protocol.version_string(),
            encoding
        );

        ProtocolId {
            versioned_protocol,
            encoding,
            protocol_id,
        }
    }
}

/* Inbound upgrade */

// The inbound protocol reads the request, decodes it and returns the stream to the protocol
// handler to respond to once ready.

pub type InboundOutput<TSocket, P> = (InboundRequest<P>, InboundFramed<TSocket, P>);
pub type InboundFramed<TSocket, P> =
    Framed<std::pin::Pin<Box<TimeoutStream<Compat<TSocket>>>>, InboundCodec<P>>;

impl<TSocket, P> InboundUpgrade<TSocket> for RPCProtocol<P>
where
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: Preset,
{
    type Output = InboundOutput<TSocket, P>;
    type Error = RPCError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: TSocket, protocol: ProtocolId) -> Self::Future {
        async move {
            let versioned_protocol = protocol.versioned_protocol;
            // convert the socket to tokio compatible socket
            let socket = socket.compat();
            let codec = match protocol.encoding {
                Encoding::SSZSnappy => {
                    let ssz_snappy_codec = BaseInboundCodec::new(SSZSnappyInboundCodec::new(
                        protocol,
                        self.max_rpc_size,
                        self.fork_context.clone(),
                    ));
                    InboundCodec::SSZSnappy(ssz_snappy_codec)
                }
            };
            let mut timed_socket = TimeoutStream::new(socket);
            timed_socket.set_read_timeout(Some(self.ttfb_timeout));

            let socket = Framed::new(Box::pin(timed_socket), codec);

            // MetaData requests should be empty, return the stream
            match versioned_protocol {
                SupportedProtocol::MetaDataV1 => {
                    Ok((InboundRequest::MetaData(MetadataRequest::new_v1()), socket))
                }
                SupportedProtocol::MetaDataV2 => {
                    Ok((InboundRequest::MetaData(MetadataRequest::new_v2()), socket))
                }
                SupportedProtocol::MetaDataV3 => {
                    Ok((InboundRequest::MetaData(MetadataRequest::new_v3()), socket))
                }
                SupportedProtocol::LightClientOptimisticUpdateV1 => {
                    Ok((InboundRequest::LightClientOptimisticUpdate, socket))
                }
                SupportedProtocol::LightClientFinalityUpdateV1 => {
                    Ok((InboundRequest::LightClientFinalityUpdate, socket))
                }
                _ => {
                    match tokio::time::timeout(
                        Duration::from_secs(REQUEST_TIMEOUT),
                        socket.into_future(),
                    )
                    .await
                    {
                        Err(e) => Err(RPCError::from(e)),
                        Ok((Some(Ok(request)), stream)) => Ok((request, stream)),
                        Ok((Some(Err(e)), _)) => Err(e),
                        Ok((None, _)) => Err(RPCError::IncompleteStream),
                    }
                }
            }
        }
        .boxed()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InboundRequest<P: Preset> {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    BlocksByRange(OldBlocksByRangeRequest),
    BlocksByRoot(BlocksByRootRequest),
    BlobsByRange(BlobsByRangeRequest),
    BlobsByRoot(BlobsByRootRequest),
    DataColumnsByRoot(DataColumnsByRootRequest),
    DataColumnsByRange(DataColumnsByRangeRequest),
    LightClientBootstrap(LightClientBootstrapRequest),
    LightClientOptimisticUpdate,
    LightClientFinalityUpdate,
    Ping(Ping),
    MetaData(MetadataRequest<P>),
}

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<P: Preset> InboundRequest<P> {
    /// Maximum number of responses expected for this request.
    pub fn max_responses(&self) -> u64 {
        match self {
            InboundRequest::Status(_) => 1,
            InboundRequest::Goodbye(_) => 0,
            InboundRequest::BlocksByRange(req) => req.count(),
            InboundRequest::BlocksByRoot(req) => req.len() as u64,
            InboundRequest::BlobsByRange(req) => req.max_blobs_requested::<P>(),
            InboundRequest::BlobsByRoot(req) => req.blob_ids.len() as u64,
            InboundRequest::LightClientBootstrap(_) => 1,
            InboundRequest::LightClientOptimisticUpdate => 1,
            InboundRequest::LightClientFinalityUpdate => 1,
            InboundRequest::DataColumnsByRoot(req) => req.data_column_ids.len() as u64,
            InboundRequest::DataColumnsByRange(req) => req.max_requested::<P>(),
            InboundRequest::Ping(_) => 1,
            InboundRequest::MetaData(_) => 1,
        }
    }

    /// Gives the corresponding `SupportedProtocol` to this request.
    pub fn versioned_protocol(&self) -> SupportedProtocol {
        match self {
            InboundRequest::Status(_) => SupportedProtocol::StatusV1,
            InboundRequest::Goodbye(_) => SupportedProtocol::GoodbyeV1,
            InboundRequest::BlocksByRange(req) => match req {
                OldBlocksByRangeRequest::V1(_) => SupportedProtocol::BlocksByRangeV1,
                OldBlocksByRangeRequest::V2(_) => SupportedProtocol::BlocksByRangeV2,
            },
            InboundRequest::BlocksByRoot(req) => match req {
                BlocksByRootRequest::V1(_) => SupportedProtocol::BlocksByRootV1,
                BlocksByRootRequest::V2(_) => SupportedProtocol::BlocksByRootV2,
            },
            InboundRequest::BlobsByRange(_) => SupportedProtocol::BlobsByRangeV1,
            InboundRequest::BlobsByRoot(_) => SupportedProtocol::BlobsByRootV1,
            InboundRequest::DataColumnsByRoot(_) => SupportedProtocol::DataColumnsByRootV1,
            InboundRequest::DataColumnsByRange(_) => SupportedProtocol::DataColumnsByRangeV1,
            InboundRequest::Ping(_) => SupportedProtocol::PingV1,
            InboundRequest::MetaData(req) => match req {
                MetadataRequest::V1(_) => SupportedProtocol::MetaDataV1,
                MetadataRequest::V2(_) => SupportedProtocol::MetaDataV2,
                MetadataRequest::V3(_) => SupportedProtocol::MetaDataV3,
            },
            InboundRequest::LightClientBootstrap(_) => SupportedProtocol::LightClientBootstrapV1,
            InboundRequest::LightClientOptimisticUpdate => {
                SupportedProtocol::LightClientOptimisticUpdateV1
            }
            InboundRequest::LightClientFinalityUpdate => {
                SupportedProtocol::LightClientFinalityUpdateV1
            }
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            InboundRequest::BlocksByRange(_) => ResponseTermination::BlocksByRange,
            InboundRequest::BlocksByRoot(_) => ResponseTermination::BlocksByRoot,
            InboundRequest::BlobsByRange(_) => ResponseTermination::BlobsByRange,
            InboundRequest::BlobsByRoot(_) => ResponseTermination::BlobsByRoot,
            InboundRequest::DataColumnsByRoot(_) => ResponseTermination::DataColumnsByRoot,
            InboundRequest::DataColumnsByRange(_) => ResponseTermination::DataColumnsByRange,
            InboundRequest::Status(_) => unreachable!(),
            InboundRequest::Goodbye(_) => unreachable!(),
            InboundRequest::Ping(_) => unreachable!(),
            InboundRequest::MetaData(_) => unreachable!(),
            InboundRequest::LightClientBootstrap(_) => unreachable!(),
            InboundRequest::LightClientFinalityUpdate => unreachable!(),
            InboundRequest::LightClientOptimisticUpdate => unreachable!(),
        }
    }
}

/// Error in RPC Encoding/Decoding.
#[derive(Debug, Clone, PartialEq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RPCError {
    /// Error when decoding the raw buffer from ssz.
    // NOTE: in the future a ssz::ReadError should map to an InvalidData error
    #[strum(serialize = "decode_error")]
    SszReadError(ReadError),
    /// Error when encoding data as SSZ.
    #[strum(serialize = "encode_error")]
    SszWriteError(WriteError),
    /// IO Error.
    IoError(String),
    /// The peer returned a valid response but the response indicated an error.
    ErrorResponse(RPCResponseErrorCode, String),
    /// Timed out waiting for a response.
    StreamTimeout,
    /// Peer does not support the protocol.
    UnsupportedProtocol,
    /// Stream ended unexpectedly.
    IncompleteStream,
    /// Peer sent invalid data.
    InvalidData(String),
    /// An error occurred due to internal reasons. Ex: timer failure.
    InternalError(&'static str),
    /// Negotiation with this peer timed out.
    NegotiationTimeout,
    /// Handler rejected this request.
    HandlerRejected,
    /// We have intentionally disconnected.
    Disconnected,
}

impl From<ReadError> for RPCError {
    #[inline]
    fn from(err: ReadError) -> Self {
        RPCError::SszReadError(err)
    }
}

impl From<WriteError> for RPCError {
    #[inline]
    fn from(err: WriteError) -> Self {
        RPCError::SszWriteError(err)
    }
}

impl From<tokio::time::error::Elapsed> for RPCError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        RPCError::StreamTimeout
    }
}

impl From<io::Error> for RPCError {
    fn from(err: io::Error) -> Self {
        RPCError::IoError(err.to_string())
    }
}

// Error trait is required for `ProtocolsHandler`
impl std::fmt::Display for RPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RPCError::SszReadError(ref err) => write!(f, "Error while decoding ssz: {:?}", err),
            RPCError::SszWriteError(ref err) => write!(f, "Error while encoding ssz: {:?}", err),
            RPCError::InvalidData(ref err) => write!(f, "Peer sent unexpected data: {}", err),
            RPCError::IoError(ref err) => write!(f, "IO Error: {}", err),
            RPCError::ErrorResponse(ref code, ref reason) => write!(
                f,
                "RPC response was an error: {} with reason: {}",
                code, reason
            ),
            RPCError::StreamTimeout => write!(f, "Stream Timeout"),
            RPCError::UnsupportedProtocol => write!(f, "Peer does not support the protocol"),
            RPCError::IncompleteStream => write!(f, "Stream ended unexpectedly"),
            RPCError::InternalError(ref err) => write!(f, "Internal error: {}", err),
            RPCError::NegotiationTimeout => write!(f, "Negotiation timeout"),
            RPCError::HandlerRejected => write!(f, "Handler rejected the request"),
            RPCError::Disconnected => write!(f, "Gracefully Disconnected"),
        }
    }
}

impl std::error::Error for RPCError {}

pub fn rpc_blob_limits<P: Preset>() -> RpcLimits {
    RpcLimits::new(BLOB_SIDECAR_MIN, BLOB_SIDECAR_MAX)
}

pub fn rpc_data_column_limits<P: Preset>() -> RpcLimits {
    RpcLimits::new(*DATA_COLUMN_MIN, *DATA_COLUMN_MAX)
}

impl<P: Preset> std::fmt::Display for InboundRequest<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InboundRequest::Status(status) => write!(f, "Status Message: {}", status),
            InboundRequest::Goodbye(reason) => write!(f, "Goodbye: {}", reason),
            InboundRequest::BlocksByRange(req) => write!(f, "Blocks by range: {}", req),
            InboundRequest::BlocksByRoot(req) => write!(f, "Blocks by root: {:?}", req),
            InboundRequest::BlobsByRange(req) => write!(f, "Blobs by range: {:?}", req),
            InboundRequest::BlobsByRoot(req) => write!(f, "Blobs by root: {:?}", req),
            InboundRequest::DataColumnsByRoot(req) => write!(f, "Data columns by root: {:?}", req),
            InboundRequest::DataColumnsByRange(req) => {
                write!(f, "Data columns by range: {:?}", req)
            }
            InboundRequest::Ping(ping) => write!(f, "Ping: {}", ping.data),
            InboundRequest::MetaData(_) => write!(f, "MetaData request"),
            InboundRequest::LightClientBootstrap(bootstrap) => {
                write!(f, "Light client boostrap: {}", bootstrap.root)
            }
            InboundRequest::LightClientOptimisticUpdate => {
                write!(f, "Light client optimistic update request")
            }
            InboundRequest::LightClientFinalityUpdate => {
                write!(f, "Light client finality update request")
            }
        }
    }
}

impl RPCError {
    /// Get a `str` representation of the error.
    /// Used for metrics.
    pub fn as_static_str(&self) -> &'static str {
        match self {
            RPCError::ErrorResponse(ref code, ..) => code.into(),
            e => e.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ssz::{ContiguousList, SszWrite as _};
    use types::{
        // altair::containers::SignedBeaconBlock as AltairSignedBeaconBlock,
        // bellatrix::containers::SignedBeaconBlock as BellatrixBeaconBlock,
        phase0::{containers::SignedBeaconBlock as Phase0SignedBeaconBlock, primitives::H256},
        preset::Mainnet,
    };

    use crate::{factory, rpc::methods::MaxErrorLen};

    use super::*;

    #[test]
    fn length_constants_are_calculated_from_ssz_encodings() {
        assert_eq!(
            SIGNED_BEACON_BLOCK_PHASE0_MIN,
            Phase0SignedBeaconBlock::<Mainnet>::default()
                .to_ssz()
                .unwrap()
                .len(),
        );
        assert_eq!(
            SIGNED_BEACON_BLOCK_PHASE0_MAX,
            factory::full_phase0_signed_beacon_block::<Mainnet>()
                .to_ssz()
                .unwrap()
                .len(),
        );
        // assert_eq!(
        //     SIGNED_BEACON_BLOCK_ALTAIR_MIN,
        //     AltairSignedBeaconBlock::<Mainnet>::default()
        //         .to_ssz()
        //         .unwrap()
        //         .len(),
        // );
        assert_eq!(
            SIGNED_BEACON_BLOCK_ALTAIR_MAX,
            factory::full_altair_signed_beacon_block::<Mainnet>()
                .to_ssz()
                .unwrap()
                .len(),
        );
        // assert_eq!(
        //     SIGNED_BEACON_BLOCK_BELLATRIX_MIN,
        //     BellatrixBeaconBlock::<Mainnet>::default()
        //         .to_ssz()
        //         .unwrap()
        //         .len(),
        // );
        assert_eq!(
            BLOCKS_BY_ROOT_REQUEST_MIN,
            ContiguousList::<H256, MaxRequestBlocks>::default()
                .to_ssz()
                .unwrap()
                .len(),
        );
        assert_eq!(
            BLOCKS_BY_ROOT_REQUEST_MAX,
            ContiguousList::<H256, MaxRequestBlocks>::full(H256::zero())
                .to_ssz()
                .unwrap()
                .len(),
        );
        assert_eq!(
            ERROR_TYPE_MIN,
            ContiguousList::<u8, MaxErrorLen>::default()
                .to_ssz()
                .unwrap()
                .len(),
        );
        assert_eq!(
            ERROR_TYPE_MAX,
            ContiguousList::<u8, MaxErrorLen>::full(0)
                .to_ssz()
                .unwrap()
                .len(),
        );
    }
}
