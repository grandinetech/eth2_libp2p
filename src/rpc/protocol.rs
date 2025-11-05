use super::methods::*;
use crate::rpc::codec::SSZSnappyInboundCodec;
use crate::types::ForkContext;
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, StreamExt};
use helper_functions::misc;
use libp2p::core::{InboundUpgrade, UpgradeInfo};
use ssz::{
    ContiguousList, ReadError, SszSize as _, SszWrite as _, WriteError, BYTES_PER_LENGTH_OFFSET,
    H256,
};
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use std_ext::ArcExt as _;
use strum::{AsRefStr, Display, EnumString, IntoStaticStr};
use tokio_util::{
    codec::Framed,
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use typenum::Unsigned as _;
use types::deneb::containers::{BlobIdentifier, ExecutionPayload};
use types::electra::containers::ExecutionRequests;
use types::fulu::containers::DataColumnSidecar as FuluDataColumnSidecar;
use types::gloas::containers::{
    DataColumnSidecar as GloasDataColumnSidecar, ExecutionPayloadEnvelope,
    SignedExecutionPayloadEnvelope,
};
use types::phase0::primitives::{Slot, ValidatorIndex};
use bls::SignatureBytes;
use types::phase0::primitives::Epoch;
use types::{
    altair::containers::{
        LightClientBootstrap as AltairLightClientBootstrap,
        LightClientFinalityUpdate as AltairLightClientFinalityUpdate,
        LightClientOptimisticUpdate as AltairLightClientOptimisticUpdate,
        LightClientUpdate as AltairLightClientUpdate,
    },
    config::Config as ChainConfig,
    nonstandard::Phase,
    preset::{Mainnet, Preset, PresetName},
};

pub const SIGNED_BEACON_BLOCK_PHASE0_MIN: usize = 404;
pub const SIGNED_BEACON_BLOCK_PHASE0_MAX: usize = 157756;
pub const SIGNED_BEACON_BLOCK_ALTAIR_MAX: usize = 157916;
pub const SIGNED_BEACON_BLOCK_BELLATRIX_MAX: usize = 1125899911195388;

pub const BLOB_SIDECAR_MIN: usize = 131928;
pub const BLOB_SIDECAR_MAX: usize = 131928;

pub const BLOB_SIDECAR_MINIMAL_MIN: usize = 131704;
pub const BLOB_SIDECAR_MINIMAL_MAX: usize = 131704;

pub static DATA_COLUMN_FULU_MIN: LazyLock<usize> = LazyLock::new(|| {
    FuluDataColumnSidecar::<Mainnet>::default()
        .to_ssz()
        .expect("default DataColumnSidecar unavailable in SSZ")
        .len()
});

pub static DATA_COLUMN_FULU_MAX: LazyLock<usize> = LazyLock::new(|| {
    FuluDataColumnSidecar::<Mainnet>::full()
        .to_ssz()
        .expect("full DataColumnSidecar unavailable in SSZ")
        .len()
});

pub static DATA_COLUMN_GLOAS_MIN: LazyLock<usize> = LazyLock::new(|| {
    GloasDataColumnSidecar::<Mainnet>::default()
        .to_ssz()
        .expect("default DataColumnSidecar unavailable in SSZ")
        .len()
});

pub static DATA_COLUMN_GLOAS_MAX: LazyLock<usize> = LazyLock::new(|| {
    GloasDataColumnSidecar::<Mainnet>::full()
        .to_ssz()
        .expect("full DataColumnSidecar unavailable in SSZ")
        .len()
});


/// Minimum SSZ size of SignedExecutionPayloadEnvelope (all variable fields at minimum).
pub static SIGNED_EXECUTION_PAYLOAD_ENVELOPE_GLOAS_MIN: LazyLock<usize> = LazyLock::new(|| {
    SignedExecutionPayloadEnvelope::<Mainnet>::default()
        .to_ssz()
        .expect("should serialize")
        .len()
});

/// Maximum SSZ size of SignedExecutionPayloadEnvelope.
/// Uses .full() method which fills all variable-length fields to maximum.
pub static SIGNED_EXECUTION_PAYLOAD_ENVELOPE_GLOAS_MAX: LazyLock<usize> = LazyLock::new(|| {
    SignedExecutionPayloadEnvelope::<Mainnet>::full()
        .to_ssz()
        .expect("should serialize")
        .len()
});

pub const ERROR_TYPE_MIN: usize = 0;
pub const ERROR_TYPE_MAX: usize = 256;

// pub(crate) const MAX_RPC_SIZE_POST_EIP4844: usize = 10 * 1_048_576; // 10M

/// The protocol prefix the RPC protocol id.
const PROTOCOL_PREFIX: &str = "/eth2/beacon_chain/req";
/// The number of seconds to wait for the first bytes of a request once a protocol has been
/// established before the stream is terminated.
const REQUEST_TIMEOUT: u64 = 15;

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
        // After the merge the max SSZ size of a block is absurdly big. The size is actually
        // bound by other constants, so here we default to the bellatrix's max value
        _ => RpcLimits::new(
            SIGNED_BEACON_BLOCK_PHASE0_MIN, // Base block is smaller than altair and merge blocks
            SIGNED_BEACON_BLOCK_BELLATRIX_MAX, // Merge block is larger than base and altair blocks
        ),
    }
}

fn rpc_light_client_updates_by_range_limits_by_fork<P: Preset>(current_fork: Phase) -> RpcLimits {
    let altair_fixed_len = AltairLightClientUpdate::<Mainnet>::SIZE.get();

    match &current_fork {
        Phase::Phase0 => RpcLimits::new(0, 0),
        Phase::Altair | Phase::Bellatrix => RpcLimits::new(altair_fixed_len, altair_fixed_len),
        Phase::Capella | Phase::Deneb | Phase::Electra | Phase::Fulu | Phase::Gloas => {
            RpcLimits::new(
                altair_fixed_len,
                altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
            )
        }
    }
}

fn rpc_light_client_finality_update_limits_by_fork<P: Preset>(current_fork: Phase) -> RpcLimits {
    let altair_fixed_len = AltairLightClientFinalityUpdate::<Mainnet>::SIZE.get();

    match &current_fork {
        Phase::Phase0 => RpcLimits::new(0, 0),
        Phase::Altair | Phase::Bellatrix => RpcLimits::new(altair_fixed_len, altair_fixed_len),
        Phase::Capella | Phase::Deneb | Phase::Electra | Phase::Fulu | Phase::Gloas => {
            RpcLimits::new(
                altair_fixed_len,
                altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
            )
        }
    }
}

fn rpc_light_client_optimistic_update_limits_by_fork<P: Preset>(current_fork: Phase) -> RpcLimits {
    let altair_fixed_len = AltairLightClientOptimisticUpdate::<Mainnet>::SIZE.get();

    match &current_fork {
        Phase::Phase0 => RpcLimits::new(0, 0),
        Phase::Altair | Phase::Bellatrix => RpcLimits::new(altair_fixed_len, altair_fixed_len),
        Phase::Capella | Phase::Deneb | Phase::Electra | Phase::Fulu | Phase::Gloas => {
            RpcLimits::new(
                altair_fixed_len,
                altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
            )
        }
    }
}

fn rpc_light_client_bootstrap_limits_by_fork<P: Preset>(current_fork: Phase) -> RpcLimits {
    let altair_fixed_len = AltairLightClientBootstrap::<Mainnet>::SIZE.get();

    match &current_fork {
        Phase::Phase0 => RpcLimits::new(0, 0),
        Phase::Altair | Phase::Bellatrix => RpcLimits::new(altair_fixed_len, altair_fixed_len),
        Phase::Capella | Phase::Deneb | Phase::Electra | Phase::Fulu | Phase::Gloas => {
            RpcLimits::new(
                altair_fixed_len,
                altair_fixed_len + P::MaxExtraDataBytes::USIZE * u8::SIZE.get(),
            )
        }
    }
}

fn rpc_execution_payload_envelope_limits() -> RpcLimits {
    RpcLimits::new(
        *SIGNED_EXECUTION_PAYLOAD_ENVELOPE_GLOAS_MIN,
        *SIGNED_EXECUTION_PAYLOAD_ENVELOPE_GLOAS_MAX,
    )
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
    /// The `ExecutionPayloadEnvelopesByRange` protocol name.
    #[strum(serialize = "execution_payload_envelopes_by_range")]
    ExecutionPayloadEnvelopesByRange,
    /// The `ExecutionPayloadEnvelopesByRoot` protocol name.
    #[strum(serialize = "execution_payload_envelopes_by_root")]
    ExecutionPayloadEnvelopesByRoot,
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
    /// The `LightClientUpdatesByRange` protocol name
    #[strum(serialize = "light_client_updates_by_range")]
    LightClientUpdatesByRange,
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
            Protocol::ExecutionPayloadEnvelopesByRange => {
                Some(ResponseTermination::ExecutionPayloadEnvelopesByRange)
            }
            Protocol::ExecutionPayloadEnvelopesByRoot => {
                Some(ResponseTermination::ExecutionPayloadEnvelopesByRoot)
            }
            Protocol::Ping => None,
            Protocol::MetaData => None,
            Protocol::LightClientBootstrap => None,
            Protocol::LightClientOptimisticUpdate => None,
            Protocol::LightClientFinalityUpdate => None,
            Protocol::LightClientUpdatesByRange => todo!(),
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
    StatusV2,
    GoodbyeV1,
    BlocksByRangeV1,
    BlocksByRangeV2,
    BlocksByRootV1,
    BlocksByRootV2,
    BlobsByRangeV1,
    BlobsByRootV1,
    DataColumnsByRootV1,
    DataColumnsByRangeV1,
    ExecutionPayloadEnvelopesByRangeV1,
    ExecutionPayloadEnvelopesByRootV1,
    PingV1,
    MetaDataV1,
    MetaDataV2,
    MetaDataV3,
    LightClientBootstrapV1,
    LightClientOptimisticUpdateV1,
    LightClientFinalityUpdateV1,
    LightClientUpdatesByRangeV1,
}

impl SupportedProtocol {
    pub fn version_string(&self) -> &'static str {
        match self {
            SupportedProtocol::StatusV1 => "1",
            SupportedProtocol::StatusV2 => "2",
            SupportedProtocol::GoodbyeV1 => "1",
            SupportedProtocol::BlocksByRangeV1 => "1",
            SupportedProtocol::BlocksByRangeV2 => "2",
            SupportedProtocol::BlocksByRootV1 => "1",
            SupportedProtocol::BlocksByRootV2 => "2",
            SupportedProtocol::BlobsByRangeV1 => "1",
            SupportedProtocol::BlobsByRootV1 => "1",
            SupportedProtocol::DataColumnsByRootV1 => "1",
            SupportedProtocol::DataColumnsByRangeV1 => "1",
            SupportedProtocol::ExecutionPayloadEnvelopesByRangeV1 => "1",
            SupportedProtocol::ExecutionPayloadEnvelopesByRootV1 => "1",
            SupportedProtocol::PingV1 => "1",
            SupportedProtocol::MetaDataV1 => "1",
            SupportedProtocol::MetaDataV2 => "2",
            SupportedProtocol::MetaDataV3 => "3",
            SupportedProtocol::LightClientBootstrapV1 => "1",
            SupportedProtocol::LightClientOptimisticUpdateV1 => "1",
            SupportedProtocol::LightClientFinalityUpdateV1 => "1",
            SupportedProtocol::LightClientUpdatesByRangeV1 => "1",
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            SupportedProtocol::StatusV1 => Protocol::Status,
            SupportedProtocol::StatusV2 => Protocol::Status,
            SupportedProtocol::GoodbyeV1 => Protocol::Goodbye,
            SupportedProtocol::BlocksByRangeV1 => Protocol::BlocksByRange,
            SupportedProtocol::BlocksByRangeV2 => Protocol::BlocksByRange,
            SupportedProtocol::BlocksByRootV1 => Protocol::BlocksByRoot,
            SupportedProtocol::BlocksByRootV2 => Protocol::BlocksByRoot,
            SupportedProtocol::BlobsByRangeV1 => Protocol::BlobsByRange,
            SupportedProtocol::BlobsByRootV1 => Protocol::BlobsByRoot,
            SupportedProtocol::DataColumnsByRootV1 => Protocol::DataColumnsByRoot,
            SupportedProtocol::DataColumnsByRangeV1 => Protocol::DataColumnsByRange,
            SupportedProtocol::ExecutionPayloadEnvelopesByRangeV1 => {
                Protocol::ExecutionPayloadEnvelopesByRange
            }
            SupportedProtocol::ExecutionPayloadEnvelopesByRootV1 => {
                Protocol::ExecutionPayloadEnvelopesByRoot
            }
            SupportedProtocol::PingV1 => Protocol::Ping,
            SupportedProtocol::MetaDataV1 => Protocol::MetaData,
            SupportedProtocol::MetaDataV2 => Protocol::MetaData,
            SupportedProtocol::MetaDataV3 => Protocol::MetaData,
            SupportedProtocol::LightClientBootstrapV1 => Protocol::LightClientBootstrap,
            SupportedProtocol::LightClientOptimisticUpdateV1 => {
                Protocol::LightClientOptimisticUpdate
            }
            SupportedProtocol::LightClientFinalityUpdateV1 => Protocol::LightClientFinalityUpdate,
            SupportedProtocol::LightClientUpdatesByRangeV1 => Protocol::LightClientUpdatesByRange,
        }
    }

    fn currently_supported(fork_context: &Arc<ForkContext>) -> Vec<ProtocolId> {
        let mut supported = vec![
            ProtocolId::new(Self::StatusV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::StatusV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::GoodbyeV1, Encoding::SSZSnappy),
            // V2 variants have higher preference then V1
            ProtocolId::new(Self::BlocksByRangeV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRangeV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV2, Encoding::SSZSnappy),
            ProtocolId::new(Self::BlocksByRootV1, Encoding::SSZSnappy),
            ProtocolId::new(Self::PingV1, Encoding::SSZSnappy),
        ];
        if fork_context.chain_config().is_peerdas_scheduled() {
            supported.extend_from_slice(&[
                // V3 variants have higher preference for protocol negotation
                ProtocolId::new(Self::MetaDataV3, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV1, Encoding::SSZSnappy),
            ]);
        } else {
            supported.extend_from_slice(&[
                ProtocolId::new(Self::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(Self::MetaDataV1, Encoding::SSZSnappy),
            ]);
        }
        if fork_context.fork_exists(Phase::Deneb) {
            supported.extend_from_slice(&[
                ProtocolId::new(SupportedProtocol::BlobsByRootV1, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlobsByRangeV1, Encoding::SSZSnappy),
            ]);
        }
        if fork_context.chain_config().is_peerdas_scheduled() {
            supported.extend_from_slice(&[
                ProtocolId::new(SupportedProtocol::DataColumnsByRootV1, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::DataColumnsByRangeV1, Encoding::SSZSnappy),
            ]);
        }
        if fork_context.fork_exists(Phase::Gloas) {
            supported.extend_from_slice(&[
                ProtocolId::new(
                    SupportedProtocol::ExecutionPayloadEnvelopesByRangeV1,
                    Encoding::SSZSnappy,
                ),
                ProtocolId::new(
                    SupportedProtocol::ExecutionPayloadEnvelopesByRootV1,
                    Encoding::SSZSnappy,
                ),
            ]);
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
    pub chain_config: Arc<ChainConfig>,
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
    pub enable_light_client_server: bool,
    pub phantom: PhantomData<P>,
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
    pub fn rpc_request_limits<P: Preset>(
        &self,
        chain_config: &ChainConfig,
        phase: Phase,
    ) -> RpcLimits {
        match self.versioned_protocol.protocol() {
            Protocol::Status => {
                RpcLimits::new(StatusMessageV1::SIZE.get(), StatusMessageV2::SIZE.get())
            }
            Protocol::Goodbye => {
                RpcLimits::new(GoodbyeReason::SIZE.get(), GoodbyeReason::SIZE.get())
            }
            // V1 and V2 requests are the same
            Protocol::BlocksByRange => RpcLimits::new(
                OldBlocksByRangeRequestV2::SIZE.get(),
                OldBlocksByRangeRequestV2::SIZE.get(),
            ),
            Protocol::BlocksByRoot => RpcLimits::new(
                0,
                chain_config.max_request_blocks(Phase::Phase0) as usize * H256::SIZE.get(),
            ),
            Protocol::BlobsByRange => RpcLimits::new(
                BlobsByRangeRequest::SIZE.get(),
                BlobsByRangeRequest::SIZE.get(),
            ),
            Protocol::BlobsByRoot => RpcLimits::new(
                0,
                chain_config.max_request_blob_sidecars(phase) as usize * BlobIdentifier::SIZE.get(),
            ),
            Protocol::DataColumnsByRoot => {
                RpcLimits::new(0, chain_config.max_data_columns_by_root_request::<P>())
            }
            Protocol::DataColumnsByRange => RpcLimits::new(
                DataColumnsByRangeRequest::<P>::ssz_min_len().unwrap_or_default(),
                DataColumnsByRangeRequest::<P>::ssz_max_len()
                    .expect("Unable to get DataColumnsByRange ssz_max_len"),
            ),
            Protocol::ExecutionPayloadEnvelopesByRoot => RpcLimits::new(
                0,
                chain_config.max_request_payloads as usize * H256::SIZE.get(),
            ),
            Protocol::ExecutionPayloadEnvelopesByRange => RpcLimits::new(
                ExecutionPayloadEnvelopesByRangeRequest::SIZE.get(),
                ExecutionPayloadEnvelopesByRangeRequest::SIZE.get(),
            ),
            Protocol::Ping => RpcLimits::new(Ping::SIZE.get(), Ping::SIZE.get()),
            Protocol::LightClientBootstrap => RpcLimits::new(
                LightClientBootstrapRequest::SIZE.get(),
                LightClientBootstrapRequest::SIZE.get(),
            ),
            Protocol::LightClientOptimisticUpdate => RpcLimits::new(0, 0),
            Protocol::LightClientFinalityUpdate => RpcLimits::new(0, 0),
            Protocol::LightClientUpdatesByRange => RpcLimits::new(0, 0),
            Protocol::MetaData => RpcLimits::new(0, 0), // Metadata requests are empty
        }
    }

    /// Returns min and max size for messages of given protocol id responses.
    pub fn rpc_response_limits<P: Preset>(&self, fork_context: &ForkContext) -> RpcLimits {
        match self.versioned_protocol.protocol() {
            Protocol::Status => {
                RpcLimits::new(StatusMessageV1::SIZE.get(), StatusMessageV2::SIZE.get())
            }
            Protocol::Goodbye => RpcLimits::new(0, 0), // Goodbye request has no response
            Protocol::BlocksByRange => rpc_block_limits_by_fork(fork_context.current_fork_name()),
            Protocol::BlocksByRoot => rpc_block_limits_by_fork(fork_context.current_fork_name()),
            Protocol::BlobsByRange => rpc_blob_limits::<P>(),
            Protocol::BlobsByRoot => rpc_blob_limits::<P>(),
            Protocol::DataColumnsByRoot => {
                rpc_data_column_limits::<P>(fork_context.current_fork_name())
            }
            Protocol::DataColumnsByRange => {
                rpc_data_column_limits::<P>(fork_context.current_fork_name())
            }
            Protocol::ExecutionPayloadEnvelopesByRange => {
                rpc_execution_payload_envelope_limits()
            }
            Protocol::ExecutionPayloadEnvelopesByRoot => {
                rpc_execution_payload_envelope_limits()
            }
            Protocol::Ping => RpcLimits::new(Ping::SIZE.get(), Ping::SIZE.get()),
            Protocol::MetaData => RpcLimits::new(MetaDataV1::SIZE.get(), MetaDataV3::SIZE.get()),
            Protocol::LightClientBootstrap => {
                rpc_light_client_bootstrap_limits_by_fork::<P>(fork_context.current_fork_name())
            }
            Protocol::LightClientOptimisticUpdate => {
                rpc_light_client_optimistic_update_limits_by_fork::<P>(
                    fork_context.current_fork_name(),
                )
            }
            Protocol::LightClientFinalityUpdate => {
                rpc_light_client_finality_update_limits_by_fork::<P>(
                    fork_context.current_fork_name(),
                )
            }
            Protocol::LightClientUpdatesByRange => {
                rpc_light_client_updates_by_range_limits_by_fork::<P>(
                    fork_context.current_fork_name(),
                )
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
            | SupportedProtocol::ExecutionPayloadEnvelopesByRangeV1
            | SupportedProtocol::ExecutionPayloadEnvelopesByRootV1
            | SupportedProtocol::LightClientBootstrapV1
            | SupportedProtocol::LightClientOptimisticUpdateV1
            | SupportedProtocol::LightClientFinalityUpdateV1
            | SupportedProtocol::LightClientUpdatesByRangeV1 => true,
            SupportedProtocol::StatusV1
            | SupportedProtocol::StatusV2
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

// The inbound protocol reads the request, decodes it and returns the stream to the protocol
// handler to respond to once ready.

pub type InboundOutput<TSocket, P> = (RequestType<P>, InboundFramed<TSocket, P>);
pub type InboundFramed<TSocket, P> =
    Framed<std::pin::Pin<Box<Compat<TSocket>>>, SSZSnappyInboundCodec<P>>;

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
                Encoding::SSZSnappy => SSZSnappyInboundCodec::new(
                    self.chain_config.clone_arc(),
                    protocol,
                    self.max_rpc_size,
                    self.fork_context.clone(),
                ),
            };

            let socket = Framed::new(Box::pin(socket), codec);

            // MetaData requests should be empty, return the stream
            match versioned_protocol {
                SupportedProtocol::MetaDataV1 => {
                    Ok((RequestType::MetaData(MetadataRequest::new_v1()), socket))
                }
                SupportedProtocol::MetaDataV2 => {
                    Ok((RequestType::MetaData(MetadataRequest::new_v2()), socket))
                }
                SupportedProtocol::MetaDataV3 => {
                    Ok((RequestType::MetaData(MetadataRequest::new_v3()), socket))
                }
                SupportedProtocol::LightClientOptimisticUpdateV1 => {
                    Ok((RequestType::LightClientOptimisticUpdate, socket))
                }
                SupportedProtocol::LightClientFinalityUpdateV1 => {
                    Ok((RequestType::LightClientFinalityUpdate, socket))
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
pub enum RequestType<P: Preset> {
    Status(StatusMessage),
    Goodbye(GoodbyeReason),
    BlocksByRange(OldBlocksByRangeRequest),
    BlocksByRoot(BlocksByRootRequest),
    BlobsByRange(BlobsByRangeRequest),
    BlobsByRoot(BlobsByRootRequest),
    DataColumnsByRoot(DataColumnsByRootRequest<P>),
    DataColumnsByRange(DataColumnsByRangeRequest<P>),
    ExecutionPayloadEnvelopesByRange(ExecutionPayloadEnvelopesByRangeRequest),
    ExecutionPayloadEnvelopesByRoot(ExecutionPayloadEnvelopesByRootRequest),
    LightClientBootstrap(LightClientBootstrapRequest),
    LightClientOptimisticUpdate,
    LightClientFinalityUpdate,
    LightClientUpdatesByRange(LightClientUpdatesByRangeRequest),
    Ping(Ping),
    MetaData(MetadataRequest<P>),
}

/// Implements the encoding per supported protocol for `RPCRequest`.
impl<P: Preset> RequestType<P> {
    /* These functions are used in the handler for stream management */

    /// Maximum number of responses expected for this request.
    pub fn max_responses(&self, chain_config: &ChainConfig, _epoch: Epoch) -> u64 {
        match self {
            RequestType::Status(_) => 1,
            RequestType::Goodbye(_) => 0,
            RequestType::BlocksByRange(req) => req.count(),
            RequestType::BlocksByRoot(req) => req.len() as u64,
            RequestType::BlobsByRange(req) => {
                let epoch = misc::compute_epoch_at_slot::<P>(req.start_slot);
                req.max_blobs_requested(chain_config, epoch)
            }
            RequestType::BlobsByRoot(req) => req.blob_ids.len() as u64,
            RequestType::DataColumnsByRoot(req) => req.max_requested() as u64,
            RequestType::DataColumnsByRange(req) => req.max_requested(),
            RequestType::ExecutionPayloadEnvelopesByRange(req) => req.max_requested(),
            RequestType::ExecutionPayloadEnvelopesByRoot(req) => req.max_requested() as u64,
            RequestType::Ping(_) => 1,
            RequestType::MetaData(_) => 1,
            RequestType::LightClientBootstrap(_) => 1,
            RequestType::LightClientOptimisticUpdate => 1,
            RequestType::LightClientFinalityUpdate => 1,
            RequestType::LightClientUpdatesByRange(req) => req.count,
        }
    }

    /// Gives the corresponding `SupportedProtocol` to this request.
    pub fn versioned_protocol(&self) -> SupportedProtocol {
        match self {
            RequestType::Status(req) => match req {
                StatusMessage::V1(_) => SupportedProtocol::StatusV1,
                StatusMessage::V2(_) => SupportedProtocol::StatusV2,
            },
            RequestType::Goodbye(_) => SupportedProtocol::GoodbyeV1,
            RequestType::BlocksByRange(req) => match req {
                OldBlocksByRangeRequest::V1(_) => SupportedProtocol::BlocksByRangeV1,
                OldBlocksByRangeRequest::V2(_) => SupportedProtocol::BlocksByRangeV2,
            },
            RequestType::BlocksByRoot(req) => match req {
                BlocksByRootRequest::V1(_) => SupportedProtocol::BlocksByRootV1,
                BlocksByRootRequest::V2(_) => SupportedProtocol::BlocksByRootV2,
            },
            RequestType::BlobsByRange(_) => SupportedProtocol::BlobsByRangeV1,
            RequestType::BlobsByRoot(_) => SupportedProtocol::BlobsByRootV1,
            RequestType::DataColumnsByRoot(_) => SupportedProtocol::DataColumnsByRootV1,
            RequestType::DataColumnsByRange(_) => SupportedProtocol::DataColumnsByRangeV1,
            RequestType::ExecutionPayloadEnvelopesByRange(_) => {
                SupportedProtocol::ExecutionPayloadEnvelopesByRangeV1
            }
            RequestType::ExecutionPayloadEnvelopesByRoot(_) => {
                SupportedProtocol::ExecutionPayloadEnvelopesByRootV1
            }
            RequestType::Ping(_) => SupportedProtocol::PingV1,
            RequestType::MetaData(req) => match req {
                MetadataRequest::V1(_) => SupportedProtocol::MetaDataV1,
                MetadataRequest::V2(_) => SupportedProtocol::MetaDataV2,
                MetadataRequest::V3(_) => SupportedProtocol::MetaDataV3,
            },
            RequestType::LightClientBootstrap(_) => SupportedProtocol::LightClientBootstrapV1,
            RequestType::LightClientOptimisticUpdate => {
                SupportedProtocol::LightClientOptimisticUpdateV1
            }
            RequestType::LightClientFinalityUpdate => {
                SupportedProtocol::LightClientFinalityUpdateV1
            }
            RequestType::LightClientUpdatesByRange(_) => {
                SupportedProtocol::LightClientUpdatesByRangeV1
            }
        }
    }

    /// Returns the `ResponseTermination` type associated with the request if a stream gets
    /// terminated.
    pub fn stream_termination(&self) -> ResponseTermination {
        match self {
            // this only gets called after `multiple_responses()` returns true. Therefore, only
            // variants that have `multiple_responses()` can have values.
            RequestType::BlocksByRange(_) => ResponseTermination::BlocksByRange,
            RequestType::BlocksByRoot(_) => ResponseTermination::BlocksByRoot,
            RequestType::BlobsByRange(_) => ResponseTermination::BlobsByRange,
            RequestType::BlobsByRoot(_) => ResponseTermination::BlobsByRoot,
            RequestType::DataColumnsByRoot(_) => ResponseTermination::DataColumnsByRoot,
            RequestType::DataColumnsByRange(_) => ResponseTermination::DataColumnsByRange,
            RequestType::ExecutionPayloadEnvelopesByRange(_) => {
                ResponseTermination::ExecutionPayloadEnvelopesByRange
            }
            RequestType::ExecutionPayloadEnvelopesByRoot(_) => {
                ResponseTermination::ExecutionPayloadEnvelopesByRoot
            }
            RequestType::Status(_) => unreachable!(),
            RequestType::Goodbye(_) => unreachable!(),
            RequestType::Ping(_) => unreachable!(),
            RequestType::MetaData(_) => unreachable!(),
            RequestType::LightClientBootstrap(_) => unreachable!(),
            RequestType::LightClientFinalityUpdate => unreachable!(),
            RequestType::LightClientOptimisticUpdate => unreachable!(),
            RequestType::LightClientUpdatesByRange(_) => unreachable!(),
        }
    }

    pub fn supported_protocols(&self) -> Vec<ProtocolId> {
        match self {
            // add more protocols when versions/encodings are supported
            RequestType::Status(_) => vec![
                ProtocolId::new(SupportedProtocol::StatusV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::StatusV1, Encoding::SSZSnappy),
            ],
            RequestType::Goodbye(_) => vec![ProtocolId::new(
                SupportedProtocol::GoodbyeV1,
                Encoding::SSZSnappy,
            )],
            RequestType::BlocksByRange(_) => vec![
                ProtocolId::new(SupportedProtocol::BlocksByRangeV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlocksByRangeV1, Encoding::SSZSnappy),
            ],
            RequestType::BlocksByRoot(_) => vec![
                ProtocolId::new(SupportedProtocol::BlocksByRootV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::BlocksByRootV1, Encoding::SSZSnappy),
            ],
            RequestType::BlobsByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::BlobsByRangeV1,
                Encoding::SSZSnappy,
            )],
            RequestType::BlobsByRoot(_) => vec![ProtocolId::new(
                SupportedProtocol::BlobsByRootV1,
                Encoding::SSZSnappy,
            )],
            RequestType::DataColumnsByRoot(_) => vec![ProtocolId::new(
                SupportedProtocol::DataColumnsByRootV1,
                Encoding::SSZSnappy,
            )],
            RequestType::DataColumnsByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::DataColumnsByRangeV1,
                Encoding::SSZSnappy,
            )],
            RequestType::ExecutionPayloadEnvelopesByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::ExecutionPayloadEnvelopesByRangeV1,
                Encoding::SSZSnappy,
            )],
            RequestType::ExecutionPayloadEnvelopesByRoot(_) => vec![ProtocolId::new(
                SupportedProtocol::ExecutionPayloadEnvelopesByRootV1,
                Encoding::SSZSnappy,
            )],
            RequestType::Ping(_) => vec![ProtocolId::new(
                SupportedProtocol::PingV1,
                Encoding::SSZSnappy,
            )],
            RequestType::MetaData(_) => vec![
                ProtocolId::new(SupportedProtocol::MetaDataV3, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::MetaDataV2, Encoding::SSZSnappy),
                ProtocolId::new(SupportedProtocol::MetaDataV1, Encoding::SSZSnappy),
            ],
            RequestType::LightClientBootstrap(_) => vec![ProtocolId::new(
                SupportedProtocol::LightClientBootstrapV1,
                Encoding::SSZSnappy,
            )],
            RequestType::LightClientOptimisticUpdate => vec![ProtocolId::new(
                SupportedProtocol::LightClientOptimisticUpdateV1,
                Encoding::SSZSnappy,
            )],
            RequestType::LightClientFinalityUpdate => vec![ProtocolId::new(
                SupportedProtocol::LightClientFinalityUpdateV1,
                Encoding::SSZSnappy,
            )],
            RequestType::LightClientUpdatesByRange(_) => vec![ProtocolId::new(
                SupportedProtocol::LightClientUpdatesByRangeV1,
                Encoding::SSZSnappy,
            )],
        }
    }

    pub fn expect_exactly_one_response(&self) -> bool {
        match self {
            RequestType::Status(_) => true,
            RequestType::Goodbye(_) => false,
            RequestType::BlocksByRange(_) => false,
            RequestType::BlocksByRoot(_) => false,
            RequestType::BlobsByRange(_) => false,
            RequestType::BlobsByRoot(_) => false,
            RequestType::DataColumnsByRoot(_) => false,
            RequestType::DataColumnsByRange(_) => false,
            RequestType::Ping(_) => true,
            RequestType::MetaData(_) => true,
            RequestType::LightClientBootstrap(_) => true,
            RequestType::LightClientOptimisticUpdate => true,
            RequestType::LightClientFinalityUpdate => true,
            RequestType::LightClientUpdatesByRange(_) => true,
            RequestType::ExecutionPayloadEnvelopesByRange(_) => false,
            RequestType::ExecutionPayloadEnvelopesByRoot(_) => false,
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
    ErrorResponse(RpcErrorResponse, String),
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
    match <P as Preset>::NAME {
        PresetName::Minimal => RpcLimits::new(BLOB_SIDECAR_MINIMAL_MIN, BLOB_SIDECAR_MINIMAL_MAX),
        PresetName::Mainnet | PresetName::Medalla => {
            RpcLimits::new(BLOB_SIDECAR_MIN, BLOB_SIDECAR_MAX)
        }
    }
}

pub fn rpc_data_column_limits<P: Preset>(phase: Phase) -> RpcLimits {
    if phase >= Phase::Gloas {
        RpcLimits::new(*DATA_COLUMN_GLOAS_MIN, *DATA_COLUMN_GLOAS_MAX)
    } else {
        RpcLimits::new(*DATA_COLUMN_FULU_MIN, *DATA_COLUMN_FULU_MAX)
    }
}

impl<P: Preset> std::fmt::Display for RequestType<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestType::Status(status) => write!(f, "Status Message: {}", status),
            RequestType::Goodbye(reason) => write!(f, "Goodbye: {}", reason),
            RequestType::BlocksByRange(req) => write!(f, "Blocks by range: {}", req),
            RequestType::BlocksByRoot(req) => write!(f, "Blocks by root: {:?}", req),
            RequestType::BlobsByRange(req) => write!(f, "Blobs by range: {:?}", req),
            RequestType::BlobsByRoot(req) => write!(f, "Blobs by root: {:?}", req),
            RequestType::DataColumnsByRoot(req) => write!(f, "Data columns by root: {:?}", req),
            RequestType::DataColumnsByRange(req) => {
                write!(f, "Data columns by range: {:?}", req)
            }
            RequestType::Ping(ping) => write!(f, "Ping: {}", ping.data),
            RequestType::MetaData(_) => write!(f, "MetaData request"),
            RequestType::LightClientBootstrap(bootstrap) => {
                write!(f, "Light client boostrap: {}", bootstrap.root)
            }
            RequestType::LightClientOptimisticUpdate => {
                write!(f, "Light client optimistic update request")
            }
            RequestType::LightClientFinalityUpdate => {
                write!(f, "Light client finality update request")
            }
            RequestType::LightClientUpdatesByRange(_) => {
                write!(f, "Light client updates by range request")
            }
            RequestType::ExecutionPayloadEnvelopesByRange(req) => {
                write!(f, "Execution payload envelopes by range: {:?}", req)
            }
            RequestType::ExecutionPayloadEnvelopesByRoot(req) => {
                write!(f, "Execution payload envelopes by root: {:?}", req)
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
    use ssz::{ContiguousList, DynamicList, SszWrite as _};
    use types::{
        deneb::containers::BlobSidecar,
        phase0::{containers::SignedBeaconBlock as Phase0SignedBeaconBlock, primitives::H256},
        preset::Mainnet,
    };

    use crate::{factory, rpc::methods::MaxErrorLen};

    use super::*;

    #[test]
    fn length_constants_are_calculated_from_ssz_encodings() {
        let config = ChainConfig::mainnet();

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
        assert_eq!(
            SIGNED_BEACON_BLOCK_ALTAIR_MAX,
            factory::full_altair_signed_beacon_block::<Mainnet>(&config)
                .to_ssz()
                .unwrap()
                .len(),
        );
        assert_eq!(0, DynamicList::<H256>::empty().to_ssz().unwrap().len());
        assert_eq!(
            // Previously defined as constant
            32_768,
            DynamicList::<H256>::full(
                H256::zero(),
                config.max_request_blocks(Phase::Phase0) as usize
            )
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
        assert_eq!(BLOB_SIDECAR_MIN, BlobSidecar::<Mainnet>::SIZE.get());
        assert_eq!(BLOB_SIDECAR_MAX, BlobSidecar::<Mainnet>::SIZE.get());
    }
}
