//! Available RPC methods types and ids.
use std::fmt::Display;

use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use anyhow::Result;
use regex::bytes::Regex;
use serde::Serialize;
use ssz::{
    ContiguousList, DynamicList, ReadError, Size, Ssz, SszRead, SszSize, SszWrite, WriteError,
};
use std::marker::PhantomData;
use std::{ops::Deref, sync::Arc};
use strum::IntoStaticStr;
use try_from_iterator::TryFromIterator as _;
use typenum::{Unsigned as _, U256};
use types::deneb::containers::BlobIdentifier;
use types::nonstandard::Phase;
use types::{
    combined::{
        DataColumnSidecar, LightClientBootstrap, LightClientFinalityUpdate,
        LightClientOptimisticUpdate, LightClientUpdate, SignedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::containers::BlobSidecar,
    fulu::{containers::DataColumnsByRootIdentifier, primitives::ColumnIndex},
    phase0::primitives::{Epoch, ForkDigest, Slot, H256},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

/// Maximum length of error message.
pub type MaxErrorLen = U256;

/// Wrapper over SSZ List to represent error message in rpc responses.
#[derive(Debug, Clone)]
pub struct ErrorType(pub ContiguousList<u8, MaxErrorLen>);

impl From<String> for ErrorType {
    fn from(string: String) -> Self {
        Self(ContiguousList::try_from_iter(string.bytes().take(MaxErrorLen::USIZE)).unwrap())
    }
}

impl From<&str> for ErrorType {
    fn from(string: &str) -> Self {
        Self(ContiguousList::try_from_iter(string.bytes().take(MaxErrorLen::USIZE)).unwrap())
    }
}

impl Deref for ErrorType {
    type Target = ContiguousList<u8, MaxErrorLen>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::invalid_regex)]
        let re = Regex::new("\\p{C}").expect("Regex is valid");
        let error_type_str =
            String::from_utf8_lossy(&re.replace_all(self.0.deref(), &b""[..])).to_string();
        write!(f, "{}", error_type_str)
    }
}

/* Request/Response data structures for RPC methods */

/* Requests */

/// The STATUS request/response handshake message.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StatusMessage {
    V1(StatusMessageV1),
    V2(StatusMessageV2),
}

impl StatusMessage {
    pub fn fork_digest(self) -> ForkDigest {
        match self {
            Self::V1(status_message) => status_message.fork_digest,
            Self::V2(status_message) => status_message.fork_digest,
        }
    }

    pub fn finalized_root(self) -> H256 {
        match self {
            Self::V1(status_message) => status_message.finalized_root,
            Self::V2(status_message) => status_message.finalized_root,
        }
    }

    pub fn finalized_epoch(self) -> Epoch {
        match self {
            Self::V1(status_message) => status_message.finalized_epoch,
            Self::V2(status_message) => status_message.finalized_epoch,
        }
    }

    pub fn head_root(self) -> H256 {
        match self {
            Self::V1(status_message) => status_message.head_root,
            Self::V2(status_message) => status_message.head_root,
        }
    }

    pub fn head_slot(self) -> Slot {
        match self {
            Self::V1(status_message) => status_message.head_slot,
            Self::V2(status_message) => status_message.head_slot,
        }
    }

    pub fn earliest_available_slot(self) -> Option<Slot> {
        match self {
            Self::V1(_) => None,
            Self::V2(status_message) => Some(status_message.earliest_available_slot),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Ssz)]
#[ssz(derive_hash = false)]
pub struct StatusMessageV1 {
    /// The fork version of the chain we are broadcasting.
    pub fork_digest: ForkDigest,

    /// Latest finalized root.
    pub finalized_root: H256,

    /// Latest finalized epoch.
    pub finalized_epoch: Epoch,

    /// The latest block root.
    pub head_root: H256,

    /// The slot associated with the latest block root.
    pub head_slot: Slot,
}

#[derive(Copy, Clone, Debug, PartialEq, Ssz)]
#[ssz(derive_hash = false)]
pub struct StatusMessageV2 {
    /// The fork version of the chain we are broadcasting.
    pub fork_digest: ForkDigest,

    /// Latest finalized root.
    pub finalized_root: H256,

    /// Latest finalized epoch.
    pub finalized_epoch: Epoch,

    /// The latest block root.
    pub head_root: H256,

    /// The slot associated with the latest block root.
    pub head_slot: Slot,

    /// The slot after which we guarantee to have all the blocks
    /// and blobs/data columns that we currently advertise.
    pub earliest_available_slot: Slot,
}

impl StatusMessage {
    pub fn status_v1(&self) -> StatusMessageV1 {
        match &self {
            Self::V1(status) => status.clone(),
            Self::V2(status) => StatusMessageV1 {
                fork_digest: status.fork_digest,
                finalized_root: status.finalized_root,
                finalized_epoch: status.finalized_epoch,
                head_root: status.head_root,
                head_slot: status.head_slot,
            },
        }
    }

    pub fn status_v2(&self) -> StatusMessageV2 {
        match &self {
            Self::V1(status) => StatusMessageV2 {
                fork_digest: status.fork_digest,
                finalized_root: status.finalized_root,
                finalized_epoch: status.finalized_epoch,
                head_root: status.head_root,
                head_slot: status.head_slot,
                // Note: we always produce a V2 message as our local
                // status message, so this match arm should ideally never
                // be invoked in lighthouse.
                earliest_available_slot: 0,
            },
            Self::V2(status) => *status,
        }
    }
}

/// The PING request/response message.
#[derive(Copy, Clone, Debug, PartialEq, Ssz)]
#[ssz(derive_hash = false, transparent)]
pub struct Ping {
    /// The metadata sequence number.
    pub data: u64,
}

/// The METADATA request structure.
#[derive(Clone, Debug, PartialEq)]
pub enum MetadataRequest<P: Preset> {
    V1(MetadataRequestV1<P>),
    V2(MetadataRequestV2<P>),
    V3(MetadataRequestV3<P>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataRequestV1<P: Preset> {
    _phantom_data: PhantomData<P>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataRequestV2<P: Preset> {
    _phantom_data: PhantomData<P>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataRequestV3<P: Preset> {
    _phantom_data: PhantomData<P>,
}

impl<P: Preset> MetadataRequest<P> {
    pub fn new_v1() -> Self {
        Self::V1(MetadataRequestV1 {
            _phantom_data: PhantomData,
        })
    }

    pub fn new_v2() -> Self {
        Self::V2(MetadataRequestV2 {
            _phantom_data: PhantomData,
        })
    }

    pub fn new_v3() -> Self {
        Self::V3(MetadataRequestV3 {
            _phantom_data: PhantomData,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
pub enum MetaData {
    V1(MetaDataV1),
    V2(MetaDataV2),
    V3(MetaDataV3),
}

impl MetaData {
    pub fn seq_number(self) -> u64 {
        match self {
            Self::V1(meta_data) => meta_data.seq_number,
            Self::V2(meta_data) => meta_data.seq_number,
            Self::V3(meta_data) => meta_data.seq_number,
        }
    }

    pub fn attnets(self) -> EnrAttestationBitfield {
        match self {
            Self::V1(meta_data) => meta_data.attnets,
            Self::V2(meta_data) => meta_data.attnets,
            Self::V3(meta_data) => meta_data.attnets,
        }
    }

    pub fn syncnets(self) -> Option<EnrSyncCommitteeBitfield> {
        match self {
            Self::V1(_) => None,
            Self::V2(meta_data) => Some(meta_data.syncnets),
            Self::V3(meta_data) => Some(meta_data.syncnets),
        }
    }

    pub fn seq_number_mut(&mut self) -> &mut u64 {
        match self {
            Self::V1(meta_data) => &mut meta_data.seq_number,
            Self::V2(meta_data) => &mut meta_data.seq_number,
            Self::V3(meta_data) => &mut meta_data.seq_number,
        }
    }

    pub fn attnets_mut(&mut self) -> &mut EnrAttestationBitfield {
        match self {
            Self::V1(meta_data) => &mut meta_data.attnets,
            Self::V2(meta_data) => &mut meta_data.attnets,
            Self::V3(meta_data) => &mut meta_data.attnets,
        }
    }

    pub fn syncnets_mut(&mut self) -> Option<&mut EnrSyncCommitteeBitfield> {
        match self {
            Self::V1(_) => None,
            Self::V2(meta_data) => Some(&mut meta_data.syncnets),
            Self::V3(meta_data) => Some(&mut meta_data.syncnets),
        }
    }

    pub fn custody_group_count(&self) -> Option<u64> {
        match self {
            Self::V1(_) | Self::V2(_) => None,
            Self::V3(meta_data) => Some(meta_data.custody_group_count),
        }
    }

    pub fn custody_group_count_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::V1(_) | Self::V2(_) => None,
            Self::V3(meta_data) => Some(&mut meta_data.custody_group_count),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
#[ssz(derive_hash = false)]
pub struct MetaDataV1 {
    /// A sequential counter indicating when data gets modified.
    pub seq_number: u64,
    /// The persistent attestation subnet bitfield.
    pub attnets: EnrAttestationBitfield,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
#[ssz(derive_hash = false)]
pub struct MetaDataV2 {
    /// A sequential counter indicating when data gets modified.
    pub seq_number: u64,
    /// The persistent attestation subnet bitfield.
    pub attnets: EnrAttestationBitfield,
    /// The persistent sync committee bitfield.
    pub syncnets: EnrSyncCommitteeBitfield,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
#[ssz(derive_hash = false)]
pub struct MetaDataV3 {
    /// A sequential counter indicating when data gets modified.
    pub seq_number: u64,
    /// The persistent attestation subnet bitfield.
    pub attnets: EnrAttestationBitfield,
    /// The persistent sync committee bitfield.
    pub syncnets: EnrSyncCommitteeBitfield,
    /// The node's custody group count.
    pub custody_group_count: u64,
}

impl MetaData {
    /// Returns a V1 MetaData response from self.
    pub fn metadata_v1(&self) -> Self {
        match self {
            md @ MetaData::V1(_) => md.clone(),
            MetaData::V2(metadata) => MetaData::V1(MetaDataV1 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
            }),
            MetaData::V3(metadata) => MetaData::V1(MetaDataV1 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
            }),
        }
    }

    /// Returns a V2 MetaData response from self by filling unavailable fields with default.
    pub fn metadata_v2(&self) -> Self {
        match self {
            MetaData::V1(metadata) => MetaData::V2(MetaDataV2 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: Default::default(),
            }),
            md @ MetaData::V2(_) => md.clone(),
            MetaData::V3(metadata) => MetaData::V2(MetaDataV2 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: metadata.syncnets.clone(),
            }),
        }
    }

    /// Returns a V3 MetaData response from self by filling unavailable fields with default.
    pub fn metadata_v3(&self, chain_config: &ChainConfig) -> Self {
        match self {
            MetaData::V1(metadata) => MetaData::V3(MetaDataV3 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: Default::default(),
                custody_group_count: chain_config.custody_requirement,
            }),
            MetaData::V2(metadata) => MetaData::V3(MetaDataV3 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: metadata.syncnets.clone(),
                custody_group_count: chain_config.custody_requirement,
            }),
            md @ MetaData::V3(_) => md.clone(),
        }
    }

    pub fn to_ssz(&self) -> Result<Vec<u8>, WriteError> {
        match self {
            MetaData::V1(md) => md.to_ssz(),
            MetaData::V2(md) => md.to_ssz(),
            MetaData::V3(md) => md.to_ssz(),
        }
    }
}

/// The reason given for a `Goodbye` message.
///
/// Note: any unknown `u64::into(n)` will resolve to `Goodbye::Unknown` for any unknown `n`,
/// however `GoodbyeReason::Unknown.into()` will go into `0_u64`. Therefore de-serializing then
/// re-serializing may not return the same bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoodbyeReason {
    /// This node has shutdown.
    ClientShutdown = 1,

    /// Incompatible networks.
    IrrelevantNetwork = 2,

    /// Error/fault in the RPC.
    Fault = 3,

    /// Teku uses this code for not being able to verify a network.
    UnableToVerifyNetwork = 128,

    /// The node has too many connected peers.
    TooManyPeers = 129,

    /// Scored poorly.
    BadScore = 250,

    /// The peer is banned
    Banned = 251,

    /// The IP address the peer is using is banned.
    BannedIP = 252,

    /// Unknown reason.
    Unknown = 0,
}

impl SszSize for GoodbyeReason {
    const SIZE: Size = u64::SIZE;
}

impl<C> SszRead<C> for GoodbyeReason {
    #[inline]
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        u64::from_ssz_unchecked(context, bytes).map(Into::into)
    }
}

impl SszWrite for GoodbyeReason {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        (*self as u64).write_fixed(bytes);
    }
}

/// Request a number of beacon blobs from a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ssz)]
pub struct BlobsByRangeRequest {
    /// The starting slot to request blobs.
    pub start_slot: u64,

    /// The number of slots from the start slot.
    pub count: u64,
}

impl BlobsByRangeRequest {
    pub fn max_blobs_requested(&self, config: &ChainConfig, epoch: Epoch) -> u64 {
        self.count.saturating_mul(config.max_blobs_per_block(epoch))
    }
}

impl From<u64> for GoodbyeReason {
    fn from(id: u64) -> GoodbyeReason {
        match id {
            1 => GoodbyeReason::ClientShutdown,
            2 => GoodbyeReason::IrrelevantNetwork,
            3 => GoodbyeReason::Fault,
            128 => GoodbyeReason::UnableToVerifyNetwork,
            129 => GoodbyeReason::TooManyPeers,
            250 => GoodbyeReason::BadScore,
            251 => GoodbyeReason::Banned,
            252 => GoodbyeReason::BannedIP,
            _ => GoodbyeReason::Unknown,
        }
    }
}

impl From<GoodbyeReason> for u64 {
    fn from(reason: GoodbyeReason) -> u64 {
        reason as u64
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlocksByRangeRequest {
    V1(BlocksByRangeRequestV1),
    V2(BlocksByRangeRequestV2),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlocksByRangeRequestV1 {
    /// The starting slot to request blocks.
    pub start_slot: u64,

    /// The number of blocks from the start slot.
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlocksByRangeRequestV2 {
    /// The starting slot to request blocks.
    pub start_slot: u64,

    /// The number of blocks from the start slot.
    pub count: u64,
}

impl BlocksByRangeRequest {
    /// The default request is V2
    pub fn new(start_slot: u64, count: u64) -> Self {
        Self::V2(BlocksByRangeRequestV2 { start_slot, count })
    }

    pub fn new_v1(start_slot: u64, count: u64) -> Self {
        Self::V1(BlocksByRangeRequestV1 { start_slot, count })
    }

    pub fn start_slot(&self) -> u64 {
        match self {
            Self::V1(req) => req.start_slot,
            Self::V2(req) => req.start_slot,
        }
    }

    pub fn count(&self) -> u64 {
        match self {
            Self::V1(req) => req.count,
            Self::V2(req) => req.count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz)]
/// Request a number of beacon data columns from a peer.
pub struct DataColumnsByRangeRequest<P: Preset> {
    /// The starting slot to request data columns.
    pub start_slot: u64,
    /// The number of slots from the start slot.
    pub count: u64,
    /// The list column indices being requested.
    pub columns: Arc<ContiguousList<ColumnIndex, P::NumberOfColumns>>,
}

impl<P: Preset> DataColumnsByRangeRequest<P> {
    pub fn max_requested(&self) -> u64 {
        self.count.saturating_mul(self.columns.len() as u64)
    }

    pub fn ssz_min_len() -> Result<usize> {
        Ok(DataColumnsByRangeRequest::<P> {
            start_slot: 0,
            count: 0,
            columns: Arc::new(ContiguousList::try_from(vec![0])?),
        }
        .to_ssz()?
        .len())
    }

    pub fn ssz_max_len() -> Result<usize> {
        Ok(DataColumnsByRangeRequest::<P> {
            start_slot: 0,
            count: 0,
            columns: Arc::new(ContiguousList::full(0)),
        }
        .to_ssz()?
        .len())
    }
}

/// Request a number of beacon block roots from a peer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OldBlocksByRangeRequest {
    V1(OldBlocksByRangeRequestV1),
    V2(OldBlocksByRangeRequestV2),
}

/// Request a number of beacon block roots from a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ssz)]
pub struct OldBlocksByRangeRequestV1 {
    /// The starting slot to request blocks.
    pub start_slot: u64,

    /// The number of blocks from the start slot.
    pub count: u64,

    /// The step increment to receive blocks.
    ///
    /// A value of 1 returns every block.
    /// A value of 2 returns every second block.
    /// A value of 3 returns every third block and so on.
    pub step: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ssz)]
pub struct OldBlocksByRangeRequestV2 {
    /// The starting slot to request blocks.
    pub start_slot: u64,

    /// The number of blocks from the start slot.
    pub count: u64,

    /// The step increment to receive blocks.
    ///
    /// A value of 1 returns every block.
    /// A value of 2 returns every second block.
    /// A value of 3 returns every third block and so on.
    pub step: u64,
}

impl OldBlocksByRangeRequest {
    /// The default request is V2
    pub fn new(start_slot: u64, count: u64, step: u64) -> Self {
        Self::V2(OldBlocksByRangeRequestV2 {
            start_slot,
            count,
            step,
        })
    }

    pub fn new_v1(start_slot: u64, count: u64, step: u64) -> Self {
        Self::V1(OldBlocksByRangeRequestV1 {
            start_slot,
            count,
            step,
        })
    }

    pub fn start_slot(&self) -> u64 {
        match self {
            Self::V1(req) => req.start_slot,
            Self::V2(req) => req.start_slot,
        }
    }

    pub fn count(&self) -> u64 {
        match self {
            Self::V1(req) => req.count,
            Self::V2(req) => req.count,
        }
    }

    pub fn step(&self) -> u64 {
        match self {
            Self::V1(req) => req.step,
            Self::V2(req) => req.step,
        }
    }

    pub fn max_request_blocks(&self, config: &ChainConfig) -> u64 {
        match self {
            Self::V1(_) => config.max_request_blocks,
            Self::V2(_) => config.max_request_blocks_deneb,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BlocksByRootRequest {
    V1(BlocksByRootRequestV1),
    V2(BlocksByRootRequestV2),
}

/// Request a number of beacon block bodies from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocksByRootRequestV1 {
    /// The list of beacon block bodies being requested.
    pub block_roots: DynamicList<H256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocksByRootRequestV2 {
    /// The list of beacon block bodies being requested.
    pub block_roots: DynamicList<H256>,
}

impl BlocksByRootRequest {
    pub fn new(
        config: &ChainConfig,
        phase: Phase,
        block_roots: impl Iterator<Item = H256>,
    ) -> Self {
        let block_roots = DynamicList::from_iter_with_maximum(
            block_roots,
            config.max_request_blocks(phase) as usize,
        );

        Self::V2(BlocksByRootRequestV2 { block_roots })
    }

    pub fn new_v1(
        config: &ChainConfig,
        phase: Phase,
        block_roots: impl Iterator<Item = H256>,
    ) -> Self {
        let block_roots = DynamicList::from_iter_with_maximum(
            block_roots,
            config.max_request_blocks(phase) as usize,
        );

        Self::V1(BlocksByRootRequestV1 { block_roots })
    }

    pub fn len(&self) -> usize {
        match self {
            Self::V1(req) => req.block_roots.len(),
            Self::V2(req) => req.block_roots.len(),
        }
    }

    pub fn block_roots(self) -> DynamicList<H256> {
        match self {
            Self::V1(req) => req.block_roots,
            Self::V2(req) => req.block_roots,
        }
    }

    pub fn max_request_blocks(&self, config: &ChainConfig) -> u64 {
        match self {
            Self::V1(_) => config.max_request_blocks,
            Self::V2(_) => config.max_request_blocks_deneb,
        }
    }
}

/// Request a number of beacon blocks and blobs from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobsByRootRequest {
    /// The list of beacon block roots being requested.
    pub blob_ids: DynamicList<BlobIdentifier>,
}

impl BlobsByRootRequest {
    pub fn new(
        config: &ChainConfig,
        phase: Phase,
        blob_identifiers: impl Iterator<Item = BlobIdentifier>,
    ) -> Self {
        let blob_ids = DynamicList::from_iter_with_maximum(
            blob_identifiers,
            config.max_request_blob_sidecars(phase) as usize,
        );

        Self { blob_ids }
    }
}

/// Request a number of data columns from a peer.
#[derive(Clone, Debug, PartialEq)]
pub struct DataColumnsByRootRequest<P: Preset> {
    /// The list of beacon block roots and column indices being requested.
    pub data_column_ids: DynamicList<DataColumnsByRootIdentifier<P>>,
}

impl<P: Preset> DataColumnsByRootRequest<P> {
    pub fn new(
        config: &ChainConfig,
        data_column_identifiers: impl Iterator<Item = DataColumnsByRootIdentifier<P>>,
    ) -> Self {
        let data_column_ids = DynamicList::from_iter_with_maximum(
            data_column_identifiers,
            config.max_request_blocks_deneb as usize,
        );

        Self { data_column_ids }
    }

    pub fn max_requested(&self) -> usize {
        self.data_column_ids.iter().map(|id| id.columns.len()).sum()
    }
}

/// Request a number of beacon data columns from a peer.
#[derive(Clone, Debug, PartialEq, Ssz)]
pub struct LightClientUpdatesByRangeRequest {
    /// The starting period to request light client updates.
    pub start_period: u64,
    /// The number of periods from `start_period`.
    pub count: u64,
}

impl LightClientUpdatesByRangeRequest {
    pub fn max_requested(&self) -> u64 {
        MAX_REQUEST_LIGHT_CLIENT_UPDATES
    }
}

/* RPC Handling and Grouping */
// Collection of enums and structs used by the Codecs to encode/decode RPC messages

#[derive(Debug, Clone, PartialEq)]
pub enum RpcSuccessResponse<P: Preset> {
    /// A HELLO message.
    Status(StatusMessage),

    /// A response to a get BLOCKS_BY_RANGE request. A None response signifies the end of the
    /// batch.
    BlocksByRange(Arc<SignedBeaconBlock<P>>),

    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Arc<SignedBeaconBlock<P>>),

    /// A response to a get BLOBS_BY_RANGE request
    BlobsByRange(Arc<BlobSidecar<P>>),

    /// A response to a get LIGHT_CLIENT_BOOTSTRAP request.
    LightClientBootstrap(Arc<LightClientBootstrap<P>>),

    /// A response to a get LIGHT_CLIENT_OPTIMISTIC_UPDATE request.
    LightClientOptimisticUpdate(Arc<LightClientOptimisticUpdate<P>>),

    /// A response to a get LIGHT_CLIENT_FINALITY_UPDATE request.
    LightClientFinalityUpdate(Arc<LightClientFinalityUpdate<P>>),

    /// A response to a get LIGHT_CLIENT_UPDATES_BY_RANGE request.
    LightClientUpdatesByRange(Arc<LightClientUpdate<P>>),

    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Arc<BlobSidecar<P>>),

    /// A response to a get DATA_COLUMN_SIDECARS_BY_ROOT request.
    DataColumnsByRoot(Arc<DataColumnSidecar<P>>),

    /// A response to a get DATA_COLUMN_SIDECARS_BY_RANGE request.
    DataColumnsByRange(Arc<DataColumnSidecar<P>>),

    /// A PONG response to a PING request.
    Pong(Ping),

    /// A response to a META_DATA request.
    MetaData(Arc<MetaData>),
}

/// Indicates which response is being terminated by a stream termination response.
#[derive(Debug, Clone)]
pub enum ResponseTermination {
    /// Blocks by range stream termination.
    BlocksByRange,

    /// Blocks by root stream termination.
    BlocksByRoot,

    /// Blobs by range stream termination.
    BlobsByRange,

    /// Blobs by root stream termination.
    BlobsByRoot,

    /// Data column sidecars by root stream termination.
    DataColumnsByRoot,

    /// Data column sidecars by range stream termination.
    DataColumnsByRange,

    /// Light client updates by range stream termination.
    LightClientUpdatesByRange,
}

impl ResponseTermination {
    pub fn as_protocol(&self) -> Protocol {
        match self {
            ResponseTermination::BlocksByRange => Protocol::BlocksByRange,
            ResponseTermination::BlocksByRoot => Protocol::BlocksByRoot,
            ResponseTermination::BlobsByRange => Protocol::BlobsByRange,
            ResponseTermination::BlobsByRoot => Protocol::BlobsByRoot,
            ResponseTermination::DataColumnsByRoot => Protocol::DataColumnsByRoot,
            ResponseTermination::DataColumnsByRange => Protocol::DataColumnsByRange,
            ResponseTermination::LightClientUpdatesByRange => Protocol::LightClientUpdatesByRange,
        }
    }
}

/// The structured response containing a result/code indicating success or failure
/// and the contents of the response
#[derive(Debug, Clone)]
pub enum RpcResponse<P: Preset> {
    /// The response is a successful.
    Success(RpcSuccessResponse<P>),

    Error(RpcErrorResponse, ErrorType),

    /// Received a stream termination indicating which response is being terminated.
    StreamTermination(ResponseTermination),
}

/// Request a light_client_bootstrap for light_clients peers.
#[derive(Clone, Debug, PartialEq, Ssz)]
pub struct LightClientBootstrapRequest {
    pub root: H256,
}

/// The code assigned to an erroneous `RPCResponse`.
#[derive(Debug, Clone, Copy, PartialEq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RpcErrorResponse {
    RateLimited,
    BlobsNotFoundForBlock,
    InvalidRequest,
    ServerError,
    /// Error spec'd to indicate that a peer does not have blocks on a requested range.
    ResourceUnavailable,
    Unknown,
}

impl<P: Preset> RpcResponse<P> {
    /// Used to encode the response in the codec.
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            RpcResponse::Success(_) => Some(0),
            RpcResponse::Error(code, _) => Some(code.as_u8()),
            RpcResponse::StreamTermination(_) => None,
        }
    }

    /// Tells the codec whether to decode as an RPCResponse or an error.
    pub fn is_response(response_code: u8) -> bool {
        matches!(response_code, 0)
    }

    /// Builds an RPCCodedResponse from a response code and an ErrorMessage
    pub fn from_error(response_code: u8, err: ErrorType) -> Self {
        let code = match response_code {
            1 => RpcErrorResponse::InvalidRequest,
            2 => RpcErrorResponse::ServerError,
            3 => RpcErrorResponse::ResourceUnavailable,
            139 => RpcErrorResponse::RateLimited,
            140 => RpcErrorResponse::BlobsNotFoundForBlock,
            _ => RpcErrorResponse::Unknown,
        };
        RpcResponse::Error(code, err)
    }

    /// Returns true if this response always terminates the stream.
    pub fn close_after(&self) -> bool {
        !matches!(self, RpcResponse::Success(_))
    }
}

impl RpcErrorResponse {
    fn as_u8(&self) -> u8 {
        match self {
            RpcErrorResponse::InvalidRequest => 1,
            RpcErrorResponse::ServerError => 2,
            RpcErrorResponse::ResourceUnavailable => 3,
            RpcErrorResponse::Unknown => 255,
            RpcErrorResponse::RateLimited => 139,
            RpcErrorResponse::BlobsNotFoundForBlock => 140,
        }
    }
}

use super::Protocol;
impl<P: Preset> RpcSuccessResponse<P> {
    pub fn protocol(&self) -> Protocol {
        match self {
            RpcSuccessResponse::Status(_) => Protocol::Status,
            RpcSuccessResponse::BlocksByRange(_) => Protocol::BlocksByRange,
            RpcSuccessResponse::BlocksByRoot(_) => Protocol::BlocksByRoot,
            RpcSuccessResponse::BlobsByRange(_) => Protocol::BlobsByRange,
            RpcSuccessResponse::BlobsByRoot(_) => Protocol::BlobsByRoot,
            RpcSuccessResponse::DataColumnsByRoot(_) => Protocol::DataColumnsByRoot,
            RpcSuccessResponse::DataColumnsByRange(_) => Protocol::DataColumnsByRange,
            RpcSuccessResponse::Pong(_) => Protocol::Ping,
            RpcSuccessResponse::MetaData(_) => Protocol::MetaData,
            RpcSuccessResponse::LightClientBootstrap(_) => Protocol::LightClientBootstrap,
            RpcSuccessResponse::LightClientOptimisticUpdate(_) => {
                Protocol::LightClientOptimisticUpdate
            }
            RpcSuccessResponse::LightClientFinalityUpdate(_) => Protocol::LightClientFinalityUpdate,
            RpcSuccessResponse::LightClientUpdatesByRange(_) => Protocol::LightClientUpdatesByRange,
        }
    }

    pub fn slot(&self) -> Option<Slot> {
        match self {
            RpcSuccessResponse::BlocksByRange(block) | RpcSuccessResponse::BlocksByRoot(block) => {
                Some(block.message().slot())
            }
            RpcSuccessResponse::BlobsByRange(blob) | RpcSuccessResponse::BlobsByRoot(blob) => {
                Some(blob.signed_block_header.message.slot)
            }
            RpcSuccessResponse::DataColumnsByRange(column)
            | RpcSuccessResponse::DataColumnsByRoot(column) => Some(column.slot()),
            RpcSuccessResponse::LightClientBootstrap(b) => Some(b.slot()),
            RpcSuccessResponse::LightClientOptimisticUpdate(update) => {
                Some(update.signature_slot())
            }
            RpcSuccessResponse::LightClientFinalityUpdate(update) => Some(update.signature_slot()),
            RpcSuccessResponse::LightClientUpdatesByRange(update) => Some(update.signature_slot()),
            RpcSuccessResponse::MetaData(_)
            | RpcSuccessResponse::Status(_)
            | RpcSuccessResponse::Pong(_) => None,
        }
    }
}

impl std::fmt::Display for RpcErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            RpcErrorResponse::InvalidRequest => "The request was invalid",
            RpcErrorResponse::ResourceUnavailable => "Resource unavailable",
            RpcErrorResponse::ServerError => "Server error occurred",
            RpcErrorResponse::Unknown => "Unknown error occurred",
            RpcErrorResponse::RateLimited => "Rate limited",
            RpcErrorResponse::BlobsNotFoundForBlock => "No blobs for the given root",
        };
        f.write_str(repr)
    }
}

impl std::fmt::Display for StatusMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status Message: Fork Digest: {:?}, Finalized Root: {}, Finalized Epoch: {}, Head Root: {}, Head Slot: {} Earliest available slot: {:?}", self.fork_digest(), self.finalized_root(), self.finalized_epoch(), self.head_root(), self.head_slot(), self.earliest_available_slot())
    }
}

impl<P: Preset> std::fmt::Display for RpcSuccessResponse<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcSuccessResponse::Status(status) => write!(f, "{}", status),
            RpcSuccessResponse::BlocksByRange(block) => {
                write!(f, "BlocksByRange: Block slot: {}", block.message().slot())
            }
            RpcSuccessResponse::BlocksByRoot(block) => {
                write!(f, "BlocksByRoot: Block slot: {}", block.message().slot())
            }
            RpcSuccessResponse::BlobsByRange(blob) => {
                write!(f, "BlobsByRange: Blob slot: {}", blob.slot())
            }
            RpcSuccessResponse::BlobsByRoot(sidecar) => {
                write!(f, "BlobsByRoot: Blob slot: {}", sidecar.slot())
            }
            RpcSuccessResponse::DataColumnsByRoot(sidecar) => {
                write!(f, "DataColumnsByRoot: Data column slot: {}", sidecar.slot())
            }
            RpcSuccessResponse::DataColumnsByRange(sidecar) => {
                write!(
                    f,
                    "DataColumnsByRange: Data column slot: {}",
                    sidecar.slot()
                )
            }
            RpcSuccessResponse::Pong(ping) => write!(f, "Pong: {}", ping.data),
            RpcSuccessResponse::MetaData(metadata) => {
                write!(f, "Metadata: {}", metadata.seq_number())
            }
            RpcSuccessResponse::LightClientBootstrap(bootstrap) => {
                write!(f, "LightClientBootstrap Slot: {}", bootstrap.slot())
            }
            RpcSuccessResponse::LightClientOptimisticUpdate(update) => {
                write!(
                    f,
                    "LightClientOptimisticUpdate Slot: {}",
                    update.signature_slot()
                )
            }
            RpcSuccessResponse::LightClientFinalityUpdate(update) => {
                write!(
                    f,
                    "LightClientFinalityUpdate Slot: {}",
                    update.signature_slot()
                )
            }
            RpcSuccessResponse::LightClientUpdatesByRange(update) => {
                write!(
                    f,
                    "LightClientUpdatesByRange Slot: {}",
                    update.signature_slot(),
                )
            }
        }
    }
}

impl<P: Preset> std::fmt::Display for RpcResponse<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcResponse::Success(res) => write!(f, "{}", res),
            RpcResponse::Error(code, err) => write!(f, "{}: {}", code, err),
            RpcResponse::StreamTermination(_) => write!(f, "Stream Termination"),
        }
    }
}

impl std::fmt::Display for GoodbyeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoodbyeReason::ClientShutdown => write!(f, "Client Shutdown"),
            GoodbyeReason::IrrelevantNetwork => write!(f, "Irrelevant Network"),
            GoodbyeReason::Fault => write!(f, "Fault"),
            GoodbyeReason::UnableToVerifyNetwork => write!(f, "Unable to verify network"),
            GoodbyeReason::TooManyPeers => write!(f, "Too many peers"),
            GoodbyeReason::BadScore => write!(f, "Bad Score"),
            GoodbyeReason::Banned => write!(f, "Banned"),
            GoodbyeReason::BannedIP => write!(f, "BannedIP"),
            GoodbyeReason::Unknown => write!(f, "Unknown Reason"),
        }
    }
}

impl std::fmt::Display for BlocksByRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start Slot: {}, Count: {}",
            self.start_slot(),
            self.count()
        )
    }
}

impl std::fmt::Display for OldBlocksByRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start Slot: {}, Count: {}, Step: {}",
            self.start_slot(),
            self.count(),
            self.step()
        )
    }
}

impl std::fmt::Display for BlobsByRootRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request: BlobsByRoot: Number of Requested Roots: {}",
            self.blob_ids.len()
        )
    }
}

impl std::fmt::Display for BlobsByRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request: BlobsByRange: Start Slot: {}, Count: {}",
            self.start_slot, self.count
        )
    }
}

impl<P: Preset> std::fmt::Display for DataColumnsByRootRequest<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request: DataColumnsByRoot: Number of Requested Data Column Ids: {}",
            self.data_column_ids.len()
        )
    }
}

impl<P: Preset> std::fmt::Display for DataColumnsByRangeRequest<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request: DataColumnsByRange: Start Slot: {}, Count: {}, Number of Requested Columns Ids: {}",
            self.start_slot,
            self.count,
            self.columns.len()
        )
    }
}
