//! Available RPC methods types and ids.
use std::fmt::Display;

use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use anyhow::Result;
use regex::bytes::Regex;
use serde::Serialize;
use ssz::{ContiguousList, ReadError, Size, Ssz, SszRead, SszSize, SszWrite, WriteError};
use std::marker::PhantomData;
use std::{ops::Deref, sync::Arc};
use strum::IntoStaticStr;
use try_from_iterator::TryFromIterator as _;
use typenum::{Unsigned as _, U1024, U128, U256, U768};
use types::deneb::containers::BlobIdentifier;
use types::{
    combined::{
        BlobSidecar, LightClientBootstrap, LightClientFinalityUpdate, LightClientOptimisticUpdate,
        SignedBeaconBlock,
    },
    phase0::primitives::{Epoch, ForkDigest, Slot, H256},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

/// Maximum number of blocks in a single request.
pub type MaxRequestBlocks = U1024;
pub const MAX_REQUEST_BLOCKS: u64 = 1024;

/// Maximum length of error message.
pub type MaxErrorLen = U256;
pub const MAX_ERROR_LEN: u64 = 256;

pub type MaxRequestBlocksDeneb = U128;
pub const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;

pub type MaxRequestBlobSidecars = U768;
pub const MAX_REQUEST_BLOB_SIDECARS: u64 = 768;

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
#[derive(Copy, Clone, Debug, PartialEq, Ssz)]
#[ssz(derive_hash = false)]
pub struct StatusMessage {
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

/// The PING request/response message.
#[derive(Clone, Debug, PartialEq, Ssz)]
#[ssz(derive_hash = false, transparent)]
pub struct Ping {
    /// The metadata sequence number.
    pub data: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MetadataRequest<P: Preset> {
    V1(MetadataRequestV1<P>),
    V2(MetadataRequestV2<P>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataRequestV1<P: Preset> {
    _phantom_data: PhantomData<P>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataRequestV2<P: Preset> {
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
}

/// The METADATA response structure.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
pub enum MetaData {
    V1(MetaDataV1),
    V2(MetaDataV2),
}

impl MetaData {
    pub fn seq_number(self) -> u64 {
        match self {
            Self::V1(meta_data) => meta_data.seq_number,
            Self::V2(meta_data) => meta_data.seq_number,
        }
    }

    pub fn attnets(self) -> EnrAttestationBitfield {
        match self {
            Self::V1(meta_data) => meta_data.attnets,
            Self::V2(meta_data) => meta_data.attnets,
        }
    }

    pub fn syncnets(self) -> Option<EnrSyncCommitteeBitfield> {
        match self {
            Self::V1(_) => None,
            Self::V2(meta_data) => Some(meta_data.syncnets),
        }
    }

    pub fn seq_number_mut(&mut self) -> &mut u64 {
        match self {
            Self::V1(meta_data) => &mut meta_data.seq_number,
            Self::V2(meta_data) => &mut meta_data.seq_number,
        }
    }

    pub fn attnets_mut(&mut self) -> &mut EnrAttestationBitfield {
        match self {
            Self::V1(meta_data) => &mut meta_data.attnets,
            Self::V2(meta_data) => &mut meta_data.attnets,
        }
    }

    pub fn syncnets_mut(&mut self) -> Option<&mut EnrSyncCommitteeBitfield> {
        match self {
            Self::V1(_) => None,
            Self::V2(meta_data) => Some(&mut meta_data.syncnets),
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

impl MetaData {
    /// Returns a V1 MetaData response from self.
    pub fn metadata_v1(&self) -> Self {
        match self {
            md @ MetaData::V1(_) => md.clone(),
            MetaData::V2(metadata) => MetaData::V1(MetaDataV1 {
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
        }
    }

    pub fn to_ssz(&self) -> Result<Vec<u8>, WriteError> {
        match self {
            MetaData::V1(md) => md.to_ssz(),
            MetaData::V2(md) => md.to_ssz(),
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
    pub fn max_blobs_requested<P: Preset>(&self) -> u64 {
        self.count.saturating_mul(P::MaxBlobsPerBlock::U64)
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
    pub block_roots: ContiguousList<H256, MaxRequestBlocks>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocksByRootRequestV2 {
    /// The list of beacon block bodies being requested.
    pub block_roots: ContiguousList<H256, MaxRequestBlocks>,
}

impl BlocksByRootRequest {
    pub fn new(block_roots: ContiguousList<H256, MaxRequestBlocks>) -> Self {
        Self::V2(BlocksByRootRequestV2 { block_roots })
    }

    pub fn new_v1(block_roots: ContiguousList<H256, MaxRequestBlocks>) -> Self {
        Self::V1(BlocksByRootRequestV1 { block_roots })
    }

    pub fn len(&self) -> usize {
        match self {
            Self::V1(req) => req.block_roots.len(),
            Self::V2(req) => req.block_roots.len(),
        }
    }

    pub fn block_roots(self) -> ContiguousList<H256, MaxRequestBlocks> {
        match self {
            Self::V1(req) => req.block_roots,
            Self::V2(req) => req.block_roots,
        }
    }
}

/// Request a number of beacon blocks and blobs from a peer.
#[derive(Clone, Debug, PartialEq)]
pub struct BlobsByRootRequest {
    /// The list of beacon block roots being requested.
    pub blob_ids: ContiguousList<BlobIdentifier, MaxRequestBlobSidecars>,
}

impl BlobsByRootRequest {
    pub fn new(blob_ids: ContiguousList<BlobIdentifier, MaxRequestBlobSidecars>) -> Self {
        Self { blob_ids }
    }
}

/* RPC Handling and Grouping */
// Collection of enums and structs used by the Codecs to encode/decode RPC messages

#[derive(Debug, Clone, PartialEq)]
pub enum RPCResponse<P: Preset> {
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

    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Arc<BlobSidecar<P>>),

    /// A PONG response to a PING request.
    Pong(Ping),

    /// A response to a META_DATA request.
    MetaData(MetaData),
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
}

/// The structured response containing a result/code indicating success or failure
/// and the contents of the response
#[derive(Debug, Clone)]
pub enum RPCCodedResponse<P: Preset> {
    /// The response is a successful.
    Success(RPCResponse<P>),

    Error(RPCResponseErrorCode, ErrorType),

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
pub enum RPCResponseErrorCode {
    RateLimited,
    BlobsNotFoundForBlock,
    InvalidRequest,
    ServerError,
    /// Error spec'd to indicate that a peer does not have blocks on a requested range.
    ResourceUnavailable,
    Unknown,
}

impl<P: Preset> RPCCodedResponse<P> {
    /// Used to encode the response in the codec.
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            RPCCodedResponse::Success(_) => Some(0),
            RPCCodedResponse::Error(code, _) => Some(code.as_u8()),
            RPCCodedResponse::StreamTermination(_) => None,
        }
    }

    /// Tells the codec whether to decode as an RPCResponse or an error.
    pub fn is_response(response_code: u8) -> bool {
        matches!(response_code, 0)
    }

    /// Builds an RPCCodedResponse from a response code and an ErrorMessage
    pub fn from_error(response_code: u8, err: ErrorType) -> Self {
        let code = match response_code {
            1 => RPCResponseErrorCode::InvalidRequest,
            2 => RPCResponseErrorCode::ServerError,
            3 => RPCResponseErrorCode::ResourceUnavailable,
            139 => RPCResponseErrorCode::RateLimited,
            140 => RPCResponseErrorCode::BlobsNotFoundForBlock,
            _ => RPCResponseErrorCode::Unknown,
        };
        RPCCodedResponse::Error(code, err)
    }

    /// Returns true if this response always terminates the stream.
    pub fn close_after(&self) -> bool {
        !matches!(self, RPCCodedResponse::Success(_))
    }
}

impl RPCResponseErrorCode {
    fn as_u8(&self) -> u8 {
        match self {
            RPCResponseErrorCode::InvalidRequest => 1,
            RPCResponseErrorCode::ServerError => 2,
            RPCResponseErrorCode::ResourceUnavailable => 3,
            RPCResponseErrorCode::Unknown => 255,
            RPCResponseErrorCode::RateLimited => 139,
            RPCResponseErrorCode::BlobsNotFoundForBlock => 140,
        }
    }
}

use super::Protocol;
impl<P: Preset> RPCResponse<P> {
    pub fn protocol(&self) -> Protocol {
        match self {
            RPCResponse::Status(_) => Protocol::Status,
            RPCResponse::BlocksByRange(_) => Protocol::BlocksByRange,
            RPCResponse::BlocksByRoot(_) => Protocol::BlocksByRoot,
            RPCResponse::BlobsByRange(_) => Protocol::BlobsByRange,
            RPCResponse::BlobsByRoot(_) => Protocol::BlobsByRoot,
            RPCResponse::Pong(_) => Protocol::Ping,
            RPCResponse::MetaData(_) => Protocol::MetaData,
            RPCResponse::LightClientBootstrap(_) => Protocol::LightClientBootstrap,
            RPCResponse::LightClientOptimisticUpdate(_) => Protocol::LightClientOptimisticUpdate,
            RPCResponse::LightClientFinalityUpdate(_) => Protocol::LightClientFinalityUpdate,
        }
    }
}

impl std::fmt::Display for RPCResponseErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            RPCResponseErrorCode::InvalidRequest => "The request was invalid",
            RPCResponseErrorCode::ResourceUnavailable => "Resource unavailable",
            RPCResponseErrorCode::ServerError => "Server error occurred",
            RPCResponseErrorCode::Unknown => "Unknown error occurred",
            RPCResponseErrorCode::RateLimited => "Rate limited",
            RPCResponseErrorCode::BlobsNotFoundForBlock => "No blobs for the given root",
        };
        f.write_str(repr)
    }
}

impl std::fmt::Display for StatusMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status Message: Fork Digest: {:?}, Finalized Root: {}, Finalized Epoch: {}, Head Root: {}, Head Slot: {}", self.fork_digest, self.finalized_root, self.finalized_epoch, self.head_root, self.head_slot)
    }
}

impl<P: Preset> std::fmt::Display for RPCResponse<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCResponse::Status(status) => write!(f, "{}", status),
            RPCResponse::BlocksByRange(block) => {
                write!(f, "BlocksByRange: Block slot: {}", block.message().slot())
            }
            RPCResponse::BlocksByRoot(block) => {
                write!(f, "BlocksByRoot: Block slot: {}", block.message().slot())
            }
            RPCResponse::BlobsByRange(blob) => {
                write!(
                    f,
                    "BlobsByRange: Blob slot: {}",
                    blob.signed_block_header().message.slot
                )
            }
            RPCResponse::BlobsByRoot(sidecar) => {
                write!(
                    f,
                    "BlobsByRoot: Blob slot: {}",
                    sidecar.signed_block_header().message.slot
                )
            }
            RPCResponse::Pong(ping) => write!(f, "Pong: {}", ping.data),
            RPCResponse::MetaData(metadata) => write!(f, "Metadata: {}", metadata.seq_number()),
            RPCResponse::LightClientBootstrap(bootstrap) => {
                write!(f, "LightClientBootstrap Slot: {}", bootstrap.slot())
            }
            RPCResponse::LightClientOptimisticUpdate(update) => {
                write!(
                    f,
                    "LightClientOptimisticUpdate Slot: {}",
                    update.signature_slot()
                )
            }
            RPCResponse::LightClientFinalityUpdate(update) => {
                write!(
                    f,
                    "LightClientFinalityUpdate Slot: {}",
                    update.signature_slot()
                )
            }
        }
    }
}

impl<P: Preset> std::fmt::Display for RPCCodedResponse<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCCodedResponse::Success(res) => write!(f, "{}", res),
            RPCCodedResponse::Error(code, err) => write!(f, "{}: {}", code, err),
            RPCCodedResponse::StreamTermination(_) => write!(f, "Stream Termination"),
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

impl slog::KV for StatusMessage {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        use slog::Value;
        serializer.emit_arguments("fork_digest", &format_args!("{:?}", self.fork_digest))?;
        Value::serialize(&self.finalized_epoch, record, "finalized_epoch", serializer)?;
        serializer.emit_arguments("finalized_root", &format_args!("{}", self.finalized_root))?;
        Value::serialize(&self.head_slot, record, "head_slot", serializer)?;
        serializer.emit_arguments("head_root", &format_args!("{}", self.head_root))?;
        slog::Result::Ok(())
    }
}
