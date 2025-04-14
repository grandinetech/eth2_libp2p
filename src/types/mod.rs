mod enr_fork_id;
mod fork_context;
mod globals;
mod grandine;
mod pubsub;
mod subnet;
mod sync_state;
mod topics;

use ssz::BitVector;
use types::{altair::consts::SyncCommitteeSubnetCount, phase0::consts::AttestationSubnetCount};

pub type EnrAttestationBitfield = BitVector<AttestationSubnetCount>;
pub type EnrSyncCommitteeBitfield = BitVector<SyncCommitteeSubnetCount>;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use enr_fork_id::EnrForkId;
pub use fork_context::ForkContext;
pub use globals::NetworkGlobals;
pub use grandine::{PeerDirection, PeerState};
pub use pubsub::{PubsubMessage, SnappyTransform};
pub use subnet::{Subnet, SubnetDiscovery};
pub use sync_state::{BackFillState, SyncState};
pub use topics::{
    attestation_sync_committee_topics, core_topics_to_subscribe, fork_core_topics,
    subnet_from_topic_hash, GossipEncoding, GossipKind, GossipTopic, ALTAIR_CORE_TOPICS,
    BASE_CORE_TOPICS, CAPELLA_CORE_TOPICS, LIGHT_CLIENT_GOSSIP_TOPICS,
};
