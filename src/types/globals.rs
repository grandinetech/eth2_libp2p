//! A collection of variables that are accessible outside of the network thread itself.
use crate::eip7594::{columns_for_data_column_subnet, compute_custody_subnets, from_column_index};
use crate::peer_manager::peerdb::PeerDB;
use crate::rpc::{MetaData, MetaDataV3};
use crate::types::{BackFillState, SyncState};
use crate::{Client, Enr, EnrExt, GossipTopic, Multiaddr, NetworkConfig, PeerId};
use itertools::Itertools as _;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use std_ext::ArcExt as _;
use types::config::Config as ChainConfig;
use types::eip7594::ColumnIndex;
use types::phase0::primitives::SubnetId;

pub struct NetworkGlobals {
    /// Ethereum chain configuration. Immutable after initialization.
    pub config: Arc<ChainConfig>,
    /// The current local ENR.
    pub local_enr: RwLock<Enr>,
    /// The local peer_id.
    pub peer_id: RwLock<PeerId>,
    /// Listening multiaddrs.
    pub listen_multiaddrs: RwLock<Vec<Multiaddr>>,
    /// The collection of known peers.
    pub peers: RwLock<PeerDB>,
    // The local meta data of our node.
    pub local_metadata: RwLock<MetaData>,
    /// The current gossipsub topic subscriptions.
    pub gossipsub_subscriptions: RwLock<HashSet<GossipTopic>>,
    /// The current sync status of the node.
    pub sync_state: RwLock<SyncState>,
    /// The current state of the backfill sync.
    pub backfill_state: RwLock<BackFillState>,
    /// The computed sampling subnets and columns is stored to avoid re-computing.
    pub sampling_subnets: Vec<SubnetId>,
    pub sampling_columns: Vec<ColumnIndex>,
    /// Target subnet peers.
    pub target_subnet_peers: usize,
    /// Network-related configuration. Immutable after initialization.
    pub network_config: Arc<NetworkConfig>,
}

impl NetworkGlobals {
    pub fn new(
        config: Arc<ChainConfig>,
        enr: Enr,
        local_metadata: MetaData,
        trusted_peers: Vec<PeerId>,
        disable_peer_scoring: bool,
        target_subnet_peers: usize,
        log: &slog::Logger,
        network_config: Arc<NetworkConfig>,
    ) -> Self {
        let (sampling_subnets, sampling_columns) = if config.is_eip7594_fork_epoch_set() {
            let node_id = enr.node_id().raw();

            let custody_subnet_count = local_metadata
                .custody_subnet_count()
                .expect("custody subnet count must be set if PeerDAS is scheduled");

            let subnet_sampling_size = std::cmp::max(custody_subnet_count, config.samples_per_slot);

            let sampling_subnets = compute_custody_subnets(node_id, subnet_sampling_size)
                .expect("sampling subnet count must be valid")
                .collect::<Vec<_>>();

            let sampling_columns = sampling_subnets
                .iter()
                .flat_map(|subnet| columns_for_data_column_subnet(*subnet))
                .sorted()
                .collect();

            (sampling_subnets, sampling_columns)
        } else {
            (vec![], vec![])
        };

        NetworkGlobals {
            config: config.clone_arc(),
            local_enr: RwLock::new(enr.clone()),
            peer_id: RwLock::new(enr.peer_id()),
            listen_multiaddrs: RwLock::new(Vec::new()),
            local_metadata: RwLock::new(local_metadata),
            peers: RwLock::new(PeerDB::new(
                config,
                trusted_peers,
                disable_peer_scoring,
                log,
            )),
            gossipsub_subscriptions: RwLock::new(HashSet::new()),
            sync_state: RwLock::new(SyncState::Stalled),
            backfill_state: RwLock::new(BackFillState::Paused),
            sampling_subnets,
            sampling_columns,
            target_subnet_peers,
            network_config,
        }
    }

    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Enr {
        self.local_enr.read().clone()
    }

    /// Returns the local libp2p PeerID.
    pub fn local_peer_id(&self) -> PeerId {
        *self.peer_id.read()
    }

    /// Returns the list of `Multiaddr` that the underlying libp2p instance is listening on.
    pub fn listen_multiaddrs(&self) -> Vec<Multiaddr> {
        self.listen_multiaddrs.read().clone()
    }

    /// Returns the number of libp2p connected peers.
    pub fn connected_peers(&self) -> usize {
        self.peers.read().connected_peer_ids().count()
    }

    /// Check if peer is connected
    pub fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.peers.read().is_peer_connected(peer_id)
    }

    /// Returns the number of libp2p connected peers with outbound-only connections.
    pub fn connected_outbound_only_peers(&self) -> usize {
        self.peers.read().connected_outbound_only_peers().count()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    pub fn connected_or_dialing_peers(&self) -> usize {
        self.peers.read().connected_or_dialing_peers().count()
    }

    /// Returns in the node is syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync_state.read().is_syncing()
    }

    /// Returns the current sync state of the peer.
    pub fn sync_state(&self) -> SyncState {
        self.sync_state.read().clone()
    }

    /// Returns the current backfill state.
    pub fn backfill_state(&self) -> BackFillState {
        self.backfill_state.read().clone()
    }

    /// Returns a `Client` type if one is known for the `PeerId`.
    pub fn client(&self, peer_id: &PeerId) -> Client {
        self.peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client().clone())
            .unwrap_or_default()
    }

    pub fn add_trusted_peer(&self, enr: Enr) {
        self.peers.write().set_trusted_peer(enr);
    }

    pub fn remove_trusted_peer(&self, enr: Enr) {
        self.peers.write().unset_trusted_peer(enr);
    }

    pub fn trusted_peers(&self) -> Vec<PeerId> {
        self.peers.read().trusted_peers()
    }

    /// Updates the syncing state of the node.
    ///
    /// The old state is returned
    pub fn set_sync_state(&self, new_state: SyncState) -> SyncState {
        std::mem::replace(&mut *self.sync_state.write(), new_state)
    }

    /// Returns a connected peer that:
    /// 1. is connected
    /// 2. assigned to custody the column based on it's `custody_subnet_count` from ENR or metadata
    /// 3. has a good score
    pub fn custody_peers_for_column(&self, column_index: ColumnIndex) -> Vec<PeerId> {
        self.peers
            .read()
            .good_custody_subnet_peer(from_column_index(column_index as usize, &self.config))
            .cloned()
            .collect::<Vec<_>>()
    }

    /// TESTING ONLY. Build a dummy NetworkGlobals instance.
    pub fn new_test_globals(
        chain_config: Arc<ChainConfig>,
        trusted_peers: Vec<PeerId>,
        log: &slog::Logger,
        network_config: Arc<NetworkConfig>,
    ) -> NetworkGlobals {
        let metadata = MetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: Default::default(),
            syncnets: Default::default(),
            custody_subnet_count: chain_config.custody_requirement,
        });

        Self::new_test_globals_with_metadata(
            chain_config,
            trusted_peers,
            metadata,
            log,
            network_config,
        )
    }

    pub(crate) fn new_test_globals_with_metadata(
        chain_config: Arc<ChainConfig>,
        trusted_peers: Vec<PeerId>,
        metadata: MetaData,
        log: &slog::Logger,
        network_config: Arc<NetworkConfig>,
    ) -> NetworkGlobals {
        use crate::CombinedKeyExt;
        let keypair = libp2p::identity::secp256k1::Keypair::generate();
        let enr_key: discv5::enr::CombinedKey = discv5::enr::CombinedKey::from_secp256k1(&keypair);
        let enr = discv5::enr::Enr::builder().build(&enr_key).unwrap();
        NetworkGlobals::new(
            chain_config,
            enr,
            metadata,
            trusted_peers,
            false,
            3,
            log,
            network_config,
        )
    }
}

// TODO(das): uncomment after merging and updating stubs
// #[cfg(test)]
// mod test {
//     use slog::{o, Drain as _, Level};

//     use super::*;

//     pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
//         let decorator = slog_term::TermDecorator::new().build();
//         let drain = slog_term::FullFormat::new(decorator).build().fuse();
//         let drain = slog_async::Async::new(drain).build().fuse();

//         if enabled {
//             slog::Logger::root(drain.filter_level(level).fuse(), o!())
//         } else {
//             slog::Logger::root(drain.filter(|_| false).fuse(), o!())
//         }
//     }

//     #[test]
//     fn test_sampling_subnets() {
//         let log_level = Level::Debug;
//         let enable_logging = false;

//         let log = build_log(log_level, enable_logging);
//         let mut chain_config = ChainConfig::mainnet();
//         chain_config.eip7594_fork_epoch = 0;

//         let custody_subnet_count = chain_config.data_column_sidecar_subnet_count / 2;
//         let subnet_sampling_size =
//             std::cmp::max(custody_subnet_count, chain_config.samples_per_slot);
//         let metadata = get_metadata(custody_subnet_count);
//         let config = Arc::new(NetworkConfig::default());

//         let globals = NetworkGlobals::new_test_globals_with_metadata(
//             Arc::new(chain_config),
//             vec![],
//             metadata,
//             &log,
//             config,
//         );
//         assert_eq!(
//             globals.sampling_subnets.len(),
//             subnet_sampling_size as usize
//         );
//     }

//     #[test]
//     fn test_sampling_columns() {
//         let log_level = Level::Debug;
//         let enable_logging = false;

//         let log = build_log(log_level, enable_logging);
//         let mut chain_config = ChainConfig::mainnet();
//         chain_config.eip7594_fork_epoch = 0;

//         let custody_subnet_count = chain_config.data_column_sidecar_subnet_count / 2;
//         let subnet_sampling_size =
//             std::cmp::max(custody_subnet_count, chain_config.samples_per_slot);
//         let metadata = get_metadata(custody_subnet_count);
//         let config = Arc::new(NetworkConfig::default());

//         let globals = NetworkGlobals::new_test_globals_with_metadata(
//             Arc::new(chain_config),
//             vec![],
//             metadata,
//             &log,
//             config,
//         );
//         assert_eq!(
//             globals.sampling_columns.len(),
//             subnet_sampling_size as usize
//         );
//     }

//     fn get_metadata(custody_subnet_count: u64) -> MetaData {
//         MetaData::V3(MetaDataV3 {
//             seq_number: 0,
//             attnets: Default::default(),
//             syncnets: Default::default(),
//             custody_subnet_count,
//         })
//     }
// }
