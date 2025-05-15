//! A collection of variables that are accessible outside of the network thread itself.
use super::TopicConfig;
use crate::peer_manager::peerdb::PeerDB;
use crate::rpc::{MetaData, MetaDataV3};
use crate::types::{BackFillState, SyncState};
use crate::{Client, Enr, EnrExt, GossipTopic, Multiaddr, NetworkConfig, PeerId};
use eip_7594::{
    compute_columns_for_custody_group, compute_subnets_from_custody_group, get_custody_groups,
};
use helper_functions::misc::compute_subnet_for_data_column_sidecar;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use std_ext::ArcExt as _;
use types::config::Config as ChainConfig;
use types::fulu::primitives::ColumnIndex;
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
    pub sampling_subnets: HashSet<SubnetId>,
    pub sampling_columns: HashSet<ColumnIndex>,
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
        let (sampling_subnets, sampling_columns) = if config.is_peerdas_scheduled() {
            let node_id = enr.node_id().raw();

            let custody_group_count = local_metadata
                .custody_group_count()
                .expect("custody group count must be set if PeerDAS is scheduled");

            let sampling_size = config.sampling_size(custody_group_count);

            let custody_groups = get_custody_groups(node_id, sampling_size, &config)
                .expect("should compute custody groups for node");

            let mut sampling_subnets = HashSet::new();
            for custody_index in &custody_groups {
                let subnets = compute_subnets_from_custody_group(*custody_index, &config)
                    .expect("should compute custody subnets for node");
                sampling_subnets.extend(subnets);
            }

            let mut sampling_columns = HashSet::new();
            for custody_index in &custody_groups {
                let columns = compute_columns_for_custody_group(*custody_index, &config)
                    .expect("should compute custody columns for node");
                sampling_columns.extend(columns);
            }

            (sampling_subnets, sampling_columns)
        } else {
            (HashSet::new(), HashSet::new())
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
            .good_custody_subnet_peer(compute_subnet_for_data_column_sidecar(
                &self.config,
                column_index,
            ))
            .cloned()
            .collect::<Vec<_>>()
    }

    // Returns the TopicConfig to compute the set of Gossip topics for a given fork
    pub fn as_topic_config(&self) -> TopicConfig {
        TopicConfig {
            enable_light_client_server: self.network_config.enable_light_client_server,
            subscribe_all_subnets: self.network_config.subscribe_all_subnets,
            subscribe_all_data_column_subnets: self
                .network_config
                .subscribe_all_data_column_subnets,
            sampling_subnets: &self.sampling_subnets,
        }
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
            custody_group_count: chain_config.custody_requirement,
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

#[cfg(test)]
mod test {
    use slog::{o, Drain as _, Level};

    use super::*;

    pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        if enabled {
            slog::Logger::root(drain.filter_level(level).fuse(), o!())
        } else {
            slog::Logger::root(drain.filter(|_| false).fuse(), o!())
        }
    }

    #[test]
    fn test_sampling_subnets() {
        let log_level = Level::Debug;
        let enable_logging = false;

        let log = build_log(log_level, enable_logging);
        let mut chain_config = ChainConfig::mainnet();
        chain_config.fulu_fork_epoch = 0;

        let custody_group_count = chain_config.number_of_custody_groups / 2;
        let sampling_size = chain_config.sampling_size(custody_group_count);
        let metadata = get_metadata(custody_group_count);
        let config = Arc::new(NetworkConfig::default());

        let globals = NetworkGlobals::new_test_globals_with_metadata(
            Arc::new(chain_config),
            vec![],
            metadata,
            &log,
            config,
        );
        assert_eq!(globals.sampling_subnets.len(), sampling_size as usize);
    }

    #[test]
    fn test_sampling_columns() {
        let log_level = Level::Debug;
        let enable_logging = false;

        let log = build_log(log_level, enable_logging);
        let mut chain_config = ChainConfig::mainnet();
        chain_config.fulu_fork_epoch = 0;

        let custody_group_count = chain_config.number_of_custody_groups / 2;
        let sampling_size = chain_config.sampling_size(custody_group_count);
        let metadata = get_metadata(custody_group_count);
        let config = Arc::new(NetworkConfig::default());

        let globals = NetworkGlobals::new_test_globals_with_metadata(
            Arc::new(chain_config),
            vec![],
            metadata,
            &log,
            config,
        );
        assert_eq!(globals.sampling_subnets.len(), sampling_size as usize);
    }

    fn get_metadata(custody_group_count: u64) -> MetaData {
        MetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: Default::default(),
            syncnets: Default::default(),
            custody_group_count,
        })
    }
}
