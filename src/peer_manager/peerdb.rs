use crate::discovery::enr::PEERDAS_CUSTODY_SUBNET_COUNT_ENR_KEY;
use crate::discovery::{peer_id_to_node_id, CombinedKey};
use crate::eip7594::compute_custody_subnets;
use crate::{metrics, multiaddr::Multiaddr, types::Subnet, Enr, EnrExt, Gossipsub, PeerId};
use itertools::Itertools as _;
use peer_info::{ConnectionDirection, PeerConnectionStatus, PeerInfo};
use score::{PeerAction, ReportSource, Score, ScoreState};
use slog::{crit, debug, error, trace, warn};
use std::net::IpAddr;
use std::time::Instant;
use std::{cmp::Ordering, fmt::Display};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::Formatter,
    sync::Arc,
};
use sync_status::SyncStatus;
use types::config::Config as ChainConfig;
use types::phase0::primitives::SubnetId;

pub mod client;
pub mod peer_info;
pub mod score;
pub mod sync_status;

/// Max number of disconnected nodes to remember.
const MAX_DC_PEERS: usize = 500;
/// The maximum number of banned nodes to remember.
pub const MAX_BANNED_PEERS: usize = 1000;
/// We ban an IP if there are more than `BANNED_PEERS_PER_IP_THRESHOLD` banned peers with this IP.
const BANNED_PEERS_PER_IP_THRESHOLD: usize = 5;
/// Relative factor of peers that are allowed to have a negative gossipsub score without penalizing.
const ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR: f32 = 0.1;
/// The time we allow peers to be in the dialing state in our PeerDb before we revert them to a
/// disconnected state.
const DIAL_TIMEOUT: u64 = 15;

/// Storage of known peers, their reputation and information
pub struct PeerDB {
    chain_config: Arc<ChainConfig>,
    /// The collection of known connected peers, their status and reputation
    peers: HashMap<PeerId, PeerInfo>,
    /// The number of disconnected nodes in the database.
    disconnected_peers: usize,
    /// Counts banned peers in total and per ip
    banned_peers_count: BannedPeersCount,
    /// Specifies if peer scoring is disabled.
    disable_peer_scoring: bool,
    /// PeerDB's logger
    log: slog::Logger,
}

impl PeerDB {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        trusted_peers: Vec<PeerId>,
        disable_peer_scoring: bool,
        log: &slog::Logger,
    ) -> Self {
        // Initialize the peers hashmap with trusted peers
        let peers = trusted_peers
            .into_iter()
            .map(|peer_id| (peer_id, PeerInfo::trusted_peer_info()))
            .collect();
        Self {
            chain_config,
            log: log.clone(),
            disconnected_peers: 0,
            banned_peers_count: BannedPeersCount::default(),
            disable_peer_scoring,
            peers,
        }
    }

    /* Getters */

    /// Gives the score of a peer, or default score if it is unknown.
    pub fn score(&self, peer_id: &PeerId) -> f64 {
        self.peers
            .get(peer_id)
            .map_or(&Score::default(), |info| info.score())
            .score()
    }

    /// Returns an iterator over all peers in the db.
    pub fn peers(&self) -> impl Iterator<Item = (&PeerId, &PeerInfo)> {
        self.peers.iter()
    }

    pub fn set_trusted_peer(&mut self, enr: Enr) {
        match self.peers.entry(enr.peer_id()) {
            Entry::Occupied(mut info) => {
                let entry = info.get_mut();
                entry.score = Score::max_score();
                entry.is_trusted = true;
            }
            Entry::Vacant(entry) => {
                entry.insert(PeerInfo::trusted_peer_info());
            }
        }
    }

    pub fn unset_trusted_peer(&mut self, enr: Enr) {
        if let Some(info) = self.peers.get_mut(&enr.peer_id()) {
            info.is_trusted = false;
            info.score = Score::default();
        }
    }

    pub fn trusted_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter_map(|(id, info)| if info.is_trusted { Some(*id) } else { None })
            .collect()
    }

    /// Gives the ids of all known peers.
    pub fn peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.keys()
    }

    /// Returns a peer's info, if known.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Returns a mutable reference to a peer's info if known.
    // VISIBILITY: The peer manager is able to modify some elements of the peer info, such as sync
    // status.
    pub(super) fn peer_info_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }

    /// Returns if the peer is already connected.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Connected { .. })
        )
    }

    /// If we are connected or currently dialing the peer returns true.
    pub fn is_connected_or_dialing(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Connected { .. })
                | Some(PeerConnectionStatus::Dialing { .. })
        )
    }

    /// If we are connected or in the process of disconnecting
    pub fn is_connected_or_disconnecting(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Connected { .. })
                | Some(PeerConnectionStatus::Disconnecting { .. })
        )
    }

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    pub fn should_dial(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Disconnected { .. })
                | Some(PeerConnectionStatus::Unknown)
                | None
        ) && !self.score_state_banned_or_disconnected(peer_id)
    }

    /// Returns true if the peer is synced at least to our current head.
    pub fn is_synced(&self, peer_id: &PeerId) -> bool {
        match self.peers.get(peer_id).map(|info| info.sync_status()) {
            Some(SyncStatus::Synced { .. }) => true,
            Some(_) => false,
            None => false,
        }
    }

    /// Returns the current [`BanResult`] of the peer if banned. This doesn't check the connection state, rather the
    /// underlying score of the peer. A peer may be banned but still in the connected state
    /// temporarily.
    ///
    /// This is used to determine if we should accept incoming connections or not.
    pub fn ban_status(&self, peer_id: &PeerId) -> Option<BanResult> {
        self.peers
            .get(peer_id)
            .and_then(|peer| match peer.score_state() {
                ScoreState::Banned => Some(BanResult::BadScore),
                _ => self.ip_is_banned(peer).map(BanResult::BannedIp),
            })
    }

    /// Checks if the peer's known addresses are currently banned.
    fn ip_is_banned(&self, peer: &PeerInfo) -> Option<IpAddr> {
        peer.seen_ip_addresses()
            .find(|ip| self.banned_peers_count.ip_is_banned(ip))
    }

    /// Returns true if the IP is banned.
    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        self.banned_peers_count.ip_is_banned(ip)
    }

    /// Returns true if the Peer is either banned or in the disconnected state.
    fn score_state_banned_or_disconnected(&self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get(peer_id) {
            match peer.score_state() {
                ScoreState::Banned | ScoreState::ForcedDisconnect => true,
                _ => self.ip_is_banned(peer).is_some(),
            }
        } else {
            false
        }
    }

    /// Gives the ids and info of all known connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = (&PeerId, &PeerInfo)> {
        self.peers.iter().filter(|(_, info)| info.is_connected())
    }

    /// Gives the ids of all known connected peers.
    pub fn connected_peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_connected())
            .map(|(peer_id, _)| peer_id)
    }

    pub fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_connected())
            .find(|(connected_peer_id, _)| **connected_peer_id == *peer_id)
            .is_some()
    }

    /// Connected or dialing peers
    pub fn connected_or_dialing_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_connected() || info.is_dialing())
            .map(|(peer_id, _)| peer_id)
    }

    /// Connected outbound-only peers
    pub fn connected_outbound_only_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_outbound_only())
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the `peer_id` of all known connected and synced peers.
    pub fn synced_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                if info.sync_status().is_synced() || info.sync_status().is_advanced() {
                    return info.is_connected();
                }
                false
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the `peer_id` of all known connected and advanced peers.
    pub fn advanced_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                if info.sync_status().is_advanced() {
                    return info.is_connected();
                }
                false
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives an iterator of all peers on a given subnet.
    pub fn good_peers_on_subnet(&self, subnet: Subnet) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(move |(_, info)| {
                // We check both the metadata and gossipsub data as we only want to count long-lived subscribed peers
                info.is_connected()
                    && info.on_subnet_metadata(&subnet)
                    && info.on_subnet_gossipsub(&subnet)
                    && info.is_good_gossipsub_peer()
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Returns an iterator of all good gossipsub peers that are supposed to be custodying
    /// the given subnet id.
    pub fn good_custody_subnet_peer(&self, subnet: SubnetId) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(move |(_, info)| {
                // The custody_subnets hashset can be populated via enr or metadata
                let is_custody_subnet_peer = info.is_assigned_to_custody_subnet(&subnet);
                info.is_connected() && info.is_good_gossipsub_peer() && is_custody_subnet_peer
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the ids of all known disconnected peers.
    pub fn disconnected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_disconnected())
            .map(|(peer_id, _)| peer_id)
    }

    /// Returns the ids of all known banned peers.
    pub fn banned_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_banned())
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the ids of all known banned peers.
    pub fn banned_peers_by_score(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.score_is_banned())
            .map(|(peer_id, _)| peer_id)
    }

    /// Returns a vector of all connected peers sorted by score beginning with the worst scores.
    /// Ties get broken randomly.
    pub fn worst_connected_peers(&self) -> Vec<(&PeerId, &PeerInfo)> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_connected())
            .sorted_by(|(_, info_a), (_, info_b)| info_a.score().total_cmp(info_b.score(), false))
            .collect::<Vec<_>>()
    }

    /// Returns a vector containing peers (their ids and info), sorted by
    /// score from highest to lowest, and filtered using `is_status`
    pub fn best_peers_by_status<F>(&self, is_status: F) -> Vec<(&PeerId, &PeerInfo)>
    where
        F: Fn(&PeerInfo) -> bool,
    {
        self.peers
            .iter()
            .filter(|(_, info)| is_status(info))
            .sorted_by(|(_, info_a), (_, info_b)| info_a.score().total_cmp(info_b.score(), true))
            .collect::<Vec<_>>()
    }

    /// Returns the peer with highest reputation that satisfies `is_status`
    pub fn best_by_status<F>(&self, is_status: F) -> Option<&PeerId>
    where
        F: Fn(&PeerInfo) -> bool,
    {
        self.peers
            .iter()
            .filter(|(_, info)| is_status(info))
            .max_by(|(_, info_a), (_, info_b)| info_a.score().total_cmp(info_b.score(), false))
            .map(|(id, _)| id)
    }

    /// Returns the peer's connection status. Returns unknown if the peer is not in the DB.
    pub fn connection_status(&self, peer_id: &PeerId) -> Option<PeerConnectionStatus> {
        self.peer_info(peer_id)
            .map(|info| info.connection_status().clone())
    }

    /* Mutability */

    /// Cleans up the connection state of dialing peers.
    // Libp2p dial's peerids, but sometimes the response is from another peer-id or libp2p
    // returns dial errors without a peer-id attached. This function reverts peers that have a
    // dialing status longer than DIAL_TIMEOUT seconds to a disconnected status. This is important because
    // we count the number of dialing peers in our inbound connections.
    pub fn cleanup_dialing_peers(&mut self) {
        let peers_to_disconnect: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(peer_id, info)| {
                if let PeerConnectionStatus::Dialing { since } = info.connection_status() {
                    if (*since) + std::time::Duration::from_secs(DIAL_TIMEOUT)
                        < std::time::Instant::now()
                    {
                        return Some(*peer_id);
                    }
                }
                None
            })
            .collect();

        for peer_id in peers_to_disconnect {
            self.update_connection_state(&peer_id, NewConnectionState::Disconnected);
        }
    }

    /// Allows the sync module to update sync status' of peers. Returns None, if the peer doesn't
    /// exist and returns Some(bool) representing if the sync state was modified.
    pub fn update_sync_status(
        &mut self,
        peer_id: &PeerId,
        sync_status: SyncStatus,
    ) -> Option<bool> {
        let info = self.peers.get_mut(peer_id)?;
        Some(info.update_sync_status(sync_status))
    }

    /// Updates the scores of known peers according to their connection status and the time that
    /// has passed. This function returns a list of peers that have been unbanned.
    /// NOTE: Peer scores cannot be penalized during the update, they can only increase. Therefore
    /// it not possible to ban peers when updating scores.
    #[must_use = "The unbanned peers must be sent to libp2p"]
    pub(super) fn update_scores(&mut self) -> Vec<(PeerId, ScoreUpdateResult)> {
        // Peer can be unbanned in this process.
        // We return the result, such that the peer manager can inform the swarm to lift the libp2p
        // ban on these peers.
        let mut peers_to_unban = Vec::new();
        let mut result = Vec::new();

        for (peer_id, info) in self.peers.iter_mut() {
            let previous_state = info.score_state();
            // Update scores
            info.score_update();

            match Self::handle_score_transition(previous_state, peer_id, info, &self.log) {
                // A peer should not be able to be banned from a score update.
                ScoreTransitionResult::Banned => {
                    error!(self.log, "Peer has been banned in an update"; "peer_id" => %peer_id)
                }
                // A peer should not be able to transition to a disconnected state from a healthy
                // state in a score update.
                ScoreTransitionResult::Disconnected => {
                    error!(self.log, "Peer has been disconnected in an update"; "peer_id" => %peer_id)
                }
                ScoreTransitionResult::Unbanned => {
                    peers_to_unban.push(*peer_id);
                }
                ScoreTransitionResult::NoAction => {}
            }
        }

        // Update the state in the peerdb
        for unbanned_peer in peers_to_unban {
            self.update_connection_state(&unbanned_peer, NewConnectionState::Unbanned);
            let seen_ip_addresses = self
                .peers
                .get(&unbanned_peer)
                .map(|info| {
                    info.seen_ip_addresses()
                        .filter(|ip| !self.is_ip_banned(ip))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            result.push((
                unbanned_peer,
                ScoreUpdateResult::Unbanned(seen_ip_addresses),
            ));
        }
        // Return the list so that the peer manager can update libp2p
        result
    }

    /// Updates gossipsub scores for all peers.
    #[must_use = "Score updates need to be reported to libp2p"]
    pub(super) fn update_gossipsub_scores(
        &mut self,
        target_peers: usize,
        gossipsub: &Gossipsub,
    ) -> Vec<(PeerId, ScoreUpdateResult)> {
        let mut actions = Vec::new();
        let mut results = Vec::new();

        let mut peers: Vec<_> = self
            .peers
            .iter_mut()
            .filter(|(_peer_id, info)| info.is_connected())
            .filter_map(|(peer_id, info)| {
                gossipsub
                    .peer_score(peer_id)
                    .map(|score| (peer_id, info, score))
            })
            .collect();

        // sort descending by score
        peers.sort_unstable_by(|(.., s1), (.., s2)| s2.partial_cmp(s1).unwrap_or(Ordering::Equal));

        let mut to_ignore_negative_peers =
            (target_peers as f32 * ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR).ceil() as usize;

        for (peer_id, info, score) in peers {
            let previous_state = info.score_state();
            info.update_gossipsub_score(
                score,
                if score < 0.0 && to_ignore_negative_peers > 0 {
                    to_ignore_negative_peers -= 1;
                    // We ignore the negative score for the best negative peers so that their
                    // gossipsub score can recover without getting disconnected.
                    true
                } else {
                    false
                },
            );

            actions.push((
                *peer_id,
                Self::handle_score_transition(previous_state, peer_id, info, &self.log),
            ));
        }

        for (peer_id, action) in actions {
            let result = match action {
                ScoreTransitionResult::Banned => {
                    // The peer was banned as a result of this action.
                    self.update_connection_state(&peer_id, NewConnectionState::Banned)
                        .into()
                }
                ScoreTransitionResult::Disconnected => {
                    // The peer needs to be disconnected

                    // Update the state
                    self.update_connection_state(
                        &peer_id,
                        NewConnectionState::Disconnecting { to_ban: false },
                    );
                    ScoreUpdateResult::Disconnect
                }
                ScoreTransitionResult::NoAction => ScoreUpdateResult::NoAction,
                ScoreTransitionResult::Unbanned => {
                    self.update_connection_state(&peer_id, NewConnectionState::Unbanned);
                    let seen_ip_addresses = self
                        .peers
                        .get(&peer_id)
                        .map(|info| {
                            info.seen_ip_addresses()
                                .filter(|ip| !self.is_ip_banned(ip))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    ScoreUpdateResult::Unbanned(seen_ip_addresses)
                }
            };

            // Actions to be handled by the peer manager for each peer id
            if !matches!(result, ScoreUpdateResult::NoAction) {
                results.push((peer_id, result));
            }
        }
        results
    }

    /// Reports a peer for some action.
    ///
    /// The action can only cause a negative effect. This can lead to disconnecting or banning a
    /// specific peer. Therefore the result of this function returns if the peer needs to be banned
    /// or disconnected.
    ///
    /// If the peer doesn't exist, log a warning and insert defaults.
    #[must_use = "Banned and disconnected peers need to be handled in libp2p"]
    pub(super) fn report_peer(
        &mut self,
        peer_id: &PeerId,
        action: PeerAction,
        source: ReportSource,
        msg: &'static str,
    ) -> ScoreUpdateResult {
        crate::common::metrics::inc_counter_vec(&metrics::REPORT_PEER_MSGS, &[msg]);

        match self.peers.get_mut(peer_id) {
            Some(info) => {
                let previous_state = info.score_state();
                info.apply_peer_action_to_score(action);
                crate::common::metrics::inc_counter_vec(
                    &metrics::PEER_ACTION_EVENTS_PER_CLIENT,
                    &[info.client().kind.as_ref(), action.as_ref(), source.into()],
                );
                let result =
                    Self::handle_score_transition(previous_state, peer_id, info, &self.log);
                if previous_state == info.score_state() {
                    debug!(
                        self.log,
                        "Peer score adjusted";
                        "msg" => %msg,
                        "peer_id" => %peer_id,
                        "score" => %info.score()
                    );
                }
                match result {
                    ScoreTransitionResult::Banned => {
                        // The peer was banned as a result of this action.
                        self.update_connection_state(peer_id, NewConnectionState::Banned)
                            .into()
                    }
                    ScoreTransitionResult::Disconnected => {
                        // The peer needs to be disconnected

                        // Update the state
                        self.update_connection_state(
                            peer_id,
                            NewConnectionState::Disconnecting { to_ban: false },
                        );
                        ScoreUpdateResult::Disconnect
                    }
                    ScoreTransitionResult::NoAction => ScoreUpdateResult::NoAction,
                    ScoreTransitionResult::Unbanned => {
                        error!(
                            self.log,
                            "Report peer action lead to an unbanning";
                            "msg" => %msg,
                            "peer_id" => %peer_id
                        );
                        ScoreUpdateResult::NoAction
                    }
                }
            }
            None => {
                debug!(
                    self.log,
                    "Reporting a peer that doesn't exist";
                    "msg" => %msg,
                    "peer_id" =>%peer_id
                );
                ScoreUpdateResult::NoAction
            }
        }
    }

    /// Update min ttl of a peer.
    // VISIBILITY: Only the peer manager can update the min_ttl
    pub(super) fn update_min_ttl(&mut self, peer_id: &PeerId, min_ttl: Instant) {
        let info = self.peers.entry(*peer_id).or_default();

        // only update if the ttl is longer
        if info.min_ttl().is_none() || Some(&min_ttl) > info.min_ttl() {
            info.set_min_ttl(min_ttl);

            let min_ttl_secs = min_ttl
                .checked_duration_since(Instant::now())
                .map(|duration| duration.as_secs())
                .unwrap_or_else(|| 0);
            debug!(self.log, "Updating the time a peer is required for"; "peer_id" => %peer_id, "future_min_ttl_secs" => min_ttl_secs);
        }
    }

    /// Adds a gossipsub subscription to a peer in the peerdb.
    // VISIBILITY: The behaviour is able to adjust subscriptions.
    pub(crate) fn add_subscription(&mut self, peer_id: &PeerId, subnet: Subnet) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.insert_subnet(subnet);
        }
    }

    /// Removes a gossipsub subscription to a peer in the peerdb.
    // VISIBILITY: The behaviour is able to adjust subscriptions.
    pub(crate) fn remove_subscription(&mut self, peer_id: &PeerId, subnet: &Subnet) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.remove_subnet(subnet);
        }
    }

    /// Extends the ttl of all peers on the given subnet that have a shorter
    /// min_ttl than what's given.
    // VISIBILITY: The behaviour is able to adjust subscriptions.
    pub(crate) fn extend_peers_on_subnet(&mut self, subnet: &Subnet, min_ttl: Instant) {
        let log = &self.log;
        self.peers.iter_mut()
            .filter(move |(_, info)| {
                info.is_connected() && info.on_subnet_metadata(subnet) && info.on_subnet_gossipsub(subnet)
            })
            .for_each(|(peer_id,info)| {
                if info.min_ttl().is_none() || Some(&min_ttl) > info.min_ttl() {
                    info.set_min_ttl(min_ttl);
                }
                let min_ttl_secs = min_ttl
                    .checked_duration_since(Instant::now())
                    .map(|duration| duration.as_secs())
                    .unwrap_or_else(|| 0);
                trace!(log, "Updating minimum duration a peer is required for"; "peer_id" => %peer_id, "min_ttl" => min_ttl_secs);
            });
    }

    /// A peer is being dialed.
    // VISIBILITY: Only the peer manager can adjust the connection state
    pub(super) fn dialing_peer(&mut self, peer_id: &PeerId, enr: Option<Enr>) {
        self.update_connection_state(peer_id, NewConnectionState::Dialing { enr });
    }

    /// Sets a peer as connected with an ingoing connection.
    // VISIBILITY: Only the peer manager can adjust the connection state.
    pub(super) fn connect_ingoing(
        &mut self,
        peer_id: &PeerId,
        seen_address: Multiaddr,
        enr: Option<Enr>,
    ) {
        self.update_connection_state(
            peer_id,
            NewConnectionState::Connected {
                enr,
                seen_address,
                direction: ConnectionDirection::Incoming,
            },
        );
    }

    /// Sets a peer as connected with an outgoing connection.
    // VISIBILITY: Only the peer manager can adjust the connection state.
    pub(super) fn connect_outgoing(
        &mut self,
        peer_id: &PeerId,
        seen_address: Multiaddr,
        enr: Option<Enr>,
    ) {
        self.update_connection_state(
            peer_id,
            NewConnectionState::Connected {
                enr,
                seen_address,
                direction: ConnectionDirection::Outgoing,
            },
        );
    }

    /// Updates the connection state. MUST ONLY BE USED IN TESTS.
    pub fn __add_connected_peer_testing_only(&mut self, supernode: bool) -> PeerId {
        let enr_key = CombinedKey::generate_secp256k1();
        let mut enr = Enr::builder().build(&enr_key).unwrap();
        let peer_id = enr.peer_id();

        if supernode {
            enr.insert(
                PEERDAS_CUSTODY_SUBNET_COUNT_ENR_KEY,
                &self.chain_config.data_column_sidecar_subnet_count,
                &enr_key,
            )
            .expect("u64 can be encoded");
        }

        self.update_connection_state(
            &peer_id,
            NewConnectionState::Connected {
                enr: Some(enr),
                seen_address: Multiaddr::empty(),
                direction: ConnectionDirection::Outgoing,
            },
        );

        if supernode {
            let peer_info = self.peers.get_mut(&peer_id).expect("peer exists");
            let all_subnets = (0..self.chain_config.data_column_sidecar_subnet_count)
                .map(|csc| csc.into())
                .collect();
            peer_info.set_custody_subnets(all_subnets);
        } else {
            let peer_info = self.peers.get_mut(&peer_id).expect("peer exists");
            let node_id = peer_id_to_node_id(&peer_id).expect("convert peer_id to node_id");
            let subnets =
                compute_custody_subnets(node_id.raw(), self.chain_config.custody_requirement)
                    .expect("should compute custody subnets")
                    .collect();
            peer_info.set_custody_subnets(subnets);
        }

        peer_id
    }

    /// The connection state of the peer has been changed. Modify the peer in the db to ensure all
    /// variables are in sync with libp2p.
    /// Updating the state can lead to a `BanOperation` which needs to be processed via the peer
    /// manager and should be handled in the peer manager.
    // NOTE: This function is vital in keeping the connection state, and thus the peerdb size in
    // check and up to date with libp2p.
    fn update_connection_state(
        &mut self,
        peer_id: &PeerId,
        new_state: NewConnectionState,
    ) -> Option<BanOperation> {
        let log_ref = &self.log;
        let info = self.peers.entry(*peer_id).or_insert_with(|| {
            // If we are not creating a new connection (or dropping a current inbound connection) log a warning indicating we are updating a
            // connection state for an unknown peer.
            if !matches!(
                new_state,
                NewConnectionState::Connected { .. }          // We have established a new connection (peer may not have been seen before)
                    | NewConnectionState::Disconnecting { .. }// We are disconnecting from a peer that may not have been registered before
                    | NewConnectionState::Dialing { .. }      // We are dialing a potentially new peer
                    | NewConnectionState::Disconnected // Dialing a peer that responds by a different ID can be immediately
                                                       // disconnected without having being stored in the db before
            ) {
                warn!(log_ref, "Updating state of unknown peer";
                    "peer_id" => %peer_id, "new_state" => ?new_state);
            }
            if self.disable_peer_scoring {
                PeerInfo::trusted_peer_info()
            } else {
                PeerInfo::default()
            }
        });

        // Ban the peer if the score is not already low enough.
        if matches!(new_state, NewConnectionState::Banned) {
            match info.score_state() {
                ScoreState::Banned => {}
                _ => {
                    // If score isn't low enough to ban, this function has been called incorrectly.
                    error!(self.log, "Banning a peer with a good score"; "peer_id" => %peer_id);
                    info.apply_peer_action_to_score(score::PeerAction::Fatal);
                }
            }
        }

        // Handle all the possible state changes
        match (info.connection_status().clone(), new_state) {
            /* CONNECTED
             *
             *
             * Handles the transition to a connected state
             */
            (
                current_state,
                NewConnectionState::Connected {
                    enr,
                    direction,
                    seen_address,
                },
            ) => {
                // Update the ENR if one exists, and compute the custody subnets
                if let Some(enr) = enr {
                    info.set_enr(enr);
                }

                match current_state {
                    PeerConnectionStatus::Disconnected { .. } => {
                        self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
                    }
                    PeerConnectionStatus::Banned { .. } => {
                        error!(self.log, "Accepted a connection from a banned peer"; "peer_id" => %peer_id);
                        // TODO: check if this happens and report the unban back
                        self.banned_peers_count
                            .remove_banned_peer(info.seen_ip_addresses());
                    }
                    PeerConnectionStatus::Disconnecting { .. } => {
                        warn!(self.log, "Connected to a disconnecting peer"; "peer_id" => %peer_id)
                    }
                    PeerConnectionStatus::Unknown
                    | PeerConnectionStatus::Connected { .. }
                    | PeerConnectionStatus::Dialing { .. } => {}
                }

                // Update the connection state
                match direction {
                    ConnectionDirection::Incoming => info.connect_ingoing(seen_address),
                    ConnectionDirection::Outgoing => info.connect_outgoing(seen_address),
                }
            }

            /* DIALING
             *
             *
             * Handles the transition to a dialing state
             */
            (old_state, NewConnectionState::Dialing { enr }) => {
                match old_state {
                    PeerConnectionStatus::Banned { .. } => {
                        warn!(self.log, "Dialing a banned peer"; "peer_id" => %peer_id);
                        self.banned_peers_count
                            .remove_banned_peer(info.seen_ip_addresses());
                    }
                    PeerConnectionStatus::Disconnected { .. } => {
                        self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
                    }
                    PeerConnectionStatus::Connected { .. } => {
                        warn!(self.log, "Dialing an already connected peer"; "peer_id" => %peer_id)
                    }
                    PeerConnectionStatus::Dialing { .. } => {
                        warn!(self.log, "Dialing an already dialing peer"; "peer_id" => %peer_id)
                    }
                    PeerConnectionStatus::Disconnecting { .. } => {
                        warn!(self.log, "Dialing a disconnecting peer"; "peer_id" => %peer_id)
                    }
                    PeerConnectionStatus::Unknown => {} // default behaviour
                }
                // Update the ENR if one is known.
                if let Some(enr) = enr {
                    info.set_enr(enr);
                }

                if let Err(e) = info.set_dialing_peer() {
                    error!(self.log, "{}", e; "peer_id" => %peer_id);
                }
            }

            /* DISCONNECTED
             *
             *
             * Handle the transition to the disconnected state
             */
            (old_state, NewConnectionState::Disconnected) => {
                // Remove all subnets for disconnected peers.
                info.clear_subnets();

                match old_state {
                    PeerConnectionStatus::Banned { .. } => {}
                    PeerConnectionStatus::Disconnected { .. } => {}
                    PeerConnectionStatus::Disconnecting { to_ban } if to_ban => {
                        // Update the status.
                        info.set_connection_status(PeerConnectionStatus::Banned {
                            since: Instant::now(),
                        });
                        self.banned_peers_count
                            .add_banned_peer(info.seen_ip_addresses());
                        let known_banned_ips = self.banned_peers_count.banned_ips();
                        let banned_ips = info
                            .seen_ip_addresses()
                            .filter(|ip| known_banned_ips.contains(ip))
                            .collect::<Vec<_>>();
                        return Some(BanOperation::ReadyToBan(banned_ips));
                    }
                    PeerConnectionStatus::Disconnecting { .. } => {
                        // The peer has been disconnected but not banned. Inform the peer manager
                        // that this peer could be eligible for a temporary ban.
                        self.disconnected_peers += 1;
                        info.set_connection_status(PeerConnectionStatus::Disconnected {
                            since: Instant::now(),
                        });
                        return Some(BanOperation::TemporaryBan);
                    }
                    PeerConnectionStatus::Unknown
                    | PeerConnectionStatus::Connected { .. }
                    | PeerConnectionStatus::Dialing { .. } => {
                        self.disconnected_peers += 1;
                        info.set_connection_status(PeerConnectionStatus::Disconnected {
                            since: Instant::now(),
                        });
                    }
                }
            }

            /* DISCONNECTING
             *
             *
             * Handles the transition to a disconnecting state
             */
            (PeerConnectionStatus::Banned { .. }, NewConnectionState::Disconnecting { to_ban }) => {
                error!(self.log, "Disconnecting from a banned peer"; "peer_id" => %peer_id);
                info.set_connection_status(PeerConnectionStatus::Disconnecting { to_ban });
            }
            (
                PeerConnectionStatus::Disconnected { .. },
                NewConnectionState::Disconnecting { to_ban },
            ) => {
                // If the peer was previously disconnected and is now being disconnected, decrease
                // the disconnected_peers counter.
                self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
                info.set_connection_status(PeerConnectionStatus::Disconnecting { to_ban });
            }
            (_, NewConnectionState::Disconnecting { to_ban }) => {
                // We overwrite all states and set this peer to be disconnecting.
                // NOTE: A peer can be in the disconnected state and transition straight to a
                // disconnected state. This occurs when a disconnected peer dials us, we have too
                // many peers and we transition them straight to the disconnecting state.
                info.set_connection_status(PeerConnectionStatus::Disconnecting { to_ban });
            }

            /* BANNED
             *
             *
             * Handles the transition to a banned state
             */
            (PeerConnectionStatus::Disconnected { .. }, NewConnectionState::Banned) => {
                // It is possible to ban a peer that is currently disconnected. This can occur when
                // there are many events that score it poorly and are processed after it has disconnected.
                info.set_connection_status(PeerConnectionStatus::Banned {
                    since: Instant::now(),
                });
                self.banned_peers_count
                    .add_banned_peer(info.seen_ip_addresses());
                self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
                let known_banned_ips = self.banned_peers_count.banned_ips();
                let banned_ips = info
                    .seen_ip_addresses()
                    .filter(|ip| known_banned_ips.contains(ip))
                    .collect::<Vec<_>>();
                return Some(BanOperation::ReadyToBan(banned_ips));
            }
            (PeerConnectionStatus::Disconnecting { .. }, NewConnectionState::Banned) => {
                // NOTE: This can occur due a rapid downscore of a peer. It goes through the
                // disconnection phase and straight into banning in a short time-frame.
                debug!(log_ref, "Banning peer that is currently disconnecting"; "peer_id" => %peer_id);
                // Ban the peer once the disconnection process completes.
                info.set_connection_status(PeerConnectionStatus::Disconnecting { to_ban: true });
                return Some(BanOperation::PeerDisconnecting);
            }
            (PeerConnectionStatus::Banned { .. }, NewConnectionState::Banned) => {
                error!(log_ref, "Banning already banned peer"; "peer_id" => %peer_id);
                let known_banned_ips = self.banned_peers_count.banned_ips();
                let banned_ips = info
                    .seen_ip_addresses()
                    .filter(|ip| known_banned_ips.contains(ip))
                    .collect::<Vec<_>>();
                return Some(BanOperation::ReadyToBan(banned_ips));
            }
            (
                PeerConnectionStatus::Connected { .. } | PeerConnectionStatus::Dialing { .. },
                NewConnectionState::Banned,
            ) => {
                // update the state
                info.set_connection_status(PeerConnectionStatus::Disconnecting { to_ban: true });
                return Some(BanOperation::DisconnectThePeer);
            }
            (PeerConnectionStatus::Unknown, NewConnectionState::Banned) => {
                // shift the peer straight to banned
                warn!(log_ref, "Banning a peer of unknown connection state"; "peer_id" => %peer_id);
                self.banned_peers_count
                    .add_banned_peer(info.seen_ip_addresses());
                info.set_connection_status(PeerConnectionStatus::Banned {
                    since: Instant::now(),
                });
                let known_banned_ips = self.banned_peers_count.banned_ips();
                let banned_ips = info
                    .seen_ip_addresses()
                    .filter(|ip| known_banned_ips.contains(ip))
                    .collect::<Vec<_>>();
                return Some(BanOperation::ReadyToBan(banned_ips));
            }

            /* UNBANNED
             *
             *
             * Handles the transition to an unbanned state
             */
            (old_state, NewConnectionState::Unbanned) => {
                if matches!(info.score_state(), ScoreState::Banned) {
                    error!(self.log, "Unbanning a banned peer"; "peer_id" => %peer_id);
                }
                match old_state {
                    PeerConnectionStatus::Unknown | PeerConnectionStatus::Connected { .. } => {
                        error!(self.log, "Unbanning a connected peer"; "peer_id" => %peer_id);
                    }
                    PeerConnectionStatus::Disconnected { .. }
                    | PeerConnectionStatus::Disconnecting { .. } => {
                        debug!(self.log, "Unbanning disconnected or disconnecting peer"; "peer_id" => %peer_id);
                    } // These are odd but fine.
                    PeerConnectionStatus::Dialing { .. } => {} // Also odd but acceptable
                    PeerConnectionStatus::Banned { since } => {
                        info.set_connection_status(PeerConnectionStatus::Disconnected { since });

                        // Increment the disconnected count and reduce the banned count
                        self.banned_peers_count
                            .remove_banned_peer(info.seen_ip_addresses());
                        self.disconnected_peers = self.disconnected_peers.saturating_add(1);
                    }
                }
            }
        }
        None
    }

    /// Sets the peer as disconnected. A banned peer remains banned. If the node has become banned,
    /// this returns true, otherwise this is false.
    // VISIBILITY: Only the peer manager can adjust the connection state.
    pub(super) fn inject_disconnect(
        &mut self,
        peer_id: &PeerId,
    ) -> (Option<BanOperation>, Vec<(PeerId, Vec<IpAddr>)>) {
        // A peer can be banned for disconnecting. Thus another peer could be purged
        let maybe_ban_op = self.update_connection_state(peer_id, NewConnectionState::Disconnected);
        let purged_peers = self.shrink_to_fit();
        (maybe_ban_op, purged_peers)
    }

    /// The peer manager has notified us that the peer is undergoing a normal disconnect. Optionally tag
    /// the peer to be banned after the disconnect.
    // VISIBILITY: Only the peer manager can adjust the connection state.
    pub(super) fn notify_disconnecting(&mut self, peer_id: &PeerId, to_ban: bool) {
        self.update_connection_state(peer_id, NewConnectionState::Disconnecting { to_ban });
    }

    /// Removes banned and disconnected peers from the DB if we have reached any of our limits.
    /// Drops the peers with the lowest reputation so that the number of disconnected peers is less
    /// than MAX_DC_PEERS
    #[must_use = "Unbanned peers need to be reported to libp2p."]
    fn shrink_to_fit(&mut self) -> Vec<(PeerId, Vec<IpAddr>)> {
        let excess_peers = self
            .banned_peers_count
            .banned_peers()
            .saturating_sub(MAX_BANNED_PEERS);
        let mut unbanned_peers = Vec::with_capacity(excess_peers);

        // Remove excess banned peers
        while self.banned_peers_count.banned_peers() > MAX_BANNED_PEERS {
            if let Some((to_drop, unbanned_ips)) = if let Some((id, info, _)) = self
                .peers
                .iter()
                .filter_map(|(id, info)| match info.connection_status() {
                    PeerConnectionStatus::Banned { since } => Some((id, info, since)),
                    _ => None,
                })
                .min_by_key(|(_, _, since)| *since)
            {
                self.banned_peers_count
                    .remove_banned_peer(info.seen_ip_addresses());
                let unbanned_ips = info
                    .seen_ip_addresses()
                    .filter(|ip| !self.is_ip_banned(ip))
                    .collect::<Vec<_>>();

                Some((*id, unbanned_ips))
            } else {
                // If there is no minimum, this is a coding error.
                crit!(
                    self.log,
                    "banned_peers > MAX_BANNED_PEERS despite no banned peers in db!"
                );
                // reset banned_peers this will also exit the loop
                self.banned_peers_count = BannedPeersCount::default();
                None
            } {
                debug!(self.log, "Removing old banned peer"; "peer_id" => %to_drop);
                self.peers.remove(&to_drop);
                unbanned_peers.push((to_drop, unbanned_ips))
            }
        }

        // Remove excess disconnected peers
        while self.disconnected_peers > MAX_DC_PEERS {
            if let Some(to_drop) = self
                .peers
                .iter()
                .filter(|(_, info)| info.is_disconnected() && !info.is_trusted())
                .filter_map(|(id, info)| match info.connection_status() {
                    PeerConnectionStatus::Disconnected { since } => Some((id, since)),
                    _ => None,
                })
                .min_by_key(|(_, age)| *age)
                .map(|(id, _)| *id)
            {
                debug!(self.log, "Removing old disconnected peer"; "peer_id" => %to_drop, "disconnected_size" => self.disconnected_peers.saturating_sub(1));
                self.peers.remove(&to_drop);
            }
            // If there is no minimum, this is a coding error. For safety we decrease
            // the count to avoid a potential infinite loop.
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }

        unbanned_peers
    }

    /// This handles score transitions between states. It transitions peers states from
    /// disconnected/banned/connected.
    fn handle_score_transition(
        previous_state: ScoreState,
        peer_id: &PeerId,
        info: &PeerInfo,
        log: &slog::Logger,
    ) -> ScoreTransitionResult {
        match (info.score_state(), previous_state) {
            (ScoreState::Banned, ScoreState::Healthy | ScoreState::ForcedDisconnect) => {
                debug!(log, "Peer has been banned"; "peer_id" => %peer_id, "score" => %info.score());
                ScoreTransitionResult::Banned
            }
            (ScoreState::ForcedDisconnect, ScoreState::Banned | ScoreState::Healthy) => {
                debug!(log, "Peer transitioned to forced disconnect score state"; "peer_id" => %peer_id, "score" => %info.score(), "past_score_state" => %previous_state);
                // disconnect the peer if it's currently connected or dialing
                if info.is_connected_or_dialing() {
                    ScoreTransitionResult::Disconnected
                } else if previous_state == ScoreState::Banned {
                    ScoreTransitionResult::Unbanned
                } else {
                    // The peer was healthy, but is already disconnected, so there is no action to
                    // take.
                    ScoreTransitionResult::NoAction
                }
            }
            (ScoreState::Healthy, ScoreState::ForcedDisconnect) => {
                debug!(log, "Peer transitioned to healthy score state"; "peer_id" => %peer_id, "score" => %info.score(), "past_score_state" => %previous_state);
                ScoreTransitionResult::NoAction
            }
            (ScoreState::Healthy, ScoreState::Banned) => {
                debug!(log, "Peer transitioned to healthy score state"; "peer_id" => %peer_id, "score" => %info.score(), "past_score_state" => %previous_state);
                // unban the peer if it was previously banned.
                ScoreTransitionResult::Unbanned
            }
            // Explicitly ignore states that haven't transitioned.
            (ScoreState::Healthy, ScoreState::Healthy) => ScoreTransitionResult::NoAction,
            (ScoreState::ForcedDisconnect, ScoreState::ForcedDisconnect) => {
                ScoreTransitionResult::NoAction
            }

            (ScoreState::Banned, ScoreState::Banned) => ScoreTransitionResult::NoAction,
        }
    }
}

/// Internal enum for managing connection state transitions.
#[derive(Debug)]
enum NewConnectionState {
    /// A peer has connected to us.
    Connected {
        /// An optional known ENR if the peer was dialed.
        enr: Option<Enr>,
        /// The seen socket address associated with the connection.
        seen_address: Multiaddr,
        /// The direction, incoming/outgoing.
        direction: ConnectionDirection,
    },
    /// The peer is in the process of being disconnected.
    Disconnecting {
        /// Whether the peer should be banned after the disconnect occurs.
        to_ban: bool,
    },
    /// We are dialing this peer.
    Dialing {
        /// An optional known ENR for the peer we are dialing.
        enr: Option<Enr>,
    },
    /// The peer has been disconnected from our local node.
    Disconnected,
    /// The peer has been banned and actions to shift the peer to the banned state should be
    /// undertaken
    Banned,
    /// The peer has been unbanned and the connection state should be updated to reflect this.
    Unbanned,
}

/// The result of applying a score transition to a peer.
enum ScoreTransitionResult {
    /// The peer has become disconnected.
    Disconnected,
    /// The peer has been banned.
    Banned,
    /// The peer has been unbanned.
    Unbanned,
    /// No state change occurred.
    NoAction,
}

/// The type of results that can happen from executing the `report_peer` function.
pub enum ScoreUpdateResult {
    /// The reported peer must be banned.
    Ban(BanOperation),
    ///  The reported peer transitioned to the disconnected state and must be disconnected.
    Disconnect,
    /// The peer has been unbanned and this needs to be propagated to libp2p. The list of unbanned
    /// IP addresses are sent along with it.
    Unbanned(Vec<IpAddr>),
    /// The report requires no further action.
    NoAction,
}

impl From<Option<BanOperation>> for ScoreUpdateResult {
    fn from(ban_operation: Option<BanOperation>) -> Self {
        match ban_operation {
            None => ScoreUpdateResult::NoAction,
            Some(bo) => ScoreUpdateResult::Ban(bo),
        }
    }
}

/// When attempting to ban a peer provides the peer manager with the operation that must be taken.
pub enum BanOperation {
    /// Optionally temporarily ban this peer to prevent instantaneous reconnection.
    /// The peer manager will decide if temporary banning is required.
    TemporaryBan,
    // The peer is currently connected. Perform a graceful disconnect before banning at the swarm
    // level.
    DisconnectThePeer,
    // The peer is disconnected, it has now been banned and can be banned at the swarm level. It
    // stores a collection of banned IP addresses to inform the swarm.
    ReadyToBan(Vec<IpAddr>),
    // The peer is currently being disconnected, nothing to do.
    PeerDisconnecting,
}

/// When checking if a peer is banned, it can be banned for multiple reasons.
#[derive(Copy, Clone, Debug)]
pub enum BanResult {
    /// The peer's score is too low causing it to be banned.
    BadScore,
    /// The peer should be banned because it is connecting from a banned IP address.
    BannedIp(IpAddr),
}

impl Display for BanResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BanResult::BadScore => write!(f, "Peer has a bad score"),
            BanResult::BannedIp(addr) => write!(f, "Peer address: {} is banned", addr),
        }
    }
}

impl std::error::Error for BanResult {}

#[derive(Default)]
pub struct BannedPeersCount {
    /// The number of banned peers in the database.
    banned_peers: usize,
    /// maps ips to number of banned peers with this ip
    banned_peers_per_ip: HashMap<IpAddr, usize>,
}

impl BannedPeersCount {
    /// Removes the peer from the counts if it is banned. Returns true if the peer was banned and
    /// false otherwise.
    pub fn remove_banned_peer(&mut self, ip_addresses: impl Iterator<Item = IpAddr>) {
        self.banned_peers = self.banned_peers.saturating_sub(1);
        for address in ip_addresses {
            if let Some(count) = self.banned_peers_per_ip.get_mut(&address) {
                *count = count.saturating_sub(1);
            }
        }
    }

    pub fn add_banned_peer(&mut self, ip_addresses: impl Iterator<Item = IpAddr>) {
        self.banned_peers = self.banned_peers.saturating_add(1);
        for address in ip_addresses {
            *self.banned_peers_per_ip.entry(address).or_insert(0) += 1;
        }
    }

    pub fn banned_peers(&self) -> usize {
        self.banned_peers
    }

    pub fn banned_ips(&self) -> HashSet<IpAddr> {
        self.banned_peers_per_ip
            .iter()
            .filter(|(_ip, count)| **count > BANNED_PEERS_PER_IP_THRESHOLD)
            .map(|(ip, _count)| *ip)
            .collect()
    }

    /// An IP is considered banned if more than BANNED_PEERS_PER_IP_THRESHOLD banned peers
    /// exist with this IP
    pub fn ip_is_banned(&self, ip: &IpAddr) -> bool {
        self.banned_peers_per_ip
            .get(ip)
            .is_some_and(|count| *count > BANNED_PEERS_PER_IP_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::multiaddr::Protocol;
    use slog::{o, Drain};
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    fn add_score(db: &mut PeerDB, peer_id: &PeerId, score: f64) {
        if let Some(info) = db.peer_info_mut(peer_id) {
            info.add_to_score(score);
        }
    }

    fn reset_score(db: &mut PeerDB, peer_id: &PeerId) {
        if let Some(info) = db.peer_info_mut(peer_id) {
            info.reset_score();
        }
    }

    fn get_db() -> PeerDB {
        let log = build_log(slog::Level::Debug, false);
        let config = Arc::new(ChainConfig::mainnet());
        PeerDB::new(config, vec![], false, &log)
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_peer_connected_successfully() {
        let mut pdb = get_db();
        let random_peer = PeerId::random();

        let (n_in, n_out) = (10, 20);
        for _ in 0..n_in {
            pdb.connect_ingoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        }
        for _ in 0..n_out {
            pdb.connect_outgoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        }

        // the peer is known
        let peer_info = pdb.peer_info(&random_peer);
        assert!(peer_info.is_some());
        // this is the only peer
        assert_eq!(pdb.peers().count(), 1);
        // the peer has the default reputation
        assert_eq!(pdb.score(&random_peer), Score::default().score());
        // it should be connected, and therefore not counted as disconnected
        assert_eq!(pdb.disconnected_peers, 0);
        assert!(peer_info.unwrap().is_connected());
        assert_eq!(peer_info.unwrap().connections(), (n_in, n_out));
    }

    #[test]
    fn test_outbound_only_peers_counted_correctly() {
        let mut pdb = get_db();
        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        // Create peer with no connections.
        let _p3 = PeerId::random();

        pdb.connect_ingoing(&p0, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_outgoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_outgoing(&p2, "/ip4/0.0.0.0".parse().unwrap(), None);

        // We should only have one outbound-only peer (p2).
        // Peers that are inbound-only, have both types of connections, or no connections should not be counted.
        assert_eq!(pdb.connected_outbound_only_peers().count(), 1);
    }

    #[test]
    fn test_disconnected_removed_in_correct_order() {
        let mut pdb = get_db();

        use std::collections::BTreeMap;
        let mut peer_list = BTreeMap::new();
        for id in 0..MAX_DC_PEERS + 1 {
            let new_peer = PeerId::random();
            pdb.connect_ingoing(&new_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
            peer_list.insert(id, new_peer);
        }
        assert_eq!(pdb.disconnected_peers, 0);

        for (_, p) in peer_list.iter() {
            pdb.inject_disconnect(p);
            // Allow the timing to update correctly
        }
        assert_eq!(pdb.disconnected_peers, MAX_DC_PEERS);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        // Only the oldest peer should have been removed
        for (id, peer_id) in peer_list.iter().rev().take(MAX_DC_PEERS) {
            println!("Testing id {}", id);
            assert!(
                pdb.peer_info(peer_id).is_some(),
                "Latest peer should not be pruned"
            );
        }

        assert!(
            pdb.peer_info(peer_list.iter().next().unwrap().1).is_none(),
            "First peer should be removed"
        );
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
    }

    #[test]
    fn new_connection_should_remain() {
        let mut pdb = get_db();

        use std::collections::BTreeMap;
        let mut peer_list = BTreeMap::new();
        for id in 0..MAX_DC_PEERS + 20 {
            let new_peer = PeerId::random();
            pdb.connect_ingoing(&new_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
            peer_list.insert(id, new_peer);
        }
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        for (_, p) in peer_list.iter() {
            pdb.inject_disconnect(p);
        }
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        println!("{}", pdb.disconnected_peers);

        peer_list.clear();
        for id in 0..MAX_DC_PEERS + 20 {
            let new_peer = PeerId::random();
            pdb.connect_ingoing(&new_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
            peer_list.insert(id, new_peer);
        }

        let new_peer = PeerId::random();
        // New peer gets its min_ttl updated because it exists on a subnet
        let min_ttl = Instant::now() + std::time::Duration::from_secs(12);

        pdb.update_min_ttl(&new_peer, min_ttl);
        // Peer then gets dialed
        pdb.dialing_peer(&new_peer, None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        // Dialing fails, remove the peer
        pdb.inject_disconnect(&new_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        assert!(
            pdb.peer_info(&new_peer).is_some(),
            "Peer should exist as disconnected"
        );

        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        println!("{}", pdb.disconnected_peers);
    }

    #[test]
    fn test_disconnected_are_bounded() {
        let mut pdb = get_db();

        for _ in 0..MAX_DC_PEERS + 1 {
            let p = PeerId::random();
            pdb.connect_ingoing(&p, "/ip4/0.0.0.0".parse().unwrap(), None);
        }
        assert_eq!(pdb.disconnected_peers, 0);

        for p in pdb.connected_peer_ids().cloned().collect::<Vec<_>>() {
            pdb.inject_disconnect(&p);
        }
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        assert_eq!(pdb.disconnected_peers, MAX_DC_PEERS);
    }

    #[test]
    fn test_banned_are_bounded() {
        let mut pdb = get_db();

        for _ in 0..MAX_BANNED_PEERS + 1 {
            let p = PeerId::random();
            pdb.connect_ingoing(&p, "/ip4/0.0.0.0".parse().unwrap(), None);
        }
        assert_eq!(pdb.banned_peers_count.banned_peers(), 0);

        for p in pdb.connected_peer_ids().cloned().collect::<Vec<_>>() {
            let _ = pdb.report_peer(&p, PeerAction::Fatal, ReportSource::PeerManager, "");
            pdb.inject_disconnect(&p);
        }

        assert_eq!(pdb.banned_peers_count.banned_peers(), MAX_BANNED_PEERS);
    }

    #[test]
    fn test_best_peers() {
        let mut pdb = get_db();

        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        pdb.connect_ingoing(&p0, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p2, "/ip4/0.0.0.0".parse().unwrap(), None);
        add_score(&mut pdb, &p0, 70.0);
        add_score(&mut pdb, &p1, 100.0);
        add_score(&mut pdb, &p2, 50.0);

        let best_peers: Vec<&PeerId> = pdb
            .best_peers_by_status(PeerInfo::is_connected)
            .iter()
            .map(|p| p.0)
            .collect();
        assert_eq!(vec![&p1, &p0, &p2], best_peers);
    }

    #[test]
    fn test_the_best_peer() {
        let mut pdb = get_db();

        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        pdb.connect_ingoing(&p0, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p2, "/ip4/0.0.0.0".parse().unwrap(), None);
        add_score(&mut pdb, &p0, 70.0);
        add_score(&mut pdb, &p1, 100.0);
        add_score(&mut pdb, &p2, 50.0);

        let the_best = pdb.best_by_status(PeerInfo::is_connected);
        assert!(the_best.is_some());
        // Consistency check
        let best_peers = pdb.best_peers_by_status(PeerInfo::is_connected);
        assert_eq!(the_best.unwrap(), best_peers.first().unwrap().0);
    }

    #[test]
    fn test_disconnected_consistency() {
        let mut pdb = get_db();

        let random_peer = PeerId::random();

        pdb.connect_ingoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        pdb.connect_ingoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.inject_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        pdb.connect_outgoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.inject_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        let _ = pdb.report_peer(
            &random_peer,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        pdb.inject_disconnect(&random_peer);
        let _ = pdb.report_peer(
            &random_peer,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.inject_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        pdb.inject_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.inject_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
    }

    #[test]
    fn test_disconnected_ban_consistency() {
        let mut pdb = get_db();
        let mut multiaddr = Multiaddr::empty();
        multiaddr.push(Protocol::Tcp(9000));
        multiaddr.push(Protocol::Ip4("0.0.0.0".parse().unwrap()));

        let random_peer = PeerId::random();
        let random_peer1 = PeerId::random();
        let random_peer2 = PeerId::random();
        let random_peer3 = PeerId::random();
        println!("{}", random_peer);
        println!("{}", random_peer1);
        println!("{}", random_peer2);
        println!("{}", random_peer3);

        // All 4 peers connected on the same IP
        pdb.connect_ingoing(&random_peer, multiaddr.clone(), None);
        pdb.connect_ingoing(&random_peer1, multiaddr.clone(), None);
        pdb.connect_ingoing(&random_peer2, multiaddr.clone(), None);
        pdb.connect_ingoing(&random_peer3, multiaddr.clone(), None);

        // Should be no disconnected or banned peers
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers_by_score().count()
        );

        // Should be no disconnected peers
        println!(
            "1:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        // Disconnect one peer
        pdb.inject_disconnect(&random_peer1);
        // Should be 1 disconnected peer
        println!(
            "2:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        // Disconnect and ban peer 2
        let _ = pdb.report_peer(
            &random_peer2,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        // Should be 1 disconnected peer and one peer in the process of being disconnected
        println!(
            "3:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        // The peer is now disconnected and banned
        pdb.inject_disconnect(&random_peer2);
        // There should be 2 disconnected peers.
        println!(
            "4:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        // Now that the peer is disconnected, register the ban.
        let _ = pdb.report_peer(
            &random_peer2,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        // There should be 1 disconnected peer and one banned peer.
        println!(
            "5:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        // Re-connect peer3, should have no effect
        pdb.connect_ingoing(&random_peer3, multiaddr.clone(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );
        // Now ban peer 1.
        let _ = pdb.report_peer(
            &random_peer1,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        // There should be no disconnected peers and 2 banned peers
        println!(
            "6:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        // This should have no effect
        pdb.inject_disconnect(&random_peer1);
        // Should still be no disconnected peers and 2 banned peers
        println!(
            "7:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        // Same thing here.
        let _ = pdb.report_peer(
            &random_peer1,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        println!(
            "8:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        println!(
            "{}, {:?}, {}",
            pdb.disconnected_peers,
            pdb.disconnected_peers().collect::<Vec<_>>(),
            pdb.banned_peers_count.banned_peers
        );
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        // Try and reconnect banned peer 2.
        pdb.connect_outgoing(&random_peer2, multiaddr.clone(), None);
        pdb.peer_info_mut(&random_peer2)
            .unwrap()
            .add_to_score(100.0);
        // This removes the banned peer and should give us 0 disconnected, 1 banned peer
        // (peer1)
        println!(
            "9:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );

        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        // Ban peer 3
        let _ = pdb.report_peer(
            &random_peer3,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        pdb.inject_disconnect(&random_peer3);

        // This should add a new banned peer, there should be 0 disconnected and 2 banned
        // peers (peer1 and peer3)
        println!(
            "10:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );

        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        // Ban peer 3
        let _ = pdb.report_peer(
            &random_peer3,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        pdb.inject_disconnect(&random_peer3);

        // Should still have 2 banned peers
        println!(
            "11:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );

        // Unban peer 1
        pdb.connect_ingoing(&random_peer1, multiaddr.clone(), None);
        pdb.peer_info_mut(&random_peer1)
            .unwrap()
            .add_to_score(100.0);
        // Should have 1 banned peer (peer 3)
        println!(
            "12:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );

        // Disconnect peer 2
        pdb.inject_disconnect(&random_peer2);

        // Should have 1 disconnect (peer 2) and one banned (peer 3)
        println!(
            "12:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );

        // Ban peer 3
        let _ = pdb.report_peer(
            &random_peer3,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        pdb.inject_disconnect(&random_peer3);

        // Should have 1 disconnect (peer 2) and one banned (peer 3)
        println!(
            "13:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );

        // Add peer 0
        pdb.connect_ingoing(&random_peer, multiaddr, None);
        pdb.peer_info_mut(&random_peer).unwrap().add_to_score(100.0);

        // Should have 1 disconnect (peer 2) and one banned (peer 3)
        println!(
            "14:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        // Disconnect peer 0
        pdb.inject_disconnect(&random_peer);
        // Should have 2 disconnect (peer 0, peer 2) and one banned (peer 3)
        println!(
            "15:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        // Disconnect peer 0
        pdb.inject_disconnect(&random_peer);
        // Should have 2 disconnect (peer 0, peer 2) and one banned (peer 3)
        println!(
            "16:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        // Ban peer 0
        let _ = pdb.report_peer(
            &random_peer,
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        pdb.inject_disconnect(&random_peer);

        // Should have 1 disconnect ( peer 2) and two banned (peer0, peer 3)
        println!(
            "17:{},{}",
            pdb.disconnected_peers, pdb.banned_peers_count.banned_peers
        );
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
    }

    fn connect_peer_with_ips(pdb: &mut PeerDB, ips: Vec<IpAddr>) -> PeerId {
        let p = PeerId::random();

        for ip in ips {
            let mut addr = Multiaddr::empty();
            addr.push(Protocol::from(ip));
            addr.push(Protocol::Tcp(9000));
            pdb.connect_ingoing(&p, addr, None);
        }
        p
    }

    #[test]
    fn test_ban_address() {
        let mut pdb = get_db();

        let ip1 = Ipv4Addr::new(1, 2, 3, 4).into();
        let ip2 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8).into();
        let ip3 = Ipv4Addr::new(1, 2, 3, 5).into();
        let ip4 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 9).into();
        let ip5 = Ipv4Addr::new(2, 2, 3, 4).into();

        let mut peers = Vec::new();
        for i in 0..BANNED_PEERS_PER_IP_THRESHOLD + 2 {
            peers.push(connect_peer_with_ips(
                &mut pdb,
                if i == 0 {
                    vec![ip1, ip2]
                } else {
                    vec![ip1, ip2, ip3, ip4]
                },
            ));
        }

        let p1 = connect_peer_with_ips(&mut pdb, vec![ip1]);
        let p2 = connect_peer_with_ips(&mut pdb, vec![ip2, ip5]);
        let p3 = connect_peer_with_ips(&mut pdb, vec![ip3, ip5]);
        let p4 = connect_peer_with_ips(&mut pdb, vec![ip5, ip4]);
        let p5 = connect_peer_with_ips(&mut pdb, vec![ip5]);

        for p in &peers[..BANNED_PEERS_PER_IP_THRESHOLD + 1] {
            let _ = pdb.report_peer(p, PeerAction::Fatal, ReportSource::PeerManager, "");
            pdb.inject_disconnect(p);
        }

        //check that ip1 and ip2 are banned but ip3-5 not
        assert!(pdb.ban_status(&p1).is_some());
        assert!(pdb.ban_status(&p2).is_some());
        assert!(pdb.ban_status(&p3).is_none());
        assert!(pdb.ban_status(&p4).is_none());
        assert!(pdb.ban_status(&p5).is_none());

        //ban also the last peer in peers
        let _ = pdb.report_peer(
            &peers[BANNED_PEERS_PER_IP_THRESHOLD + 1],
            PeerAction::Fatal,
            ReportSource::PeerManager,
            "",
        );
        pdb.inject_disconnect(&peers[BANNED_PEERS_PER_IP_THRESHOLD + 1]);

        //check that ip1-ip4 are banned but ip5 not
        assert!(pdb.ban_status(&p1).is_some());
        assert!(pdb.ban_status(&p2).is_some());
        assert!(pdb.ban_status(&p3).is_some());
        assert!(pdb.ban_status(&p4).is_some());
        assert!(pdb.ban_status(&p5).is_none());

        //peers[0] gets unbanned
        reset_score(&mut pdb, &peers[0]);
        pdb.update_connection_state(&peers[0], NewConnectionState::Unbanned);
        let _ = pdb.shrink_to_fit();

        //nothing changed
        assert!(pdb.ban_status(&p1).is_some());
        assert!(pdb.ban_status(&p2).is_some());
        assert!(pdb.ban_status(&p3).is_some());
        assert!(pdb.ban_status(&p4).is_some());
        assert!(pdb.ban_status(&p5).is_none());

        //peers[1] gets unbanned
        reset_score(&mut pdb, &peers[1]);
        pdb.update_connection_state(&peers[1], NewConnectionState::Unbanned);
        let _ = pdb.shrink_to_fit();

        //all ips are unbanned
        assert!(pdb.ban_status(&p1).is_none());
        assert!(pdb.ban_status(&p2).is_none());
        assert!(pdb.ban_status(&p3).is_none());
        assert!(pdb.ban_status(&p4).is_none());
        assert!(pdb.ban_status(&p5).is_none());
    }

    #[test]
    fn test_banned_ip_consistent_after_changing_ips() {
        let mut pdb = get_db();

        let ip1: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let ip2: IpAddr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8).into();

        let mut peers = Vec::new();
        for _ in 0..BANNED_PEERS_PER_IP_THRESHOLD + 1 {
            peers.push(connect_peer_with_ips(&mut pdb, vec![ip1]));
        }

        let p1 = connect_peer_with_ips(&mut pdb, vec![ip1]);
        let p2 = connect_peer_with_ips(&mut pdb, vec![ip2]);

        // ban all peers
        for p in &peers {
            let _ = pdb.report_peer(p, PeerAction::Fatal, ReportSource::PeerManager, "");
            pdb.inject_disconnect(p);
        }

        // check ip is banned
        assert!(pdb.ban_status(&p1).is_some());
        assert!(pdb.ban_status(&p2).is_none());

        // unban a peer
        reset_score(&mut pdb, &peers[0]);
        pdb.update_connection_state(&peers[0], NewConnectionState::Unbanned);
        let _ = pdb.shrink_to_fit();

        // check not banned anymore
        assert!(pdb.ban_status(&p1).is_none());
        assert!(pdb.ban_status(&p2).is_none());

        // unban all peers
        for p in &peers {
            reset_score(&mut pdb, p);
            pdb.update_connection_state(p, NewConnectionState::Unbanned);
            let _ = pdb.shrink_to_fit();
        }

        // add ip2 to all peers and ban them.
        let mut socker_addr = Multiaddr::from(ip2);
        socker_addr.push(Protocol::Tcp(8080));
        for p in &peers {
            pdb.connect_ingoing(p, socker_addr.clone(), None);
            let _ = pdb.report_peer(p, PeerAction::Fatal, ReportSource::PeerManager, "");
            pdb.inject_disconnect(p);
        }

        // both IP's are now banned
        assert!(pdb.ban_status(&p1).is_some());
        assert!(pdb.ban_status(&p2).is_some());

        // unban all peers
        for p in &peers {
            reset_score(&mut pdb, p);
            pdb.update_connection_state(p, NewConnectionState::Unbanned);
            let _ = pdb.shrink_to_fit();
        }

        // reban every peer except one
        for p in &peers[1..] {
            let _ = pdb.report_peer(p, PeerAction::Fatal, ReportSource::PeerManager, "");
            pdb.inject_disconnect(p);
        }

        // nothing is banned
        assert!(pdb.ban_status(&p1).is_none());
        assert!(pdb.ban_status(&p2).is_none());

        // reban last peer
        let _ = pdb.report_peer(&peers[0], PeerAction::Fatal, ReportSource::PeerManager, "");
        pdb.inject_disconnect(&peers[0]);

        //Ip's are banned again
        assert!(pdb.ban_status(&p1).is_some());
        assert!(pdb.ban_status(&p2).is_some());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_trusted_peers_score() {
        let trusted_peer = PeerId::random();
        let log = build_log(slog::Level::Debug, false);
        let chain_config = Arc::new(ChainConfig::mainnet());
        let mut pdb: PeerDB = PeerDB::new(chain_config, vec![trusted_peer], false, &log);

        pdb.connect_ingoing(&trusted_peer, "/ip4/0.0.0.0".parse().unwrap(), None);

        // Check trusted status and score
        assert!(pdb.peer_info(&trusted_peer).unwrap().is_trusted());
        assert_eq!(
            pdb.peer_info(&trusted_peer).unwrap().score().score(),
            Score::max_score().score()
        );

        // Adding/Subtracting score should have no effect on a trusted peer
        add_score(&mut pdb, &trusted_peer, -50.0);

        assert_eq!(
            pdb.peer_info(&trusted_peer).unwrap().score().score(),
            Score::max_score().score()
        );
    }

    #[test]
    fn test_disable_peer_scoring() {
        let peer = PeerId::random();
        let log = build_log(slog::Level::Debug, false);
        let chain_config = Arc::new(ChainConfig::mainnet());
        let mut pdb: PeerDB = PeerDB::new(chain_config, vec![], true, &log);

        pdb.connect_ingoing(&peer, "/ip4/0.0.0.0".parse().unwrap(), None);

        // Check trusted status and score
        assert!(pdb.peer_info(&peer).unwrap().is_trusted());
        assert_eq!(
            pdb.peer_info(&peer).unwrap().score().score(),
            Score::max_score().score()
        );

        // Adding/Subtracting score should have no effect on a trusted peer
        add_score(&mut pdb, &peer, -50.0);

        assert_eq!(
            pdb.peer_info(&peer).unwrap().score().score(),
            Score::max_score().score()
        );
    }
}
