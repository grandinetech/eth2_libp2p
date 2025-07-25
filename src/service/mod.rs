use self::gossip_cache::GossipCache;
use crate::config::{gossipsub_config, GossipsubConfigParams, NetworkLoad};
use crate::discovery::{
    subnet_predicate, DiscoveredPeers, Discovery, FIND_NODE_QUERY_CLOSEST_PEERS,
};
use crate::peer_manager::{
    config::Config as PeerManagerCfg, peerdb::score::PeerAction, peerdb::score::ReportSource,
    ConnectionDirection, PeerManager, PeerManagerEvent,
};
use crate::peer_manager::{MIN_OUTBOUND_ONLY_FACTOR, PEER_EXCESS_FACTOR, PRIORITY_PEER_EXCESS};
use crate::rpc::methods::MetadataRequest;
use crate::rpc::{
    GoodbyeReason, HandlerErr, InboundRequestId, NetworkParams, Protocol, RPCError, RPCMessage,
    RPCReceived, RequestType, ResponseTermination, RpcResponse, RpcSuccessResponse, RPC,
};
use crate::types::{
    attestation_sync_committee_topics, fork_core_topics, subnet_from_topic_hash, EnrForkId,
    ForkContext, GossipEncoding, GossipKind, GossipTopic, SnappyTransform, Subnet, SubnetDiscovery,
    ALTAIR_CORE_TOPICS, BASE_CORE_TOPICS, CAPELLA_CORE_TOPICS, LIGHT_CLIENT_GOSSIP_TOPICS,
};
use crate::EnrExt;
use crate::{metrics, Enr, NetworkGlobals, PubsubMessage, TopicHash};
use crate::{task_executor, Eth2Enr};
use anyhow::{anyhow, Error, Result};
use api_types::{AppRequestId, Response};
use futures::stream::StreamExt;
use gossipsub::{
    IdentTopic as Topic, MessageAcceptance, MessageAuthenticity, MessageId, PublishError,
    TopicScoreParams,
};
use gossipsub_scoring_parameters::{peer_gossip_thresholds, PeerScoreSettings};
use libp2p::multiaddr::{self, Multiaddr, Protocol as MProtocol};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::upnp::tokio::Behaviour as Upnp;
use libp2p::{identify, PeerId, SwarmBuilder};
use slog::{crit, debug, error, info, o, trace, warn};
use std::num::{NonZeroU8, NonZeroUsize};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::usize;
use std_ext::ArcExt as _;
use typenum::Unsigned as _;

use types::{
    altair::consts::SyncCommitteeSubnetCount,
    config::Config as ChainConfig,
    nonstandard::Phase,
    phase0::{
        consts::{AttestationSubnetCount, FAR_FUTURE_EPOCH},
        primitives::{ForkDigest, Slot},
    },
    preset::Preset,
};
use utils::{build_transport, strip_peer_id, Context as ServiceContext};

pub mod api_types;
mod gossip_cache;
pub mod gossipsub_scoring_parameters;
pub mod utils;

const MAX_IDENTIFY_ADDRESSES: usize = 10;

/// The types of events than can be obtained from polling the behaviour.
#[derive(Debug)]
pub enum NetworkEvent<P: Preset> {
    /// We have successfully dialed and connected to a peer.
    PeerConnectedOutgoing(PeerId),
    /// A peer has successfully dialed and connected to us.
    PeerConnectedIncoming(PeerId),
    /// A peer has disconnected.
    PeerDisconnected(PeerId),
    /// An RPC Request that was sent failed.
    RPCFailed {
        /// The id of the failed request.
        app_request_id: AppRequestId,
        /// The peer to which this request was sent.
        peer_id: PeerId,
        /// The error of the failed request.
        error: RPCError,
    },
    RequestReceived {
        /// The peer that sent the request.
        peer_id: PeerId,
        /// Identifier of the request. All responses to this request must use this id.
        inbound_request_id: InboundRequestId,
        /// Request the peer sent.
        request_type: RequestType<P>,
    },
    ResponseReceived {
        /// Peer that sent the response.
        peer_id: PeerId,
        /// Id of the request to which the peer is responding.
        app_request_id: AppRequestId,
        /// Response the peer sent.
        response: Response<P>,
    },
    PubsubMessage {
        /// The gossipsub message id. Used when propagating blocks after validation.
        id: MessageId,
        /// The peer from which we received this message, not the peer that published it.
        source: PeerId,
        /// The topic that this message was sent on.
        topic: TopicHash,
        /// The message itself.
        message: PubsubMessage<P>,
    },
    /// Inform the network to send a Status to this peer.
    StatusPeer(PeerId),
    NewListenAddr(Multiaddr),
    ZeroListeners,
}

pub type Gossipsub = gossipsub::Behaviour<SnappyTransform, SubscriptionFilter>;
pub type SubscriptionFilter =
    gossipsub::MaxCountSubscriptionFilter<gossipsub::WhitelistSubscriptionFilter>;

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour<P>
where
    P: Preset,
{
    // NOTE: The order of the following list of behaviours has meaning,
    // `NetworkBehaviour::handle_{pending, established}_{inbound, outbound}` methods
    // are called sequentially for each behaviour and they are fallible,
    // therefore we want `connection_limits` and `peer_manager` running first,
    // which are the behaviours that may reject a connection, so that
    // when the subsequent behaviours are called they are certain the connection won't be rejected.

    //
    /// Keep track of active and pending connections to enforce hard limits.
    pub connection_limits: libp2p::connection_limits::Behaviour,
    /// The peer manager that keeps track of peer's reputation and status.
    pub peer_manager: PeerManager,
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub eth2_rpc: RPC<AppRequestId, P>,
    /// Discv5 Discovery protocol.
    pub discovery: Discovery,
    /// Keep regular connection to peers and disconnect if absent.
    // NOTE: The id protocol is used for initial interop. This will be removed by mainnet.
    /// Provides IP addresses and peer information.
    pub identify: identify::Behaviour,
    /// Libp2p UPnP port mapping.
    pub upnp: Toggle<Upnp>,
    /// The routing pub-sub mechanism for eth2.
    pub gossipsub: Gossipsub,
}

/// Builds the network behaviour that manages the core protocols of eth2.
/// This core behaviour is managed by `Behaviour` which adds peer management to all core
/// behaviours.
pub struct Network<P: Preset> {
    swarm: libp2p::swarm::Swarm<Behaviour<P>>,
    /* Auxiliary Fields */
    /// A collections of variables accessible outside the network service.
    network_globals: Arc<NetworkGlobals>,
    /// Keeps track of the current EnrForkId for upgrading gossipsub topics.
    // NOTE: This can be accessed via the network_globals ENR. However we keep it here for quick
    // lookups for every gossipsub message send.
    enr_fork_id: EnrForkId,
    /// Directory where metadata is stored. `None` indicates in-memory mode.
    network_dir: Option<PathBuf>,
    fork_context: Arc<ForkContext>,
    /// Gossipsub score parameters.
    score_settings: PeerScoreSettings<P>,
    /// The interval for updating gossipsub scores
    update_gossipsub_scores: tokio::time::Interval,
    gossip_cache: GossipCache,
    /// This node's PeerId.
    pub local_peer_id: PeerId,
    /// Logger for behaviour actions.
    log: slog::Logger,
}

/// Implements the combined behaviour for the libp2p service.
impl<P: Preset> Network<P> {
    pub async fn new(
        chain_config: Arc<ChainConfig>,
        executor: task_executor::TaskExecutor,
        mut ctx: ServiceContext<'_>,
        log: &slog::Logger,
    ) -> Result<(Self, Arc<NetworkGlobals>)> {
        let log = log.new(o!("service"=> "libp2p"));

        let config = ctx.config.clone();
        trace!(log, "Libp2p Service starting");
        // initialise the node's ID
        let local_keypair = utils::load_private_key(&config, &log);

        // Trusted peers will also be marked as explicit in GossipSub.
        // Cfr. https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md#explicit-peering-agreements
        let trusted_peers: Vec<PeerId> = config
            .trusted_peers
            .iter()
            .map(|x| PeerId::from(x.clone()))
            .collect();

        // set up a collection of variables accessible outside of the network crate
        // Create an ENR or load from disk if appropriate
        let enr = crate::discovery::enr::build_or_load_enr::<P>(
            &chain_config,
            local_keypair.clone(),
            &config,
            &ctx.enr_fork_id,
            &log,
        )?;

        // construct the metadata
        let custody_subnet_count = chain_config.is_eip7594_fork_epoch_set().then(|| {
            if config.subscribe_all_data_column_subnets {
                chain_config.data_column_sidecar_subnet_count
            } else {
                chain_config.custody_requirement
            }
        });

        // Construct the metadata
        let meta_data = utils::load_or_build_metadata(
            config.network_dir.as_deref(),
            custody_subnet_count,
            &log,
        );
        let seq_number = meta_data.seq_number();
        let globals = NetworkGlobals::new(
            chain_config.clone_arc(),
            enr,
            meta_data,
            trusted_peers,
            config.disable_peer_scoring,
            config.target_subnet_peers,
            &log,
            config.clone_arc(),
        );
        let network_globals = Arc::new(globals);

        // Grab our local ENR FORK ID
        let enr_fork_id = network_globals
            .local_enr()
            .eth2()
            .expect("Local ENR must have a fork id");

        let gossipsub_config_params = GossipsubConfigParams {
            message_domain_valid_snappy: chain_config.message_domain_valid_snappy.into(),
            gossipsub_max_transmit_size: chain_config.max_message_size(),
        };

        let gs_config = gossipsub_config(
            config.network_load,
            ctx.fork_context.clone(),
            gossipsub_config_params,
            chain_config.seconds_per_slot.get(),
            chain_config
                .preset_base
                .phase0_preset()
                .slots_per_epoch()
                .get(),
            config.idontwant_message_size_threshold,
        );

        let score_settings = PeerScoreSettings::new(&chain_config, gs_config.mesh_n());

        let gossip_cache = {
            let slot_duration = std::time::Duration::from_secs(chain_config.seconds_per_slot.get());
            let half_epoch = std::time::Duration::from_secs(
                chain_config.seconds_per_slot.get() * P::SlotsPerEpoch::U64 / 2,
            );

            GossipCache::builder()
                .beacon_block_timeout(slot_duration)
                .aggregates_timeout(half_epoch)
                .attestation_timeout(half_epoch)
                .voluntary_exit_timeout(half_epoch * 2)
                .proposer_slashing_timeout(half_epoch * 2)
                .attester_slashing_timeout(half_epoch * 2)
                // .signed_contribution_and_proof_timeout(timeout) // Do not retry
                // .sync_committee_message_timeout(timeout) // Do not retry
                .bls_to_execution_change_timeout(half_epoch * 2)
                .build()
        };

        let local_peer_id = network_globals.local_peer_id();

        let (gossipsub, update_gossipsub_scores) = {
            let thresholds = peer_gossip_thresholds();

            // Prepare scoring parameters
            let params = {
                // Construct a set of gossipsub peer scoring parameters
                // We don't know the number of active validators and the current slot yet
                let active_validators = P::SlotsPerEpoch::U64;
                let current_slot = 0;

                score_settings.get_peer_score_params(
                    active_validators,
                    &thresholds,
                    &enr_fork_id,
                    current_slot,
                )
            };

            // Set up a scoring update interval
            let update_gossipsub_scores = tokio::time::interval(params.decay_interval);
            let possible_fork_digests = ctx.fork_context.all_fork_digests();

            let blob_sidecar_subnet_count_max =
                if chain_config.electra_fork_epoch != FAR_FUTURE_EPOCH {
                    chain_config.blob_sidecar_subnet_count_electra.get()
                } else {
                    chain_config.blob_sidecar_subnet_count.get()
                };

            let max_topics = AttestationSubnetCount::USIZE
                + SyncCommitteeSubnetCount::USIZE
                + blob_sidecar_subnet_count_max as usize
                + chain_config.data_column_sidecar_subnet_count as usize
                + BASE_CORE_TOPICS.len()
                + ALTAIR_CORE_TOPICS.len()
                + CAPELLA_CORE_TOPICS.len() // 0 core deneb and electra topics
                + LIGHT_CLIENT_GOSSIP_TOPICS.len();

            let filter = gossipsub::MaxCountSubscriptionFilter {
                filter: utils::create_whitelist_filter(
                    possible_fork_digests,
                    &chain_config,
                    AttestationSubnetCount::U64,
                    SyncCommitteeSubnetCount::U64,
                ),
                // during a fork we subscribe to both the old and new topics
                max_subscribed_topics: max_topics * 4,
                // 424 in theory = (64 attestation + 4 sync committee + 7 core topics + 9 blob topics + 128 column topics) * 2
                max_subscriptions_per_request: max_topics * 2,
            };

            // If metrics are enabled for libp2p build the configuration
            let gossipsub_metrics = ctx.libp2p_registry.as_mut().map(|registry| {
                (
                    registry.sub_registry_with_prefix("gossipsub"),
                    Default::default(),
                )
            });

            let snappy_transform = SnappyTransform::new(
                chain_config.max_payload_size,
                chain_config.max_payload_size_compressed(),
            );

            let mut gossipsub = Gossipsub::new_with_subscription_filter_and_transform(
                MessageAuthenticity::Anonymous,
                gs_config.clone(),
                gossipsub_metrics,
                filter,
                snappy_transform,
            )
            .map_err(|e| anyhow!("Could not construct gossipsub: {:?}", e))?;

            gossipsub
                .with_peer_score(params, thresholds)
                .expect("Valid score params and thresholds");

            // Mark trusted peers as explicit.
            for explicit_peer in config.trusted_peers.iter() {
                gossipsub.add_explicit_peer(&PeerId::from(explicit_peer.clone()));
            }

            // If we are using metrics, then register which topics we want to make sure to keep
            // track of
            if ctx.libp2p_registry.is_some() {
                let topics_to_keep_metrics_for = attestation_sync_committee_topics()
                    .map(|gossip_kind| {
                        Topic::from(GossipTopic::new(
                            gossip_kind,
                            GossipEncoding::default(),
                            enr_fork_id.fork_digest,
                        ))
                        .into()
                    })
                    .collect::<Vec<TopicHash>>();
                gossipsub.register_topics_for_metrics(topics_to_keep_metrics_for);
            }

            (gossipsub, update_gossipsub_scores)
        };

        let network_params = NetworkParams {
            max_payload_size: chain_config.max_payload_size,
            ttfb_timeout: Duration::from_secs(chain_config.ttfb_timeout),
            resp_timeout: Duration::from_secs(chain_config.resp_timeout),
        };
        let eth2_rpc = RPC::new(
            chain_config.clone_arc(),
            ctx.fork_context.clone(),
            config.enable_light_client_server,
            config.inbound_rate_limiter_config.clone(),
            config.outbound_rate_limiter_config.clone(),
            log.clone(),
            network_params,
            seq_number,
        );

        let discovery = {
            // Build and start the discovery sub-behaviour
            let mut discovery = Discovery::new(
                chain_config,
                local_keypair.clone(),
                &config,
                network_globals.clone(),
                &log,
            )
            .await?;
            // start searching for peers
            discovery.discover_peers(FIND_NODE_QUERY_CLOSEST_PEERS);
            discovery
        };

        let identify = {
            let local_public_key = local_keypair.public();
            let identify_config = if config.private {
                identify::Config::new(
                    "".into(),
                    local_public_key, // Still send legitimate public key
                )
                .with_cache_size(0)
            } else {
                identify::Config::new("eth2/1.0.0".into(), local_public_key)
                    .with_agent_version(
                        grandine_version::APPLICATION_VERSION_WITH_COMMIT_AND_PLATFORM.to_owned(),
                    )
                    .with_cache_size(0)
            };
            identify::Behaviour::new(identify_config)
        };

        let peer_manager = {
            let peer_manager_cfg = PeerManagerCfg {
                discovery_enabled: !config.disable_discovery,
                quic_enabled: !config.disable_quic_support,
                metrics_enabled: config.metrics_enabled,
                target_peer_count: config.target_peers,
                ..Default::default()
            };
            PeerManager::new(peer_manager_cfg, network_globals.clone(), &log)?
        };

        let connection_limits = {
            let limits = libp2p::connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(5))
                .with_max_pending_outgoing(Some(16))
                .with_max_established_incoming(Some(
                    (config.target_peers as f32
                        * (1.0 + PEER_EXCESS_FACTOR - MIN_OUTBOUND_ONLY_FACTOR))
                        .ceil() as u32,
                ))
                .with_max_established_outgoing(Some(
                    (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as u32,
                ))
                .with_max_established(Some(
                    (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS))
                        .ceil() as u32,
                ))
                .with_max_established_per_peer(Some(1));

            libp2p::connection_limits::Behaviour::new(limits)
        };

        let upnp = Toggle::from(
            config
                .upnp_enabled
                .then(libp2p::upnp::tokio::Behaviour::default),
        );
        let behaviour = {
            Behaviour {
                gossipsub,
                eth2_rpc,
                discovery,
                identify,
                peer_manager,
                connection_limits,
                upnp,
            }
        };

        // Set up the transport - tcp/quic with noise and mplex
        let transport = build_transport(local_keypair.clone(), !config.disable_quic_support)
            .map_err(|e| Error::msg(format!("Failed to build transport: {:?}", e)))?;

        // use the executor for libp2p
        struct Executor(task_executor::TaskExecutor);
        impl libp2p::swarm::Executor for Executor {
            fn exec(&self, f: Pin<Box<dyn futures::Future<Output = ()> + Send>>) {
                self.0.spawn(f, "libp2p");
            }
        }

        // sets up the libp2p swarm.

        let swarm = {
            let config = libp2p::swarm::Config::with_executor(Executor(executor))
                .with_notify_handler_buffer_size(NonZeroUsize::new(7).expect("Not zero"))
                .with_per_connection_event_buffer_size(4)
                .with_idle_connection_timeout(Duration::from_secs(10)) // Other clients can timeout
                // during negotiation
                .with_dial_concurrency_factor(NonZeroU8::new(1).unwrap());

            let builder = SwarmBuilder::with_existing_identity(local_keypair)
                .with_tokio()
                .with_other_transport(|_key| transport)
                .expect("infalible");

            // NOTE: adding bandwidth metrics changes the generics of the swarm, so types diverge
            if let Some(libp2p_registry) = ctx.libp2p_registry {
                builder
                    .with_bandwidth_metrics(libp2p_registry)
                    .with_behaviour(|_| behaviour)
                    .expect("infalible")
                    .with_swarm_config(|_| config)
                    .build()
            } else {
                builder
                    .with_behaviour(|_| behaviour)
                    .expect("infalible")
                    .with_swarm_config(|_| config)
                    .build()
            }
        };

        let mut network = Network {
            swarm,
            network_globals,
            enr_fork_id,
            network_dir: config.network_dir.clone(),
            fork_context: ctx.fork_context,
            score_settings,
            update_gossipsub_scores,
            gossip_cache,
            local_peer_id,
            log,
        };

        network.start(&config).await?;

        let network_globals = network.network_globals.clone();

        Ok((network, network_globals))
    }

    /// Starts the network:
    ///
    /// - Starts listening in the given ports.
    /// - Dials boot-nodes and libp2p peers.
    /// - Subscribes to starting gossipsub topics.
    async fn start(&mut self, config: &crate::NetworkConfig) -> Result<()> {
        let enr = self.network_globals.local_enr();
        info!(self.log, "Libp2p Starting"; "peer_id" => %enr.peer_id(), "bandwidth_config" => format!("{}-{}", config.network_load, NetworkLoad::from(config.network_load).name));

        debug!(self.log, "Attempting to open listening ports"; config.listen_addrs(), "discovery_enabled" => !config.disable_discovery, "quic_enabled" => !config.disable_quic_support);

        for listen_multiaddr in config.listen_addrs().libp2p_addresses() {
            // If QUIC is disabled, ignore listening on QUIC ports
            if config.disable_quic_support
                && listen_multiaddr.iter().any(|v| v == MProtocol::QuicV1)
            {
                continue;
            }

            match self.swarm.listen_on(listen_multiaddr.clone()) {
                Ok(_) => {
                    let mut log_address = listen_multiaddr;
                    log_address.push(MProtocol::P2p(enr.peer_id()));
                    info!(self.log, "Listening established"; "address" => %log_address);
                }
                Err(err) => {
                    crit!(
                        self.log,
                        "Unable to listen on libp2p address";
                        "error" => ?err,
                        "listen_multiaddr" => %listen_multiaddr,
                    );
                    return Err(anyhow!(
                        "Libp2p was unable to listen on the given listen address."
                    ));
                }
            };
        }

        // helper closure for dialing peers
        let mut dial = |mut multiaddr: Multiaddr| {
            // strip the p2p protocol if it exists
            strip_peer_id(&mut multiaddr);
            match self.swarm.dial(multiaddr.clone()) {
                Ok(()) => debug!(self.log, "Dialing libp2p peer"; "address" => %multiaddr),
                Err(err) => {
                    debug!(self.log, "Could not connect to peer"; "address" => %multiaddr, "error" => ?err)
                }
            };
        };

        // attempt to connect to user-input libp2p nodes
        for multiaddr in &config.libp2p_nodes {
            dial(multiaddr.clone());
        }

        // attempt to connect to any specified boot-nodes
        let mut boot_nodes = config.boot_nodes_enr.clone();
        boot_nodes.dedup();

        for bootnode_enr in boot_nodes {
            // If QUIC is enabled, attempt QUIC connections first
            if !config.disable_quic_support {
                for quic_multiaddr in &bootnode_enr.multiaddr_quic() {
                    if !self
                        .network_globals
                        .peers
                        .read()
                        .is_connected_or_dialing(&bootnode_enr.peer_id())
                    {
                        dial(quic_multiaddr.clone());
                    }
                }
            }

            for multiaddr in &bootnode_enr.multiaddr() {
                // ignore udp multiaddr if it exists
                let components = multiaddr.iter().collect::<Vec<_>>();
                if let MProtocol::Udp(_) = components[1] {
                    continue;
                }

                if !self
                    .network_globals
                    .peers
                    .read()
                    .is_connected_or_dialing(&bootnode_enr.peer_id())
                {
                    dial(multiaddr.clone());
                }
            }
        }

        for multiaddr in &config.boot_nodes_multiaddr {
            // check TCP support for dialing
            if multiaddr
                .iter()
                .any(|proto| matches!(proto, MProtocol::Tcp(_)))
            {
                dial(multiaddr.clone());
            }
        }

        let mut subscribed_topics: Vec<GossipKind> = vec![];

        for topic_kind in &config.topics {
            if self.subscribe_kind(topic_kind.clone()) {
                subscribed_topics.push(topic_kind.clone());
            } else {
                warn!(self.log, "Could not subscribe to topic"; "topic" => %topic_kind);
            }
        }

        if !subscribed_topics.is_empty() {
            info!(self.log, "Subscribed to topics"; "topics" => ?subscribed_topics);
        }

        Ok(())
    }

    /* Public Accessible Functions to interact with the behaviour */

    /// The routing pub-sub mechanism for eth2.
    pub fn gossipsub_mut(&mut self) -> &mut Gossipsub {
        &mut self.swarm.behaviour_mut().gossipsub
    }
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub fn eth2_rpc_mut(&mut self) -> &mut RPC<AppRequestId, P> {
        &mut self.swarm.behaviour_mut().eth2_rpc
    }
    /// Discv5 Discovery protocol.
    pub fn discovery_mut(&mut self) -> &mut Discovery {
        &mut self.swarm.behaviour_mut().discovery
    }
    /// Provides IP addresses and peer information.
    pub fn identify_mut(&mut self) -> &mut identify::Behaviour {
        &mut self.swarm.behaviour_mut().identify
    }
    /// The peer manager that keeps track of peer's reputation and status.
    pub fn peer_manager_mut(&mut self) -> &mut PeerManager {
        &mut self.swarm.behaviour_mut().peer_manager
    }

    /// The routing pub-sub mechanism for eth2.
    pub fn gossipsub(&self) -> &Gossipsub {
        &self.swarm.behaviour().gossipsub
    }
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub fn eth2_rpc(&self) -> &RPC<AppRequestId, P> {
        &self.swarm.behaviour().eth2_rpc
    }
    /// Discv5 Discovery protocol.
    pub fn discovery(&self) -> &Discovery {
        &self.swarm.behaviour().discovery
    }
    /// Provides IP addresses and peer information.
    pub fn identify(&self) -> &identify::Behaviour {
        &self.swarm.behaviour().identify
    }
    /// The peer manager that keeps track of peer's reputation and status.
    pub fn peer_manager(&self) -> &PeerManager {
        &self.swarm.behaviour().peer_manager
    }

    pub fn network_globals(&self) -> &Arc<NetworkGlobals> {
        &self.network_globals
    }

    /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> Enr {
        self.network_globals.local_enr()
    }

    /* Pubsub behaviour functions */

    /// Subscribes to a gossipsub topic kind, letting the network service determine the
    /// encoding and fork version.
    pub fn subscribe_kind(&mut self, kind: GossipKind) -> bool {
        let gossip_topic = GossipTopic::new(
            kind,
            GossipEncoding::default(),
            self.enr_fork_id.fork_digest,
        );

        self.subscribe(gossip_topic)
    }

    /// Unsubscribes from a gossipsub topic kind, letting the network service determine the
    /// encoding and fork version.
    pub fn unsubscribe_kind(&mut self, kind: GossipKind) -> bool {
        let gossip_topic = GossipTopic::new(
            kind,
            GossipEncoding::default(),
            self.enr_fork_id.fork_digest,
        );
        self.unsubscribe(gossip_topic)
    }

    /// Subscribe to all required topics for the `phase` with the given `new_fork_digest`.
    pub fn subscribe_new_fork_topics(&mut self, phase: Phase, new_fork_digest: ForkDigest) {
        // Subscribe to existing topics with new fork digest
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        for mut topic in subscriptions.into_iter() {
            topic.fork_digest = new_fork_digest;
            self.subscribe(topic);
        }

        // Subscribe to core topics for the new fork
        for kind in fork_core_topics(&self.network_globals.config, &phase) {
            let topic = GossipTopic::new(kind, GossipEncoding::default(), new_fork_digest);
            self.subscribe(topic);
        }

        // Register the new topics for metrics
        let topics_to_keep_metrics_for = attestation_sync_committee_topics()
            .map(|gossip_kind| {
                Topic::from(GossipTopic::new(
                    gossip_kind,
                    GossipEncoding::default(),
                    new_fork_digest,
                ))
                .into()
            })
            .collect::<Vec<TopicHash>>();
        self.gossipsub_mut()
            .register_topics_for_metrics(topics_to_keep_metrics_for);
    }

    /// Unsubscribe from all topics that doesn't have the given fork_digest
    pub fn unsubscribe_from_fork_topics_except(&mut self, except: ForkDigest) {
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        for topic in subscriptions
            .iter()
            .filter(|topic| topic.fork_digest != except)
            .cloned()
        {
            self.unsubscribe(topic);
        }
    }

    /// Remove topic weight from all topics that don't have the given fork digest.
    pub fn remove_topic_weight_except(&mut self, except: ForkDigest) {
        let new_param = TopicScoreParams {
            topic_weight: 0.0,
            ..Default::default()
        };
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        for topic in subscriptions
            .iter()
            .filter(|topic| topic.fork_digest != except)
        {
            let libp2p_topic: Topic = topic.clone().into();
            match self
                .gossipsub_mut()
                .set_topic_params(libp2p_topic, new_param.clone())
            {
                Ok(_) => debug!(self.log, "Removed topic weight"; "topic" => %topic),
                Err(e) => {
                    warn!(self.log, "Failed to remove topic weight"; "topic" => %topic, "error" => e)
                }
            }
        }
    }

    /// Returns the scoring parameters for a topic if set.
    pub fn get_topic_params(&self, topic: GossipTopic) -> Option<&TopicScoreParams> {
        self.swarm
            .behaviour()
            .gossipsub
            .get_topic_params(&topic.into())
    }

    /// Subscribes to a gossipsub topic.
    ///
    /// Returns `true` if the subscription was successful and `false` otherwise.
    pub fn subscribe(&mut self, topic: GossipTopic) -> bool {
        // update the network globals
        self.network_globals
            .gossipsub_subscriptions
            .write()
            .insert(topic.clone());

        let topic: Topic = topic.into();

        match self.gossipsub_mut().subscribe(&topic) {
            Err(e) => {
                warn!(self.log, "Failed to subscribe to topic"; "topic" => %topic, "error" => ?e);
                false
            }
            Ok(_) => {
                debug!(self.log, "Subscribed to topic"; "topic" => %topic);
                true
            }
        }
    }

    /// Unsubscribe from a gossipsub topic.
    pub fn unsubscribe(&mut self, topic: GossipTopic) -> bool {
        // update the network globals
        self.network_globals
            .gossipsub_subscriptions
            .write()
            .remove(&topic);

        // unsubscribe from the topic
        let libp2p_topic: Topic = topic.clone().into();

        match self.gossipsub_mut().unsubscribe(&libp2p_topic) {
            Err(_) => {
                warn!(self.log, "Failed to unsubscribe from topic"; "topic" => %libp2p_topic);
                false
            }
            Ok(v) => {
                // Inform the network
                debug!(self.log, "Unsubscribed to topic"; "topic" => %topic);
                v
            }
        }
    }

    /// Publishes message on the pubsub (gossipsub) behaviour, choosing the encoding.
    pub fn publish(&mut self, message: PubsubMessage<P>) {
        for topic in message.topics(GossipEncoding::default(), self.enr_fork_id.fork_digest) {
            let message_data = message.encode(GossipEncoding::default()).expect("TODO");

            if let Err(e) = self
                .gossipsub_mut()
                .publish(Topic::from(topic.clone()), message_data.clone())
            {
                match e {
                    PublishError::Duplicate => {
                        debug!(
                            self.log,
                            "Attempted to publish duplicate message";
                            "kind" => %topic.kind(),
                        );
                    }
                    ref e => {
                        warn!(
                            self.log,
                            "Could not publish message";
                            "error" => ?e,
                            "kind" => %topic.kind(),
                        );
                    }
                }

                // add to metrics
                match topic.kind() {
                    GossipKind::Attestation(subnet_id) => {
                        if let Some(v) = crate::common::metrics::get_int_gauge(
                            &metrics::FAILED_ATTESTATION_PUBLISHES_PER_SUBNET,
                            &[&subnet_id.to_string()],
                        ) {
                            v.inc()
                        };
                    }
                    kind => {
                        if let Some(v) = crate::common::metrics::get_int_gauge(
                            &metrics::FAILED_PUBLISHES_PER_MAIN_TOPIC,
                            &[&format!("{:?}", kind)],
                        ) {
                            v.inc()
                        };
                    }
                }

                if let PublishError::InsufficientPeers = e {
                    self.gossip_cache.insert(topic, message_data);
                }
            }
        }
    }

    /// Informs the gossipsub about the result of a message validation.
    /// If the message is valid it will get propagated by gossipsub.
    pub fn report_message_validation_result(
        &mut self,
        propagation_source: &PeerId,
        message_id: MessageId,
        validation_result: MessageAcceptance,
    ) {
        if let Some(result) = match validation_result {
            MessageAcceptance::Accept => None,
            MessageAcceptance::Ignore => Some("ignore"),
            MessageAcceptance::Reject => Some("reject"),
        } {
            if let Some(client) = self
                .network_globals
                .peers
                .read()
                .peer_info(propagation_source)
                .map(|info| info.client().kind.as_ref())
            {
                crate::common::metrics::inc_counter_vec(
                    &metrics::GOSSIP_UNACCEPTED_MESSAGES_PER_CLIENT,
                    &[client, result],
                )
            }
        }

        if let Err(e) = self.gossipsub_mut().report_message_validation_result(
            &message_id,
            propagation_source,
            validation_result,
        ) {
            warn!(self.log, "Failed to report message validation"; "message_id" => %message_id, "peer_id" => %propagation_source, "error" => ?e);
        }
    }

    /// Updates the current gossipsub scoring parameters based on the validator count and current
    /// slot.
    pub fn update_gossipsub_parameters(
        &mut self,
        active_validators: u64,
        current_slot: Slot,
    ) -> Result<()> {
        let (beacon_block_params, beacon_aggregate_proof_params, beacon_attestation_subnet_params) =
            self.score_settings
                .get_dynamic_topic_params(active_validators, current_slot);

        let fork_digest = self.enr_fork_id.fork_digest;
        let get_topic = |kind: GossipKind| -> Topic {
            GossipTopic::new(kind, GossipEncoding::default(), fork_digest).into()
        };

        debug!(self.log, "Updating gossipsub score parameters";
            "active_validators" => active_validators);
        trace!(self.log, "Updated gossipsub score parameters";
            "beacon_block_params" => ?beacon_block_params,
            "beacon_aggregate_proof_params" => ?beacon_aggregate_proof_params,
            "beacon_attestation_subnet_params" => ?beacon_attestation_subnet_params,
        );

        self.gossipsub_mut()
            .set_topic_params(get_topic(GossipKind::BeaconBlock), beacon_block_params)
            .map_err(Error::msg)?;

        self.gossipsub_mut()
            .set_topic_params(
                get_topic(GossipKind::BeaconAggregateAndProof),
                beacon_aggregate_proof_params,
            )
            .map_err(Error::msg)?;

        for i in 0..self.score_settings.attestation_subnet_count() {
            self.gossipsub_mut()
                .set_topic_params(
                    get_topic(GossipKind::Attestation(i)),
                    beacon_attestation_subnet_params.clone(),
                )
                .map_err(Error::msg)?;
        }

        Ok(())
    }

    /* Eth2 RPC behaviour functions */

    /// Send a request to a peer over RPC.
    pub fn send_request(
        &mut self,
        peer_id: PeerId,
        app_request_id: AppRequestId,
        request: RequestType<P>,
    ) -> Result<(), (AppRequestId, RPCError)> {
        // Check if the peer is connected before sending an RPC request
        if !self.swarm.is_connected(&peer_id) {
            return Err((app_request_id, RPCError::Disconnected));
        }

        self.eth2_rpc_mut()
            .send_request(peer_id, app_request_id, request);
        Ok(())
    }

    /// Send a successful response to a peer over RPC.
    pub fn send_response<T: Into<RpcResponse<P>>>(
        &mut self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        response: T,
    ) {
        if let Err(response) = self
            .eth2_rpc_mut()
            .send_response(inbound_request_id, response.into())
        {
            if self.network_globals.peers.read().is_connected(&peer_id) {
                error!(
                    self.log,
                    "Request not found in RPC active requests";
                    "peer_id" => %peer_id,
                    "inbound_request_id" => ?inbound_request_id,
                    "response" => %response,
                );
            }
        }
    }

    /* Peer management functions */

    pub fn testing_dial(&mut self, addr: Multiaddr) -> Result<(), libp2p::swarm::DialError> {
        self.swarm.dial(addr)
    }

    pub fn report_peer(
        &mut self,
        peer_id: &PeerId,
        action: PeerAction,
        source: ReportSource,
        msg: &'static str,
    ) {
        self.peer_manager_mut()
            .report_peer(peer_id, action, source, None, msg);
    }

    /// Disconnects from a peer providing a reason.
    ///
    /// This will send a goodbye, disconnect and then ban the peer.
    /// This is fatal for a peer, and should be used in unrecoverable circumstances.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        self.peer_manager_mut()
            .goodbye_peer(peer_id, reason, source);
    }

    /// Hard (ungraceful) disconnect for testing purposes only
    /// Use goodbye_peer for disconnections, do not use this function.
    pub fn __hard_disconnect_testing_only(&mut self, peer_id: PeerId) {
        let _ = self.swarm.disconnect_peer_id(peer_id);
    }

    /// Returns an iterator over all enr entries in the DHT.
    pub fn enr_entries(&self) -> Vec<Enr> {
        self.discovery().table_entries_enr()
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        self.discovery_mut().add_enr(enr);
    }

    /// Updates a subnet value to the ENR attnets/syncnets bitfield.
    ///
    /// The `value` is `true` if a subnet is being added and false otherwise.
    pub fn update_enr_subnet(&mut self, subnet_id: Subnet, value: bool) {
        if let Err(e) = self.discovery_mut().update_enr_bitfield(subnet_id, value) {
            crit!(self.log, "Could not update ENR bitfield"; "error" => ?e);
        }
        // update the local meta data which informs our peers of the update during PINGS
        self.update_metadata_bitfields();
    }

    /// Attempts to discover new peers for a given subnet. The `min_ttl` gives the time at which we
    /// would like to retain the peers for.
    pub fn discover_subnet_peers(&mut self, subnets_to_discover: Vec<SubnetDiscovery>) {
        // If discovery is not started or disabled, ignore the request
        if !self.discovery().started {
            return;
        }

        let chain_config = self.fork_context.chain_config().clone();
        let filtered: Vec<SubnetDiscovery> = subnets_to_discover
            .into_iter()
            .filter(|s| {
                // Extend min_ttl of connected peers on required subnets
                if let Some(min_ttl) = s.min_ttl {
                    self.network_globals
                        .peers
                        .write()
                        .extend_peers_on_subnet(&s.subnet, min_ttl);
                    if let Subnet::SyncCommittee(sync_subnet) = s.subnet {
                        self.peer_manager_mut()
                            .add_sync_subnet(sync_subnet, min_ttl);
                    }
                }
                // Already have target number of peers, no need for subnet discovery
                let peers_on_subnet = self
                    .network_globals
                    .peers
                    .read()
                    .good_peers_on_subnet(s.subnet)
                    .count();
                if peers_on_subnet >= self.network_globals.target_subnet_peers {
                    trace!(
                        self.log,
                        "Discovery query ignored";
                        "subnet" => ?s.subnet,
                        "reason" => "Already connected to desired peers",
                        "connected_peers_on_subnet" => peers_on_subnet,
                        "target_subnet_peers" => self.network_globals.target_subnet_peers,
                    );
                    false
                // Queue an outgoing connection request to the cached peers that are on `s.subnet_id`.
                // If we connect to the cached peers before the discovery query starts, then we potentially
                // save a costly discovery query.
                } else {
                    self.dial_cached_enrs_in_subnet(chain_config.clone(), s.subnet);
                    true
                }
            })
            .collect();

        // request the subnet query from discovery
        if !filtered.is_empty() {
            self.discovery_mut().discover_subnet_peers(filtered);
        }
    }

    /// Updates the local ENR's "eth2" field with the latest EnrForkId.
    pub fn update_fork_version(&mut self, enr_fork_id: EnrForkId) {
        self.discovery_mut().update_eth2_enr(enr_fork_id.clone());

        // update the local reference
        self.enr_fork_id = enr_fork_id;
    }

    /* Private internal functions */

    /// Updates the current meta data of the node to match the local ENR.
    fn update_metadata_bitfields(&mut self) {
        let local_attnets = self
            .discovery_mut()
            .local_enr()
            .attestation_bitfield()
            .expect("Local discovery must have attestation bitfield");

        let local_syncnets = self
            .discovery_mut()
            .local_enr()
            .sync_committee_bitfield()
            .expect("Local discovery must have sync committee bitfield");

        // write lock scope
        let mut meta_data_w = self.network_globals.local_metadata.write();

        *meta_data_w.seq_number_mut() += 1;
        *meta_data_w.attnets_mut() = local_attnets;
        if let Some(syncnets) = meta_data_w.syncnets_mut() {
            *syncnets = local_syncnets;
        }
        let seq_number = meta_data_w.seq_number();
        let meta_data = meta_data_w.clone();

        drop(meta_data_w);
        self.eth2_rpc_mut().update_seq_number(seq_number);
        // Save the updated metadata to disk
        utils::save_metadata_to_disk(self.network_dir.as_deref(), meta_data, &self.log);
    }

    /// Sends a Ping request to the peer.
    fn ping(&mut self, peer_id: PeerId) {
        self.eth2_rpc_mut().ping(peer_id, AppRequestId::Internal);
    }

    /// Sends a METADATA request to a peer.
    fn send_meta_data_request(&mut self, peer_id: PeerId) {
        let event = if self.network_globals.config.is_eip7594_fork_epoch_set() {
            // Nodes with higher custody will probably start advertising it
            // before peerdas is activated
            RequestType::MetaData(MetadataRequest::new_v3())
        } else {
            // We always prefer sending V2 requests otherwise
            RequestType::MetaData(MetadataRequest::new_v2())
        };
        self.eth2_rpc_mut()
            .send_request(peer_id, AppRequestId::Internal, event);
    }

    // RPC Propagation methods
    /// Queues the response to be sent upwards as long at it was requested outside the Behaviour.
    #[must_use = "return the response"]
    fn build_response(
        &mut self,
        app_request_id: AppRequestId,
        peer_id: PeerId,
        response: Response<P>,
    ) -> Option<NetworkEvent<P>> {
        match app_request_id {
            AppRequestId::Internal => None,
            _ => Some(NetworkEvent::ResponseReceived {
                peer_id,
                app_request_id,
                response,
            }),
        }
    }

    /// Dial cached Enrs in discovery service that are in the given `subnet_id` and aren't
    /// in Connected, Dialing or Banned state.
    fn dial_cached_enrs_in_subnet(&mut self, chain_config: Arc<ChainConfig>, subnet: Subnet) {
        let predicate = subnet_predicate(chain_config, vec![subnet], &self.log);
        let peers_to_dial: Vec<Enr> = self
            .discovery()
            .cached_enrs()
            .filter_map(|(_peer_id, enr)| {
                if predicate(enr) {
                    Some(enr.clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove the ENR from the cache to prevent continual re-dialing on disconnects
        for enr in peers_to_dial {
            self.discovery_mut().remove_cached_enr(&enr.peer_id());
            let peer_id = enr.peer_id();
            if self.peer_manager_mut().dial_peer(enr) {
                debug!(self.log, "Added cached ENR peer to dial queue"; "peer_id" => %peer_id);
            }
        }
    }

    /// Adds the given `enr` to the trusted peers mapping and tries to dial it
    /// every heartbeat to maintain the connection.
    pub fn dial_trusted_peer(&mut self, enr: Enr) {
        self.peer_manager_mut().add_trusted_peer(enr.clone());
        self.peer_manager_mut().dial_peer(enr);
    }

    /// Remove the given peer from the trusted peers mapping if it exists and disconnect
    /// from it.
    pub fn remove_trusted_peer(&mut self, enr: Enr) {
        self.peer_manager_mut().remove_trusted_peer(enr.clone());
        self.peer_manager_mut()
            .disconnect_peer(enr.peer_id(), GoodbyeReason::TooManyPeers);
    }

    /* Sub-behaviour event handling functions */

    /// Handle a gossipsub event.
    fn inject_gs_event(&mut self, event: gossipsub::Event) -> Option<NetworkEvent<P>> {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id: id,
                message: gs_msg,
            } => {
                // Note: We are keeping track here of the peer that sent us the message, not the
                // peer that originally published the message.
                match PubsubMessage::decode(&gs_msg.topic, &gs_msg.data, &self.fork_context) {
                    Err(e) => {
                        debug!(self.log, "Could not decode gossipsub message"; "topic" => ?gs_msg.topic,"error" => e);
                        //reject the message
                        if let Err(e) = self.gossipsub_mut().report_message_validation_result(
                            &id,
                            &propagation_source,
                            MessageAcceptance::Reject,
                        ) {
                            warn!(self.log, "Failed to report message validation"; "message_id" => %id, "peer_id" => %propagation_source, "error" => ?e);
                        }
                    }
                    Ok(msg) => {
                        // Notify the network
                        return Some(NetworkEvent::PubsubMessage {
                            id,
                            source: propagation_source,
                            topic: gs_msg.topic,
                            message: msg,
                        });
                    }
                }
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                if let Ok(topic) = GossipTopic::decode(topic.as_str()) {
                    if let Some(subnet_id) = topic.subnet_id() {
                        self.network_globals
                            .peers
                            .write()
                            .add_subscription(&peer_id, subnet_id);
                    }
                    // Try to send the cached messages for this topic
                    if let Some(msgs) = self.gossip_cache.retrieve(&topic) {
                        for data in msgs {
                            let topic_str: &str = topic.kind().as_ref();
                            match self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(Topic::from(topic.clone()), data)
                            {
                                Ok(_) => {
                                    debug!(
                                        self.log,
                                        "Gossip message published on retry";
                                        "topic" => topic_str
                                    );
                                    metrics::inc_counter_vec(
                                        &metrics::GOSSIP_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    );
                                }
                                Err(PublishError::Duplicate) => {
                                    debug!(
                                        self.log,
                                        "Gossip message publish ignored on retry";
                                        "reason" => "duplicate",
                                        "topic" => topic_str
                                    );
                                    metrics::inc_counter_vec(
                                        &metrics::GOSSIP_FAILED_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        self.log,
                                        "Gossip message publish failed on retry";
                                        "topic" => topic_str,
                                        "error" => %e
                                    );
                                    metrics::inc_counter_vec(
                                        &metrics::GOSSIP_FAILED_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    );
                                }
                            }
                        }
                    }
                }
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                if let Some(subnet_id) = subnet_from_topic_hash(&topic) {
                    self.network_globals
                        .peers
                        .write()
                        .remove_subscription(&peer_id, &subnet_id);
                }
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                debug!(self.log, "Peer does not support gossipsub"; "peer_id" => %peer_id);
                self.peer_manager_mut().report_peer(
                    &peer_id,
                    PeerAction::Fatal,
                    ReportSource::Gossipsub,
                    Some(GoodbyeReason::Unknown),
                    "does_not_support_gossipsub",
                );
            }
            gossipsub::Event::SlowPeer {
                peer_id,
                failed_messages,
            } => {
                debug!(self.log, "Slow gossipsub peer"; "peer_id" => %peer_id, "publish" => failed_messages.publish, "forward" => failed_messages.forward, "priority" => failed_messages.priority, "non_priority" => failed_messages.non_priority);
                // Punish the peer if it cannot handle priority messages
                if failed_messages.total_timeout() > 10 {
                    debug!(self.log, "Slow gossipsub peer penalized for priority failure"; "peer_id" => %peer_id);
                    self.peer_manager_mut().report_peer(
                        &peer_id,
                        PeerAction::HighToleranceError,
                        ReportSource::Gossipsub,
                        None,
                        "publish_timeout_penalty",
                    );
                } else if failed_messages.total_queue_full() > 10 {
                    debug!(self.log, "Slow gossipsub peer penalized for send queue full"; "peer_id" => %peer_id);
                    self.peer_manager_mut().report_peer(
                        &peer_id,
                        PeerAction::HighToleranceError,
                        ReportSource::Gossipsub,
                        None,
                        "queue_full_penalty",
                    );
                }
            }
        }
        None
    }

    /// Handle an RPC event.
    fn inject_rpc_event(&mut self, event: RPCMessage<AppRequestId, P>) -> Option<NetworkEvent<P>> {
        let peer_id = event.peer_id;

        // Do not permit Inbound events from peers that are being disconnected or RPC requests,
        // but allow `RpcFailed` and `HandlerErr::Outbound` to be bubble up to sync for state management.
        if !self.peer_manager().is_connected(&peer_id)
            && (matches!(event.message, Err(HandlerErr::Inbound { .. }))
                || matches!(event.message, Ok(RPCReceived::Request(..))))
        {
            debug!(
                self.log,
                "Ignoring rpc message of disconnecting peer";
                event
            );
            return None;
        }

        // The METADATA and PING RPC responses are handled within the behaviour and not propagated
        match event.message {
            Err(handler_err) => {
                match handler_err {
                    HandlerErr::Inbound {
                        id: _,
                        proto,
                        error,
                    } => {
                        // Inform the peer manager of the error.
                        // An inbound error here means we sent an error to the peer, or the stream
                        // timed out.
                        self.peer_manager_mut().handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Incoming,
                        );
                        None
                    }
                    HandlerErr::Outbound { id, proto, error } => {
                        // Inform the peer manager that a request we sent to the peer failed
                        self.peer_manager_mut().handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Outgoing,
                        );
                        // inform failures of requests coming outside the behaviour
                        if let AppRequestId::Internal = id {
                            None
                        } else {
                            Some(NetworkEvent::RPCFailed {
                                peer_id,
                                app_request_id: id,
                                error,
                            })
                        }
                    }
                }
            }
            Ok(RPCReceived::Request(inbound_request_id, request_type)) => {
                match request_type {
                    /* Behaviour managed protocols: Ping and Metadata */
                    RequestType::Ping(ping) => {
                        // inform the peer manager and send the response
                        self.peer_manager_mut().ping_request(&peer_id, ping.data);
                        None
                    }
                    RequestType::MetaData(_req) => {
                        // send the requested meta-data
                        let metadata = self.network_globals.local_metadata.read().clone();
                        // The encoder is responsible for sending the negotiated version of the metadata
                        let response =
                            RpcResponse::Success(RpcSuccessResponse::MetaData(Arc::new(metadata)));
                        self.send_response(peer_id, inbound_request_id, response);
                        None
                    }
                    RequestType::Goodbye(reason) => {
                        // queue for disconnection without a goodbye message
                        debug!(
                            self.log, "Peer sent Goodbye";
                            "peer_id" => %peer_id,
                            "reason" => %reason,
                            "client" => %self.network_globals.client(&peer_id),
                        );
                        // NOTE: We currently do not inform the application that we are
                        // disconnecting here. The RPC handler will automatically
                        // disconnect for us.
                        // The actual disconnection event will be relayed to the application.
                        None
                    }
                    /* Protocols propagated to the Network */
                    RequestType::Status(_) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager_mut().peer_statusd(&peer_id);
                        metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["status"]);
                        // propagate the STATUS message upwards
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::BlocksByRange(ref req) => {
                        // Still disconnect the peer if the request is naughty.
                        if req.step() == 0 {
                            self.peer_manager_mut().handle_rpc_error(
                                &peer_id,
                                Protocol::BlocksByRange,
                                &RPCError::InvalidData(
                                    "Blocks by range with 0 step parameter".into(),
                                ),
                                ConnectionDirection::Incoming,
                            );
                            return None;
                        }
                        metrics::inc_counter_vec(
                            &metrics::TOTAL_RPC_REQUESTS,
                            &["blocks_by_range"],
                        );
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::BlocksByRoot(_) => {
                        metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["blocks_by_root"]);
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::BlobsByRange(_) => {
                        metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["blobs_by_range"]);
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::BlobsByRoot(_) => {
                        metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["blobs_by_root"]);
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::DataColumnsByRoot(_) => {
                        metrics::inc_counter_vec(
                            &metrics::TOTAL_RPC_REQUESTS,
                            &["data_columns_by_root"],
                        );
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::DataColumnsByRange(_) => {
                        metrics::inc_counter_vec(
                            &metrics::TOTAL_RPC_REQUESTS,
                            &["data_columns_by_range"],
                        );
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::LightClientBootstrap(_) => {
                        metrics::inc_counter_vec(
                            &metrics::TOTAL_RPC_REQUESTS,
                            &["light_client_bootstrap"],
                        );
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::LightClientOptimisticUpdate => {
                        metrics::inc_counter_vec(
                            &metrics::TOTAL_RPC_REQUESTS,
                            &["light_client_optimistic_update"],
                        );
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::LightClientFinalityUpdate => {
                        metrics::inc_counter_vec(
                            &metrics::TOTAL_RPC_REQUESTS,
                            &["light_client_finality_update"],
                        );
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                    RequestType::LightClientUpdatesByRange(_) => {
                        metrics::inc_counter_vec(
                            &metrics::TOTAL_RPC_REQUESTS,
                            &["light_client_updates_by_range"],
                        );
                        Some(NetworkEvent::RequestReceived {
                            peer_id,
                            inbound_request_id,
                            request_type,
                        })
                    }
                }
            }
            Ok(RPCReceived::Response(id, resp)) => {
                match resp {
                    /* Behaviour managed protocols */
                    RpcSuccessResponse::Pong(ping) => {
                        self.peer_manager_mut().pong_response(&peer_id, ping.data);
                        None
                    }
                    RpcSuccessResponse::MetaData(meta_data) => {
                        self.peer_manager_mut()
                            .meta_data_response(&peer_id, meta_data.as_ref().clone());
                        None
                    }
                    /* Network propagated protocols */
                    RpcSuccessResponse::Status(msg) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager_mut().peer_statusd(&peer_id);
                        // propagate the STATUS message upwards
                        self.build_response(id, peer_id, Response::Status(msg))
                    }
                    RpcSuccessResponse::BlocksByRange(resp) => {
                        self.build_response(id, peer_id, Response::BlocksByRange(Some(resp)))
                    }
                    RpcSuccessResponse::BlobsByRange(resp) => {
                        self.build_response(id, peer_id, Response::BlobsByRange(Some(resp)))
                    }
                    RpcSuccessResponse::BlocksByRoot(resp) => {
                        self.build_response(id, peer_id, Response::BlocksByRoot(Some(resp)))
                    }
                    RpcSuccessResponse::BlobsByRoot(resp) => {
                        self.build_response(id, peer_id, Response::BlobsByRoot(Some(resp)))
                    }
                    RpcSuccessResponse::DataColumnsByRoot(resp) => {
                        self.build_response(id, peer_id, Response::DataColumnsByRoot(Some(resp)))
                    }
                    RpcSuccessResponse::DataColumnsByRange(resp) => {
                        self.build_response(id, peer_id, Response::DataColumnsByRange(Some(resp)))
                    }
                    // Should never be reached
                    RpcSuccessResponse::LightClientBootstrap(bootstrap) => {
                        self.build_response(id, peer_id, Response::LightClientBootstrap(bootstrap))
                    }
                    RpcSuccessResponse::LightClientOptimisticUpdate(update) => self.build_response(
                        id,
                        peer_id,
                        Response::LightClientOptimisticUpdate(update),
                    ),
                    RpcSuccessResponse::LightClientFinalityUpdate(update) => self.build_response(
                        id,
                        peer_id,
                        Response::LightClientFinalityUpdate(update),
                    ),
                    RpcSuccessResponse::LightClientUpdatesByRange(update) => self.build_response(
                        id,
                        peer_id,
                        Response::LightClientUpdatesByRange(Some(update)),
                    ),
                }
            }
            Ok(RPCReceived::EndOfStream(id, termination)) => {
                let response = match termination {
                    ResponseTermination::BlocksByRange => Response::BlocksByRange(None),
                    ResponseTermination::BlocksByRoot => Response::BlocksByRoot(None),
                    ResponseTermination::BlobsByRange => Response::BlobsByRange(None),
                    ResponseTermination::BlobsByRoot => Response::BlobsByRoot(None),
                    ResponseTermination::DataColumnsByRoot => Response::DataColumnsByRoot(None),
                    ResponseTermination::DataColumnsByRange => Response::DataColumnsByRange(None),
                    ResponseTermination::LightClientUpdatesByRange => {
                        Response::LightClientUpdatesByRange(None)
                    }
                };
                self.build_response(id, peer_id, response)
            }
        }
    }

    /// Handle an identify event.
    fn inject_identify_event(&mut self, event: identify::Event) -> Option<NetworkEvent<P>> {
        match event {
            identify::Event::Received {
                peer_id,
                mut info,
                connection_id: _,
            } => {
                if info.listen_addrs.len() > MAX_IDENTIFY_ADDRESSES {
                    debug!(
                        self.log,
                        "More than 10 addresses have been identified, truncating"
                    );
                    info.listen_addrs.truncate(MAX_IDENTIFY_ADDRESSES);
                }
                // send peer info to the peer manager.
                self.peer_manager_mut().identify(&peer_id, &info);
            }
            identify::Event::Sent { .. } => {}
            identify::Event::Error { .. } => {}
            identify::Event::Pushed { .. } => {}
        }
        None
    }

    /// Handle a peer manager event.
    fn inject_pm_event(&mut self, event: PeerManagerEvent) -> Option<NetworkEvent<P>> {
        match event {
            PeerManagerEvent::PeerConnectedIncoming(peer_id) => {
                Some(NetworkEvent::PeerConnectedIncoming(peer_id))
            }
            PeerManagerEvent::PeerConnectedOutgoing(peer_id) => {
                Some(NetworkEvent::PeerConnectedOutgoing(peer_id))
            }
            PeerManagerEvent::PeerDisconnected(peer_id) => {
                Some(NetworkEvent::PeerDisconnected(peer_id))
            }
            PeerManagerEvent::Banned(peer_id, associated_ips) => {
                self.discovery_mut().ban_peer(&peer_id, associated_ips);
                None
            }
            PeerManagerEvent::UnBanned(peer_id, associated_ips) => {
                self.discovery_mut().unban_peer(&peer_id, associated_ips);
                None
            }
            PeerManagerEvent::Status(peer_id) => {
                // it's time to status. We don't keep a beacon chain reference here, so we inform
                // the network to send a status to this peer
                Some(NetworkEvent::StatusPeer(peer_id))
            }
            PeerManagerEvent::DiscoverPeers(peers_to_find) => {
                // Peer manager has requested a discovery query for more peers.
                self.discovery_mut().discover_peers(peers_to_find);
                None
            }
            PeerManagerEvent::DiscoverSubnetPeers(subnets_to_discover) => {
                // Peer manager has requested a subnet discovery query for more peers.
                self.discover_subnet_peers(subnets_to_discover);
                None
            }
            PeerManagerEvent::Ping(peer_id) => {
                // send a ping request to this peer
                self.ping(peer_id);
                None
            }
            PeerManagerEvent::MetaData(peer_id) => {
                self.send_meta_data_request(peer_id);
                None
            }
            PeerManagerEvent::DisconnectPeer(peer_id, reason) => {
                debug!(self.log, "Peer Manager disconnecting peer";
                       "peer_id" => %peer_id, "reason" => %reason);
                // send one goodbye
                self.eth2_rpc_mut()
                    .shutdown(peer_id, AppRequestId::Internal, reason);
                None
            }
        }
    }

    fn inject_upnp_event(&mut self, event: libp2p::upnp::Event) {
        match event {
            libp2p::upnp::Event::NewExternalAddr(addr) => {
                info!(self.log, "UPnP route established"; "addr" => %addr);
                let mut iter = addr.iter();
                let is_ip6 = {
                    let addr = iter.next();
                    matches!(addr, Some(MProtocol::Ip6(_)))
                };
                match iter.next() {
                    Some(multiaddr::Protocol::Udp(udp_port)) => match iter.next() {
                        Some(multiaddr::Protocol::QuicV1) => {
                            if let Err(e) =
                                self.discovery_mut().update_enr_quic_port(udp_port, is_ip6)
                            {
                                warn!(self.log, "Failed to update ENR"; "error" => e);
                            }
                        }
                        _ => {
                            trace!(self.log, "UPnP address mapped multiaddr from unknown transport"; "addr" => %addr)
                        }
                    },
                    Some(multiaddr::Protocol::Tcp(tcp_port)) => {
                        if let Err(e) = self.discovery_mut().update_enr_tcp_port(tcp_port, is_ip6) {
                            warn!(self.log, "Failed to update ENR"; "error" => e);
                        }
                    }
                    _ => {
                        trace!(self.log, "UPnP address mapped multiaddr from unknown transport"; "addr" => %addr);
                    }
                }
            }
            libp2p::upnp::Event::ExpiredExternalAddr(_) => {}
            libp2p::upnp::Event::GatewayNotFound => {
                info!(self.log, "UPnP not available");
            }
            libp2p::upnp::Event::NonRoutableGateway => {
                info!(
                    self.log,
                    "UPnP is available but gateway is not exposed to public network"
                );
            }
        }
    }

    /* Networking polling */

    pub async fn next_event(&mut self) -> NetworkEvent<P> {
        loop {
            tokio::select! {
                // Poll the libp2p `Swarm`.
                // This will poll the swarm and do maintenance routines.
                Some(event) = self.swarm.next() => {
                    if let Some(event) = self.parse_swarm_event(event) {
                        return event;
                    }
                },

                // perform gossipsub score updates when necessary
                _ = self.update_gossipsub_scores.tick() => {
                    let this = self.swarm.behaviour_mut();
                    this.peer_manager.update_gossipsub_scores(&this.gossipsub);
                }
                // poll the gossipsub cache to clear expired messages
                Some(result) = self.gossip_cache.next() => {
                    match result {
                        Err(e) => warn!(self.log, "Gossip cache error"; "error" => e),
                        Ok(expired_topic) => {
                            if let Some(v) = metrics::get_int_counter(
                                &metrics::GOSSIP_EXPIRED_LATE_PUBLISH_PER_TOPIC_KIND,
                                &[expired_topic.kind().as_ref()],
                            ) {
                                v.inc()
                            };
                        }
                    }
                }
            }
        }
    }

    fn parse_swarm_event(
        &mut self,
        event: SwarmEvent<BehaviourEvent<P>>,
    ) -> Option<NetworkEvent<P>> {
        match event {
            SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                // Handle sub-behaviour events.
                BehaviourEvent::Gossipsub(ge) => self.inject_gs_event(ge),
                BehaviourEvent::Eth2Rpc(re) => self.inject_rpc_event(re),
                // Inform the peer manager about discovered peers.
                //
                // The peer manager will subsequently decide which peers need to be dialed and then dial
                // them.
                BehaviourEvent::Discovery(DiscoveredPeers { peers }) => {
                    self.peer_manager_mut().peers_discovered(peers);
                    None
                }
                BehaviourEvent::Identify(ie) => self.inject_identify_event(ie),
                BehaviourEvent::PeerManager(pe) => self.inject_pm_event(pe),
                BehaviourEvent::Upnp(e) => {
                    self.inject_upnp_event(e);
                    None
                }
                #[allow(unreachable_patterns)]
                BehaviourEvent::ConnectionLimits(le) => libp2p::core::util::unreachable(le),
            },
            SwarmEvent::ConnectionEstablished { .. } => None,
            SwarmEvent::ConnectionClosed { .. } => None,
            SwarmEvent::IncomingConnection {
                local_addr,
                send_back_addr,
                connection_id: _,
            } => {
                trace!(self.log, "Incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr);
                None
            }
            SwarmEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error,
                connection_id: _,
            } => {
                let error_repr = match error {
                    libp2p::swarm::ListenError::Aborted => {
                        "Incoming connection aborted".to_string()
                    }
                    libp2p::swarm::ListenError::WrongPeerId { obtained, endpoint } => {
                        format!("Wrong peer id, obtained {obtained}, endpoint {endpoint:?}")
                    }
                    libp2p::swarm::ListenError::LocalPeerId { endpoint } => {
                        format!("Dialing local peer id {endpoint:?}")
                    }
                    libp2p::swarm::ListenError::Denied { cause } => {
                        format!("Connection was denied with cause: {cause:?}")
                    }
                    libp2p::swarm::ListenError::Transport(t) => match t {
                        libp2p::TransportError::MultiaddrNotSupported(m) => {
                            format!("Transport error: Multiaddr not supported: {m}")
                        }
                        libp2p::TransportError::Other(e) => {
                            format!("Transport error: other: {e}")
                        }
                    },
                };
                debug!(self.log, "Failed incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr, "error" => error_repr);
                None
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: _,
                error: _,
                connection_id: _,
            } => {
                // The Behaviour event is more general than the swarm event here. It includes
                // connection failures. So we use that log for now, in the peer manager
                // behaviour implementation.
                None
            }
            SwarmEvent::NewListenAddr { address, .. } => Some(NetworkEvent::NewListenAddr(address)),
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                debug!(self.log, "Listen address expired"; "address" => %address);
                None
            }
            SwarmEvent::ListenerClosed {
                addresses, reason, ..
            } => {
                match reason {
                    Ok(_) => {
                        debug!(self.log, "Listener gracefully closed"; "addresses" => ?addresses)
                    }
                    Err(reason) => {
                        crit!(self.log, "Listener abruptly closed"; "addresses" => ?addresses, "reason" => ?reason)
                    }
                };
                if Swarm::listeners(&self.swarm).count() == 0 {
                    Some(NetworkEvent::ZeroListeners)
                } else {
                    None
                }
            }
            SwarmEvent::ListenerError { error, .. } => {
                debug!(self.log, "Listener closed connection attempt"; "reason" => ?error);
                None
            }
            _ => {
                // NOTE: SwarmEvent is a non exhaustive enum so updates should be based on
                // release notes more than compiler feedback
                None
            }
        }
    }
}
