#![cfg(test)]
use eth2_libp2p::service::Network as LibP2PService;
use eth2_libp2p::types::{EnrForkId, ForkContext};
use eth2_libp2p::Multiaddr;
use eth2_libp2p::TaskExecutor;
use eth2_libp2p::{Context, Enr, EnrExt};
use eth2_libp2p::{NetworkConfig, NetworkEvent};
use logging::{debug_with_peers, error_with_peers};
use std::sync::Arc;
use std_ext::ArcExt as _;
use tracing::{info_span, Instrument};
use tracing_subscriber::EnvFilter;
use types::{config::Config as ChainConfig, nonstandard::Phase, preset::Preset};

use eth2_libp2p::rpc::config::InboundRateLimiterConfig;
use libp2p::identity::secp256k1;
use tempfile::Builder as TempBuilder;

pub struct Libp2pInstance<P: Preset>(LibP2PService<P>);

impl<P: Preset> std::ops::Deref for Libp2pInstance<P> {
    type Target = LibP2PService<P>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P: Preset> std::ops::DerefMut for Libp2pInstance<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[allow(unused)]
pub fn build_tracing_subscriber(level: &str, enabled: bool) {
    if enabled {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_new(level).unwrap())
            .try_init()
            .unwrap();
    }
}

pub fn build_config(
    mut boot_nodes: Vec<Enr>,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
) -> Arc<NetworkConfig> {
    let mut config = NetworkConfig::default();

    // Find unused ports by using the 0 port.
    let port = 0;

    let random_path: u16 = rand::random();
    let path = TempBuilder::new()
        .prefix(&format!("libp2p_test_{}", random_path))
        .tempdir()
        .unwrap();

    config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, port, port, port);
    config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    config.boot_nodes_enr.append(&mut boot_nodes);
    config.network_dir = Some(path.keep());
    config.disable_peer_scoring = disable_peer_scoring;
    config.inbound_rate_limiter_config = inbound_rate_limiter;
    Arc::new(config)
}

pub async fn build_libp2p_instance<P: Preset>(
    chain_config: &Arc<ChainConfig>,
    boot_nodes: Vec<Enr>,
    _service_name: String,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
    fork_name: Phase,
) -> Libp2pInstance<P> {
    let config = build_config(boot_nodes, disable_peer_scoring, inbound_rate_limiter);
    // launch libp2p service

    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
    let executor = TaskExecutor::new(shutdown_tx);
    let custody_group_count = chain_config.custody_requirement;
    let libp2p_context = Context {
        chain_config: chain_config.clone_arc(),
        config,
        enr_fork_id: EnrForkId::default(),
        fork_context: Arc::new(ForkContext::dummy::<P>(chain_config, fork_name)),
        libp2p_registry: None,
    };

    Libp2pInstance(
        LibP2PService::new(
            chain_config.clone(),
            executor,
            libp2p_context,
            custody_group_count,
            secp256k1::Keypair::generate().into(),
        )
        .await
        .expect("should build libp2p instance")
        .0,
    )
}

#[allow(dead_code)]
pub fn get_enr<P: Preset>(node: &LibP2PService<P>) -> Enr {
    node.local_enr()
}

// Protocol for the node pair connection.
pub enum Protocol {
    Tcp,
    Quic,
}

// Constructs a pair of nodes with separate loggers. The sender dials the receiver.
// This returns a (sender, receiver) pair.
#[allow(dead_code)]
pub async fn build_node_pair<P: Preset>(
    chain_config: &Arc<ChainConfig>,
    fork_name: Phase,
    protocol: Protocol,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
) -> (Libp2pInstance<P>, Libp2pInstance<P>) {
    let mut sender = build_libp2p_instance::<P>(
        chain_config,
        vec![],
        "sender".to_string(),
        disable_peer_scoring,
        inbound_rate_limiter.clone(),
        fork_name,
    )
    .await;
    let mut receiver = build_libp2p_instance::<P>(
        chain_config,
        vec![],
        "receiver".to_string(),
        disable_peer_scoring,
        inbound_rate_limiter,
        fork_name,
    )
    .await;

    // let the two nodes set up listeners
    let sender_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(addr) = sender.next_event().await {
                // Only end once we've listened on the protocol we care about
                match protocol {
                    Protocol::Tcp => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::Tcp(_))
                        }) {
                            return addr;
                        }
                    }
                    Protocol::Quic => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::QuicV1)
                        }) {
                            return addr;
                        }
                    }
                }
            }
        }
    }
    .instrument(info_span!("Sender", who = "sender"));

    let receiver_fut = async {
        loop {
            if let NetworkEvent::NewListenAddr(addr) = receiver.next_event().await {
                match protocol {
                    Protocol::Tcp => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::Tcp(_))
                        }) {
                            return addr;
                        }
                    }
                    Protocol::Quic => {
                        if addr.iter().any(|multiaddr_proto| {
                            matches!(multiaddr_proto, libp2p::multiaddr::Protocol::QuicV1)
                        }) {
                            return addr;
                        }
                    }
                }
            }
        }
    }
    .instrument(info_span!("Receiver", who = "receiver"));

    let joined = futures::future::join(sender_fut, receiver_fut);

    let receiver_multiaddr = joined.await.1;

    match sender.testing_dial(receiver_multiaddr.clone()) {
        Ok(()) => {
            debug_with_peers!(address = ?receiver_multiaddr, "Sender dialed receiver")
        }
        Err(_) => error_with_peers!("Dialing failed"),
    };
    (sender, receiver)
}

// Returns `n` peers in a linear topology
#[allow(dead_code)]
pub async fn build_linear<P: Preset>(
    chain_config: &Arc<ChainConfig>,
    n: usize,
    fork_name: Phase,
) -> Vec<Libp2pInstance<P>> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(
            build_libp2p_instance::<P>(
                chain_config,
                vec![],
                "linear".to_string(),
                false,
                None,
                fork_name,
            )
            .await,
        );
    }

    let multiaddrs: Vec<Multiaddr> = nodes
        .iter()
        .map(|x| get_enr(x).multiaddr()[1].clone())
        .collect();
    for i in 0..n - 1 {
        match nodes[i].testing_dial(multiaddrs[i + 1].clone()) {
            Ok(()) => debug_with_peers!("Connected"),
            Err(_) => error_with_peers!("Failed to connect"),
        };
    }
    nodes
}
