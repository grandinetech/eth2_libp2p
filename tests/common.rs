#![cfg(test)]
use eth2_libp2p::service::Network as LibP2PService;
use eth2_libp2p::types::{EnrForkId, ForkContext};
use eth2_libp2p::Multiaddr;
use eth2_libp2p::TaskExecutor;
use eth2_libp2p::{Context, Enr, EnrExt};
use eth2_libp2p::{NetworkConfig, NetworkEvent};
use slog::{debug, error, o, Drain};
use std::sync::Arc;
use std_ext::ArcExt as _;
use types::{config::Config as ChainConfig, nonstandard::Phase, preset::Preset};

type ReqId = usize;

use eth2_libp2p::rpc::config::InboundRateLimiterConfig;

use tempfile::Builder as TempBuilder;
pub struct Libp2pInstance<P: Preset>(LibP2PService<ReqId, P>);

impl<P: Preset> std::ops::Deref for Libp2pInstance<P> {
    type Target = LibP2PService<ReqId, P>;
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
    config.network_dir = Some(path.into_path());
    config.disable_peer_scoring = disable_peer_scoring;
    config.inbound_rate_limiter_config = inbound_rate_limiter;

    Arc::new(config)
}

pub async fn build_libp2p_instance<P: Preset>(
    chain_config: &Arc<ChainConfig>,
    boot_nodes: Vec<Enr>,
    log: slog::Logger,
    fork_name: Phase,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
) -> Libp2pInstance<P> {
    let config = build_config(boot_nodes, disable_peer_scoring, inbound_rate_limiter);
    // launch libp2p service

    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
    let executor = TaskExecutor::new(log.clone(), shutdown_tx);
    let libp2p_context = Context {
        chain_config: chain_config.clone_arc(),
        config,
        enr_fork_id: EnrForkId::default(),
        fork_context: Arc::new(ForkContext::dummy::<P>(chain_config, fork_name)),
        libp2p_registry: None,
    };

    Libp2pInstance(
        LibP2PService::new(chain_config.clone(), executor, libp2p_context, &log)
            .await
            .expect("should build libp2p instance")
            .0,
    )
}

#[allow(dead_code)]
pub fn get_enr<P: Preset>(node: &LibP2PService<ReqId, P>) -> Enr {
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
    log: &slog::Logger,
    fork_name: Phase,
    protocol: Protocol,
    disable_peer_scoring: bool,
    inbound_rate_limiter: Option<InboundRateLimiterConfig>,
) -> (Libp2pInstance<P>, Libp2pInstance<P>) {
    let sender_log = log.new(o!("who" => "sender"));
    let receiver_log = log.new(o!("who" => "receiver"));

    let mut sender = build_libp2p_instance::<P>(
        chain_config,
        vec![],
        sender_log,
        fork_name,
        disable_peer_scoring,
        inbound_rate_limiter,
    )
    .await;
    let mut receiver = build_libp2p_instance::<P>(
        chain_config,
        vec![],
        receiver_log,
        fork_name,
        disable_peer_scoring,
        inbound_rate_limiter,
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
    };
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
    };

    let joined = futures::future::join(sender_fut, receiver_fut);

    let receiver_multiaddr = joined.await.1;

    match sender.testing_dial(receiver_multiaddr.clone()) {
        Ok(()) => {
            debug!(log, "Sender dialed receiver"; "address" => format!("{:?}", receiver_multiaddr))
        }
        Err(_) => error!(log, "Dialing failed"),
    };
    (sender, receiver)
}

// Returns `n` peers in a linear topology
#[allow(dead_code)]
pub async fn build_linear<P: Preset>(
    chain_config: &Arc<ChainConfig>,
    log: slog::Logger,
    n: usize,
    fork_name: Phase,
) -> Vec<Libp2pInstance<P>> {
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        nodes.push(
            build_libp2p_instance::<P>(chain_config, vec![], log.clone(), fork_name, false, None)
                .await,
        );
    }

    let multiaddrs: Vec<Multiaddr> = nodes
        .iter()
        .map(|x| get_enr(x).multiaddr()[1].clone())
        .collect();
    for i in 0..n - 1 {
        match nodes[i].testing_dial(multiaddrs[i + 1].clone()) {
            Ok(()) => debug!(log, "Connected"),
            Err(_) => error!(log, "Failed to connect"),
        };
    }
    nodes
}
