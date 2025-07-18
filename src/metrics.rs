use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

pub use crate::common::metrics::{
    dec_gauge, dec_gauge_vec, get_int_counter, inc_counter, inc_counter_vec, inc_gauge,
    inc_gauge_vec, set_float_gauge, set_gauge, set_gauge_vec, try_create_float_gauge,
    try_create_float_gauge_vec, try_create_int_counter, try_create_int_counter_vec,
    try_create_int_gauge, try_create_int_gauge_vec,
};
use crate::{
    common::metrics::{get_int_gauge, set_gauge_entry, try_create_histogram},
    peer_manager::peerdb::client::ClientKind,
    types::GossipKind,
    GossipTopic, Gossipsub, NetworkGlobals,
};
use prometheus::{
    Gauge, GaugeVec, Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Result,
};
use strum::IntoEnumIterator as _;

pub static NAT_OPEN: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "nat_open",
        "An estimate indicating if the local node is reachable from external nodes",
        &["protocol"],
    )
});

pub static ADDRESS_UPDATE_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "libp2p_address_update_total",
        "Count of libp2p socked updated events (when our view of our IP address has changed)",
    )
});
pub static PEERS_CONNECTED: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("libp2p_peers", "Count of libp2p peers currently connected")
});

pub static PEERS_CONNECTED_MULTI: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "libp2p_peers_multi",
        "Count of libp2p peers currently connected",
        &["direction", "transport"],
    )
});

pub static TCP_PEERS_CONNECTED: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "libp2p_tcp_peers",
        "Count of libp2p peers currently connected via TCP",
    )
});

pub static QUIC_PEERS_CONNECTED: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "libp2p_quic_peers",
        "Count of libp2p peers currently connected via QUIC",
    )
});

pub static PEER_CONNECT_EVENT_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "libp2p_peer_connect_event_total",
        "Count of libp2p peer connect events (not the current number of connected peers)",
    )
});
pub static PEER_DISCONNECT_EVENT_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "libp2p_peer_disconnect_event_total",
        "Count of libp2p peer disconnect events",
    )
});
pub static DISCOVERY_BYTES: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "discovery_bytes",
        "The number of bytes sent and received in discovery",
        &["direction"],
    )
});
pub static DISCOVERY_QUEUE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "discovery_queue_size",
        "The number of discovery queries awaiting execution",
    )
});
pub static DISCOVERY_REQS: LazyLock<Result<Gauge>> = LazyLock::new(|| {
    try_create_float_gauge(
        "discovery_requests",
        "The number of unsolicited discovery requests per second",
    )
});
pub static DISCOVERY_SESSIONS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "discovery_sessions",
        "The number of active discovery sessions with peers",
    )
});

pub static DISCOVERY_NO_USEFUL_ENRS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "discovery_no_useful_enrs_found",
        "Total number of counts a query returned no useful ENRs to dial",
    )
});

pub static PEERS_PER_CLIENT: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "libp2p_peers_per_client",
        "The connected peers via client implementation",
        &["Client"],
    )
});

pub static PEERS_PER_SYNC_TYPE: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "sync_peers_per_status",
        "Number of connected peers per sync status type",
        &["sync_status"],
    )
});

pub static PEERS_PER_CUSTODY_SUBNET_COUNT: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "peers_per_custody_subnet_count",
        "The current count of peers by custody subnet count",
        &["custody_subnet_count"],
    )
});

pub static FAILED_ATTESTATION_PUBLISHES_PER_SUBNET: LazyLock<Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "gossipsub_failed_attestation_publishes_per_subnet",
            "Failed attestation publishes per subnet",
            &["subnet"],
        )
    });
pub static FAILED_PUBLISHES_PER_MAIN_TOPIC: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "gossipsub_failed_publishes_per_main_topic",
        "Failed gossip publishes",
        &["topic_hash"],
    )
});
pub static TOTAL_RPC_ERRORS_PER_CLIENT: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "libp2p_rpc_errors_per_client",
        "RPC errors per client",
        &["client", "rpc_error", "direction"],
    )
});
pub static TOTAL_RPC_REQUESTS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec("libp2p_rpc_requests_total", "RPC requests total", &["type"])
});
pub static PEER_ACTION_EVENTS_PER_CLIENT: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "libp2p_peer_actions_per_client",
        "Score reports per client",
        &["client", "action", "source"],
    )
});
pub static GOSSIP_UNACCEPTED_MESSAGES_PER_CLIENT: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "gossipsub_unaccepted_messages_per_client",
            "Gossipsub messages that we did not accept, per client",
            &["client", "validation_result"],
        )
    });
pub static GOSSIP_LATE_PUBLISH_PER_TOPIC_KIND: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "gossipsub_late_publish_per_topic_kind",
            "Messages published late to gossipsub per topic kind.",
            &["topic_kind"],
        )
    });
pub static GOSSIP_EXPIRED_LATE_PUBLISH_PER_TOPIC_KIND: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "gossipsub_expired_late_publish_per_topic_kind",
            "Messages that expired waiting to be published on retry to gossipsub per topic kind.",
            &["topic_kind"],
        )
    });
pub static GOSSIP_FAILED_LATE_PUBLISH_PER_TOPIC_KIND: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "gossipsub_failed_late_publish_per_topic_kind",
            "Messages that failed to be published on retry to gossipsub per topic kind.",
            &["topic_kind"],
        )
    });
pub static PEER_SCORE_DISTRIBUTION: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "peer_score_distribution",
        "The distribution of connected peer scores",
        &["position"],
    )
});
pub static PEER_SCORE_PER_CLIENT: LazyLock<Result<GaugeVec>> = LazyLock::new(|| {
    try_create_float_gauge_vec(
        "peer_score_per_client",
        "Average score per client",
        &["client"],
    )
});

pub static SUBNET_PEERS_FOUND: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "discovery_query_peers_found",
        "Total number of peers found in attestation subnets and sync subnets",
        &["type"],
    )
});
pub static TOTAL_SUBNET_QUERIES: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "discovery_total_queries",
        "Total number of discovery subnet queries",
        &["type"],
    )
});

pub static BEACON_BLOCK_MESH_PEERS_PER_CLIENT: LazyLock<Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "block_mesh_peers_per_client",
            "Number of mesh peers for BeaconBlock topic per client",
            &["Client"],
        )
    });

pub static BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT: LazyLock<Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "beacon_aggregate_and_proof_mesh_peers_per_client",
            "Number of mesh peers for BeaconAggregateAndProof topic per client",
            &["Client"],
        )
    });

pub static RPC_RECV_BYTES: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter("rpc_recv_bytes", "The number of bytes received in RPC")
});

pub static RPC_SENT_BYTES: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| try_create_int_counter("rpc_sent_bytes", "The number of bytes sent in RPC"));

pub static RPC_TOTAL_BYTES: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "rpc_total_bytes",
        "The number of bytes sent and received in RPC",
    )
});

/*
 * Peer Reporting
 */
pub static REPORT_PEER_MSGS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "libp2p_report_peer_msgs_total",
        "Number of peer reports per msg",
        &["msg"],
    )
});

pub static OUTBOUND_REQUEST_IDLING: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "outbound_request_idling_seconds",
        "The time our own request remained idle in the self-limiter",
    )
});

pub static RESPONSE_IDLING: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "response_idling_seconds",
        "The time our response remained idle in the response limiter",
    )
});

pub fn update_discovery_metrics() {
    let metrics =
        discv5::metrics::Metrics::from(discv5::Discv5::<discv5::DefaultProtocolId>::raw_metrics());

    set_float_gauge(&DISCOVERY_REQS, metrics.unsolicited_requests_per_second);
    set_gauge(&DISCOVERY_SESSIONS, metrics.active_sessions as i64);
    set_gauge_vec(&DISCOVERY_BYTES, &["inbound"], metrics.bytes_recv as i64);
    set_gauge_vec(&DISCOVERY_BYTES, &["outbound"], metrics.bytes_sent as i64);
    set_gauge_vec(&NAT_OPEN, &["discv5_ipv4"], metrics.ipv4_contactable as i64);
    set_gauge_vec(&NAT_OPEN, &["discv5_ipv6"], metrics.ipv6_contactable as i64);
}

pub fn update_gossipsub_extended_metrics(
    gossipsub: &Gossipsub,
    network_globals: &Arc<NetworkGlobals>,
) {
    // Mesh peers per client
    // Reset the gauges
    for client_kind in ClientKind::iter() {
        set_gauge_vec(
            &BEACON_BLOCK_MESH_PEERS_PER_CLIENT,
            &[client_kind.as_ref()],
            0_i64,
        );
        set_gauge_vec(
            &BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT,
            &[client_kind.as_ref()],
            0_i64,
        );
    }

    for topic_hash in gossipsub.topics() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::Attestation(_subnet_id) => {}
                GossipKind::BeaconBlock => {
                    for peer_id in gossipsub.mesh_peers(topic_hash) {
                        let client = network_globals
                            .peers
                            .read()
                            .peer_info(peer_id)
                            .map(|peer_info| peer_info.client().kind.into())
                            .unwrap_or_else(|| "Unknown");
                        if let Some(v) =
                            get_int_gauge(&BEACON_BLOCK_MESH_PEERS_PER_CLIENT, &[client])
                        {
                            v.inc()
                        };
                    }
                }
                GossipKind::BeaconAggregateAndProof => {
                    for peer_id in gossipsub.mesh_peers(topic_hash) {
                        let client = network_globals
                            .peers
                            .read()
                            .peer_info(peer_id)
                            .map(|peer_info| peer_info.client().kind.into())
                            .unwrap_or_else(|| "Unknown");
                        if let Some(v) = get_int_gauge(
                            &BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT,
                            &[client],
                        ) {
                            v.inc()
                        };
                    }
                }
                GossipKind::SyncCommitteeMessage(_subnet_id) => {}
                _kind => {}
            }
        }
    }
}

pub fn update_sync_metrics(network_globals: &Arc<NetworkGlobals>) {
    // reset the counts
    if PEERS_PER_SYNC_TYPE
        .as_ref()
        .map(|metric| metric.reset())
        .is_err()
    {
        return;
    };

    // count per sync status, the number of connected peers
    let mut peers_per_sync_type = HashMap::<&'static str, i64>::default();

    for sync_type in network_globals
        .peers
        .read()
        .connected_peers()
        .map(|(_peer_id, info)| info.sync_status().as_str())
    {
        *peers_per_sync_type.entry(sync_type).or_default() += 1;
    }

    for (sync_type, peer_count) in peers_per_sync_type {
        set_gauge_entry(&PEERS_PER_SYNC_TYPE, &[sync_type], peer_count);
    }
}
