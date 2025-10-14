#![cfg(test)]
use common::{build_tracing_subscriber, Protocol};
use eth2_libp2p::rpc::{methods::*, RequestType};
use eth2_libp2p::{service::api_types::AppRequestId, NetworkEvent, ReportSource, Response};
use helper_functions::misc;
use logging::{debug_with_peers, error_with_peers, warn_with_peers};
use ssz::{ByteList, ContiguousList, DynamicList, SszRead as _, SszReadDefault, SszWrite};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{info_span, Instrument};
use try_from_iterator::TryFromIterator;
use typenum::Unsigned as _;
use types::deneb::containers::BlobSidecar;
use types::fulu::containers::{DataColumnSidecar, DataColumnsByRootIdentifier};
use types::phase0::primitives::H32;
use types::{
    bellatrix::containers::{
        BeaconBlock as BellatrixBeaconBlock, BeaconBlockBody as BellatrixBeaconBlockBody,
        ExecutionPayload, SignedBeaconBlock as BellatrixSignedBeaconBlock,
    },
    config::Config,
    nonstandard::Phase,
    phase0::{
        containers::SignedBeaconBlock as Phase0SignedBeaconBlock,
        primitives::{ForkDigest, H256},
    },
    preset::{Mainnet, Preset},
};

mod common;
mod factory;

/// Bellatrix block with length < max_rpc_size.
fn bellatrix_block_small<P: Preset>(config: &Config) -> BellatrixSignedBeaconBlock<P> {
    let tx = ByteList::<P::MaxBytesPerTransaction>::from_ssz_default([0; 1024]).unwrap();
    let txs = Arc::new(ContiguousList::try_from_iter(std::iter::repeat_n(tx, 5000)).unwrap());

    let block = BellatrixSignedBeaconBlock {
        message: BellatrixBeaconBlock {
            body: BellatrixBeaconBlockBody {
                execution_payload: ExecutionPayload {
                    transactions: txs,
                    ..ExecutionPayload::default()
                },
                ..BellatrixBeaconBlockBody::default()
            },
            slot: misc::compute_start_slot_at_epoch::<P>(config.bellatrix_fork_epoch),
            ..BellatrixBeaconBlock::default()
        },
        ..BellatrixSignedBeaconBlock::default()
    };

    assert!(block.to_ssz().unwrap().len() <= Config::default().max_payload_size);
    block
}

/// Bellatrix block with length > MAX_RPC_SIZE.
/// The max limit for a merge block is in the order of ~16GiB which wouldn't fit in memory.
/// Hence, we generate a merge block just greater than `MAX_RPC_SIZE` to test rejection on the rpc layer.
fn bellatrix_block_large<P: Preset>(config: &Config) -> BellatrixSignedBeaconBlock<P> {
    let tx = ByteList::<P::MaxBytesPerTransaction>::from_ssz_default([0; 1024]).unwrap();
    let txs = Arc::new(ContiguousList::try_from_iter(std::iter::repeat_n(tx, 100000)).unwrap());

    let block = BellatrixSignedBeaconBlock {
        message: BellatrixBeaconBlock {
            body: BellatrixBeaconBlockBody {
                execution_payload: ExecutionPayload {
                    transactions: txs,
                    ..ExecutionPayload::default()
                },
                ..BellatrixBeaconBlockBody::default()
            },
            slot: misc::compute_start_slot_at_epoch::<P>(config.bellatrix_fork_epoch),
            ..BellatrixBeaconBlock::default()
        },
        ..BellatrixSignedBeaconBlock::default()
    };

    assert!(block.to_ssz().unwrap().len() > Config::default().max_payload_size);
    block
}

// Tests the STATUS RPC message
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_status_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;

    build_tracing_subscriber(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(
        &Config::mainnet().rapid_upgrade().into(),
        Phase::Phase0,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // Dummy STATUS RPC message
    let rpc_request = RequestType::Status(StatusMessage::V2(StatusMessageV2 {
        fork_digest: ForkDigest::zero(),
        finalized_root: H256::zero(),
        finalized_epoch: 1,
        head_root: H256::zero(),
        head_slot: 1,
        earliest_available_slot: 0,
    }));

    // Dummy STATUS RPC message
    let rpc_response = Response::Status::<Mainnet>(StatusMessage::V2(StatusMessageV2 {
        fork_digest: ForkDigest::zero(),
        finalized_root: H256::zero(),
        finalized_epoch: 1,
        head_root: H256::zero(),
        head_slot: 1,
        earliest_available_slot: 0,
    }));

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, AppRequestId::Application(10), rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: AppRequestId::Application(10),
                    response,
                } => {
                    // Should receive the RPC response
                    debug_with_peers!("Sender Received");
                    assert_eq!(response, rpc_response.clone());
                    debug_with_peers!("Sender Completed");
                    return;
                }
                _ => {}
            }
        }
    }
    .instrument(info_span!("Sender"));

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        debug_with_peers!("Receiver Received");
                        receiver.send_response(peer_id, inbound_request_id, rpc_response.clone());
                    }
                }
                _ => {} // Ignore other events
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

// Tests a streamed BlocksByRange RPC Message
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_blocks_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;

    let messages_to_send = 6;

    build_tracing_subscriber(log_level, enable_logging);
    let config = Arc::new(Config::mainnet().rapid_upgrade());

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        Phase::Bellatrix,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // BlocksByRange Request
    let rpc_request =
        RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2 {
            start_slot: misc::compute_start_slot_at_epoch::<Mainnet>(config.deneb_fork_epoch),
            count: messages_to_send,
            step: 1,
        }));

    // BlocksByRange Response
    let signed_full_block = factory::full_phase0_signed_beacon_block().into();
    let rpc_response_base = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

    let signed_full_block = factory::full_altair_signed_beacon_block(&config).into();
    let rpc_response_altair = Response::BlocksByRange(Some(Arc::new(signed_full_block)));
    let signed_full_block = bellatrix_block_small(&config).into();
    let rpc_response_merge_small = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

    // keep count of the number of messages received
    let mut messages_received = 0;
    let request_id = AppRequestId::Application(messages_to_send as usize);
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, request_id, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: _,
                    response,
                } => {
                    warn_with_peers!("Sender received a response");
                    match response {
                        Response::BlocksByRange(Some(_)) => {
                            if messages_received < 2 {
                                assert_eq!(response, rpc_response_base.clone());
                            } else if messages_received < 4 {
                                assert_eq!(response, rpc_response_altair.clone());
                            } else {
                                assert_eq!(response, rpc_response_merge_small.clone());
                            }
                            messages_received += 1;
                            warn_with_peers!("Chunk received");
                        }
                        Response::BlocksByRange(None) => {
                            // should be exactly `messages_to_send` messages before terminating
                            assert_eq!(messages_received, messages_to_send);
                            // end the test
                            return;
                        }
                        _ => panic!("Invalid RPC received"),
                    }
                }
                _ => {} // Ignore other behaviour events
            }
        }
    }
    .instrument(info_span!("Sender"));

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        warn_with_peers!("Receiver got request");
                        for i in 0..messages_to_send {
                            // Send first half of responses as base blocks and
                            // second half as altair blocks.
                            let rpc_response = if i < 2 {
                                rpc_response_base.clone()
                            } else if i < 4 {
                                rpc_response_altair.clone()
                            } else {
                                rpc_response_merge_small.clone()
                            };
                            debug_with_peers!("Sending RPC response");
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                rpc_response.clone(),
                            );
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(10)) => {
            panic!("Future timed out");
        }
    }
}

// Tests a streamed BlobsByRange RPC Message
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_blobs_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;

    let slot_count = 32;
    let messages_to_send = 34;

    build_tracing_subscriber(log_level, enable_logging);
    let config = Arc::new(Config::mainnet().rapid_upgrade());

    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        Phase::Deneb,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // BlobsByRange Request
    let deneb_slot = misc::compute_start_slot_at_epoch::<Mainnet>(config.deneb_fork_epoch);
    let rpc_request = RequestType::BlobsByRange(BlobsByRangeRequest {
        start_slot: deneb_slot,
        count: slot_count,
    });

    // BlocksByRange Response
    let mut blob = BlobSidecar::<Mainnet>::default();
    blob.signed_block_header.message.slot = deneb_slot;
    let rpc_response = Response::BlobsByRange(Some(Arc::new(blob)));

    // keep count of the number of messages received
    let mut messages_received = 0;
    let request_id = AppRequestId::Application(messages_to_send as usize);
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, request_id, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: _,
                    response,
                } => {
                    warn_with_peers!("Sender received a response");
                    match response {
                        Response::BlobsByRange(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                            warn_with_peers!("Chunk received");
                        }
                        Response::BlobsByRange(None) => {
                            // should be exactly `messages_to_send` messages before terminating
                            assert_eq!(messages_received, messages_to_send);
                            // end the test
                            return;
                        }
                        _ => panic!("Invalid RPC received"),
                    }
                }
                _ => {} // Ignore other behaviour events
            }
        }
    }
    .instrument(info_span!("Sender"));

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        warn_with_peers!("Receiver got request");
                        for _ in 0..messages_to_send {
                            // Send first third of responses as base blocks,
                            // second as altair and third as merge.
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                rpc_response.clone(),
                            );
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::BlobsByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
                panic!("Future timed out");
        }
    }
}

// Tests rejection of blocks over `MAX_RPC_SIZE`.
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_blocks_by_range_over_limit() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;

    let config = Arc::new(Config::mainnet().rapid_upgrade());
    let messages_to_send = 5;

    // BlocksByRange Request
    let rpc_request =
        RequestType::BlocksByRange(OldBlocksByRangeRequest::V1(OldBlocksByRangeRequestV1 {
            start_slot: 0,
            count: messages_to_send,
            step: 1,
        }));

    build_tracing_subscriber(log_level, enable_logging);

    let (mut sender, mut receiver) =
        common::build_node_pair::<Mainnet>(&config, Phase::Bellatrix, Protocol::Tcp, false, None)
            .await;

    // BlocksByRange Response
    let signed_full_block = bellatrix_block_large(&config).into();
    let rpc_response_merge_large = Response::BlocksByRange(Some(Arc::new(signed_full_block)));
    let request_id = AppRequestId::Application(messages_to_send as usize);

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, request_id, rpc_request.clone())
                        .unwrap();
                }
                // The request will fail because the sender will refuse to send anything > MAX_RPC_SIZE
                NetworkEvent::RPCFailed { app_request_id, .. } => {
                    assert_eq!(app_request_id, request_id);
                    return;
                }
                _ => {} // Ignore other behaviour events
            }
        }
    }
    .instrument(info_span!("Sender"));

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        warn_with_peers!("Receiver got request");
                        for _ in 0..messages_to_send {
                            let rpc_response = rpc_response_merge_large.clone();
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                rpc_response.clone(),
                            );
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
                panic!("Future timed out");
        }
    }
}

// Tests that a streamed BlocksByRange RPC Message terminates when all expected chunks were received
#[tokio::test]
async fn test_tcp_blocks_by_range_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;

    let messages_to_send = 10;
    let extra_messages_to_send = 10;

    build_tracing_subscriber(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        Phase::Phase0,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // BlocksByRange Request
    let rpc_request =
        RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2 {
            start_slot: 0,
            count: messages_to_send,
            step: 1,
        }));

    // BlocksByRange Response
    let empty_signed = Phase0SignedBeaconBlock::default().into();
    let rpc_response = Response::BlocksByRange(Some(Arc::new(empty_signed)));

    // keep count of the number of messages received
    let mut messages_received: u64 = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, AppRequestId::Internal, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: _,
                    response,
                } =>
                // Should receive the RPC response
                {
                    debug_with_peers!("Sender received a response");
                    match response {
                        Response::BlocksByRange(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                        }
                        Response::BlocksByRange(None) => {
                            // should be exactly 10 messages, as requested
                            assert_eq!(messages_received, messages_to_send);
                        }
                        _ => panic!("Invalid RPC received"),
                    }
                }

                _ => {} // Ignore other behaviour events
            }
        }
    }
    .instrument(info_span!("Sender"));

    // determine messages to send (PeerId, RequestId). If some, indicates we still need to send
    // messages
    let mut message_info = None;
    // the number of messages we've sent
    let mut messages_sent = 0;
    let receiver_future = async {
        loop {
            // this future either drives the sending/receiving or times out allowing messages to be
            // sent in the timeout
            match futures::future::select(
                Box::pin(receiver.next_event()),
                Box::pin(tokio::time::sleep(Duration::from_secs(1))),
            )
            .await
            {
                futures::future::Either::Left((
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    },
                    _,
                )) => {
                    if request_type == rpc_request {
                        // send the response
                        warn_with_peers!("Receiver got request");
                        message_info = Some((peer_id, inbound_request_id));
                    }
                }
                futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                _ => continue,
            }

            // if we need to send messages send them here. This will happen after a delay
            if message_info.is_some() {
                messages_sent += 1;
                let (peer_id, inbound_request_id) = message_info.as_ref().unwrap();
                receiver.send_response(*peer_id, *inbound_request_id, rpc_response.clone());
                debug_with_peers!("Sending message {}", messages_sent);
                if messages_sent == messages_to_send + extra_messages_to_send {
                    // stop sending messages
                    return;
                }
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

// Tests an empty response to a BlocksByRange RPC Message
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_blocks_by_range_single_empty_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = "trace";
    let enable_logging = false;

    build_tracing_subscriber(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        Phase::Phase0,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // BlocksByRange Request
    let rpc_request =
        RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2 {
            start_slot: 0,
            count: 10,
            step: 1,
        }));

    // BlocksByRange Response
    let empty_signed = Phase0SignedBeaconBlock::default().into();
    let rpc_response = Response::BlocksByRange(Some(Arc::new(empty_signed)));

    let messages_to_send = 1;

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, AppRequestId::Application(10), rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: AppRequestId::Application(10),
                    response,
                } => match response {
                    Response::BlocksByRange(Some(_)) => {
                        assert_eq!(response, rpc_response.clone());
                        messages_received += 1;
                        warn_with_peers!("Chunk received");
                    }
                    Response::BlocksByRange(None) => {
                        // should be exactly 10 messages before terminating
                        assert_eq!(messages_received, messages_to_send);
                        // end the test
                        return;
                    }
                    _ => panic!("Invalid RPC received"),
                },
                _ => {} // Ignore other behaviour events
            }
        }
    }
    .instrument(info_span!("Sender"));

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        warn_with_peers!("Receiver got request");

                        for _ in 1..=messages_to_send {
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                rpc_response.clone(),
                            );
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(20)) => {
            panic!("Future timed out");
        }
    }
}

// Tests a streamed, chunked BlocksByRoot RPC Message
// The size of the response is a full `BeaconBlock`
// which is greater than the Snappy frame size. Hence, this test
// serves to test the snappy framing format as well.
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_blocks_by_root_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;

    let messages_to_send = 6;

    build_tracing_subscriber(log_level, enable_logging);
    let config = Arc::new(Config::mainnet().rapid_upgrade());

    // get sender/receiver
    let (mut sender, mut receiver) =
        common::build_node_pair(&config, Phase::Bellatrix, Protocol::Tcp, false, None).await;

    // BlocksByRoot Request
    let rpc_request = RequestType::BlocksByRoot(BlocksByRootRequest::new(
        &config,
        Phase::Phase0,
        vec![H256::zero(); 6].into_iter(),
    ));
    // BlocksByRoot Response
    let signed_full_block = factory::full_phase0_signed_beacon_block().into();
    let rpc_response_base = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

    let signed_full_block = factory::full_altair_signed_beacon_block(&config).into();
    let rpc_response_altair = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));
    let signed_full_block = bellatrix_block_small::<Mainnet>(&config).into();
    let rpc_response_merge_small = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, AppRequestId::Application(6), rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: AppRequestId::Application(6),
                    response,
                } => match response {
                    Response::BlocksByRoot(Some(_)) => {
                        if messages_received < 2 {
                            assert_eq!(response, rpc_response_base.clone());
                        } else if messages_received < 4 {
                            assert_eq!(response, rpc_response_altair.clone());
                        } else {
                            assert_eq!(response, rpc_response_merge_small.clone());
                        };
                        messages_received += 1;
                        debug_with_peers!("Chunk received");
                    }
                    Response::BlocksByRoot(None) => {
                        // should be exactly messages_to_send
                        assert_eq!(messages_received, messages_to_send);
                        // end the test
                        return;
                    }
                    _ => {} // Ignore other RPC messages
                },
                _ => {} // Ignore other behaviour events
            }
        }
    }
    .instrument(info_span!("Sender"));

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        debug_with_peers!("Receiver got request");

                        for i in 0..messages_to_send {
                            // Send first half of responses as base blocks and
                            // second half as altair blocks.
                            let rpc_response = if i < 2 {
                                // debug_with_peers!("Sending base block");
                                rpc_response_base.clone()
                            } else if i < 4 {
                                // debug_with_peers!("Sending altair block");
                                rpc_response_altair.clone()
                            } else {
                                // debug_with_peers!("Sending merge block");
                                rpc_response_merge_small.clone()
                            };
                            receiver.send_response(peer_id, inbound_request_id, rpc_response);
                            debug_with_peers!("Sending message");
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::BlocksByRoot(None),
                        );
                        debug_with_peers!("Send stream term");
                    }
                }
                _ => {} // Ignore other events
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_columns_by_root_chunked_rpc() {
    // set up the logging.
    let log_level = "debug";
    let enable_logging = false;
    build_tracing_subscriber(log_level, enable_logging);
    let num_of_columns = <Mainnet as Preset>::NumberOfColumns::U64;
    let messages_to_send = 32 * num_of_columns;

    let mut config = Config::mainnet().rapid_upgrade();
    // check if `max_data_columns_by_root_request` derived as expected with `max_request_blocks_deneb` changed
    config.max_request_blocks_deneb = 256;
    let config = Arc::new(config);
    let current_fork_name = Phase::Fulu;

    // get sender/receiver
    let (mut sender, mut receiver) =
        common::build_node_pair::<Mainnet>(&config, current_fork_name, Protocol::Tcp, false, None)
            .await;

    // DataColumnsByRootRequest Request
    let max_request_blocks = config.max_request_blocks_deneb as usize;
    let req = DataColumnsByRootRequest::new(
        &config,
        vec![
            DataColumnsByRootIdentifier {
                block_root: H256::zero(),
                columns: ContiguousList::try_from_iter(0..num_of_columns).unwrap(),
            };
            max_request_blocks
        ]
        .into_iter(),
    );
    let req_decoded = DataColumnsByRootRequest {
        data_column_ids: DynamicList::from_ssz(
            &max_request_blocks,
            &req.data_column_ids.to_ssz().unwrap(),
        )
        .unwrap(),
    };
    assert_eq!(req, req_decoded);
    let rpc_request = RequestType::DataColumnsByRoot(req);

    // DataColumnsByRoot Response
    let mut data_column_sidecar = DataColumnSidecar::default();
    data_column_sidecar.signed_block_header.message.slot =
        misc::compute_start_slot_at_epoch::<Mainnet>(config.fulu_fork_epoch);
    let data_column = Arc::new(data_column_sidecar);

    let rpc_response = Response::DataColumnsByRoot(Some(data_column.clone()));

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, AppRequestId::Application(6), rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: AppRequestId::Application(6),
                    response,
                } => match response {
                    Response::DataColumnsByRoot(Some(sidecar)) => {
                        assert_eq!(sidecar, data_column.clone());
                        messages_received += 1;
                        debug_with_peers!("Chunk received");
                    }
                    Response::DataColumnsByRoot(None) => {
                        // should be exactly messages_to_send
                        assert_eq!(messages_received, messages_to_send);
                        // end the test
                        return;
                    }
                    _ => {} // Ignore other RPC messages
                },
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        debug_with_peers!("Receiver got request");

                        for _ in 0..messages_to_send {
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                rpc_response.clone(),
                            );
                            debug_with_peers!("Sending message");
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::DataColumnsByRoot(None),
                        );
                        debug_with_peers!("Send stream term");
                    }
                }
                e => {
                    debug_with_peers!("Got event {:?}", e);
                } // Ignore other events
            }
        }
    };
    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(300)) => {
            panic!("Future timed out");
        }
    }
}

#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_columns_by_range_chunked_rpc() {
    // set up the logging.
    let log_level = "debug";
    let enable_logging = false;
    build_tracing_subscriber(log_level, enable_logging);
    let messages_to_send = 32;
    let config = Arc::new(Config::mainnet().rapid_upgrade());

    // get sender/receiver
    let (mut sender, mut receiver) =
        common::build_node_pair::<Mainnet>(&config, Phase::Fulu, Protocol::Tcp, false, None).await;

    // DataColumnsByRange Request
    let number_of_columns = <Mainnet as Preset>::NumberOfColumns::U64;
    let rpc_request = RequestType::DataColumnsByRange(DataColumnsByRangeRequest {
        start_slot: misc::compute_start_slot_at_epoch::<Mainnet>(config.fulu_fork_epoch),
        count: messages_to_send,
        columns: Arc::new(ContiguousList::try_from_iter(0..number_of_columns).unwrap()),
    });

    // DataColumnsByRange Response
    let mut data_column_sidecar = DataColumnSidecar::default();
    data_column_sidecar.signed_block_header.message.slot =
        misc::compute_start_slot_at_epoch::<Mainnet>(config.fulu_fork_epoch);
    let data_column = Arc::new(data_column_sidecar);

    let rpc_response = Response::DataColumnsByRange(Some(data_column.clone()));

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, AppRequestId::Application(6), rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: AppRequestId::Application(6),
                    response,
                } => match response {
                    Response::DataColumnsByRange(Some(sidecar)) => {
                        assert_eq!(sidecar, data_column.clone());
                        messages_received += 1;
                        debug_with_peers!("Chunk received");
                    }
                    Response::DataColumnsByRange(None) => {
                        // should be exactly messages_to_send
                        assert_eq!(messages_received, messages_to_send);
                        // end the test
                        return;
                    }
                    _ => {} // Ignore other RPC messages
                },
                _ => {} // Ignore other behaviour events
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                } => {
                    if request_type == rpc_request {
                        // send the response
                        debug_with_peers!("Receiver got request");

                        for _ in 0..messages_to_send {
                            receiver.send_response(
                                peer_id,
                                inbound_request_id,
                                rpc_response.clone(),
                            );
                            debug_with_peers!("Sending message");
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::DataColumnsByRange(None),
                        );
                        debug_with_peers!("Send stream term");
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };
    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(300)) => {
            panic!("Future timed out");
        }
    }
}

// Tests a streamed, chunked BlocksByRoot RPC Message terminates when all expected reponses have been received
#[tokio::test]
async fn test_tcp_blocks_by_root_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;
    let messages_to_send: u64 = 10;
    let extra_messages_to_send: u64 = 10;
    let config = Arc::new(Config::mainnet().rapid_upgrade());

    build_tracing_subscriber(log_level, enable_logging);

    // get sender/receiver

    let (mut sender, mut receiver) =
        common::build_node_pair::<Mainnet>(&config, Phase::Bellatrix, Protocol::Tcp, false, None)
            .await;

    // BlocksByRoot Request
    let rpc_request = RequestType::BlocksByRoot(BlocksByRootRequest::new(
        &config,
        Phase::Phase0,
        vec![H256::zero(); 10].into_iter(),
    ));

    // BlocksByRoot Response
    let signed_full_block = Phase0SignedBeaconBlock::default().into();
    let rpc_response = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug_with_peers!("Sending RPC");
                    sender
                        .send_request(peer_id, AppRequestId::Application(10), rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    app_request_id: AppRequestId::Application(10),
                    response,
                } => {
                    debug_with_peers!("Sender received a response");
                    match response {
                        Response::BlocksByRoot(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                            debug_with_peers!("Chunk received");
                        }
                        Response::BlocksByRoot(None) => {
                            // should be exactly messages_to_send
                            assert_eq!(messages_received, messages_to_send);
                            // end the test
                            return;
                        }
                        _ => {} // Ignore other RPC messages
                    }
                }
                _ => {} // Ignore other behaviour events
            }
        }
    }
    .instrument(info_span!("Sender"));

    // determine messages to send (PeerId, RequestId). If some, indicates we still need to send
    // messages
    let mut message_info = None;
    // the number of messages we've sent
    let mut messages_sent = 0;
    let receiver_future = async {
        loop {
            // this future either drives the sending/receiving or times out allowing messages to be
            // sent in the timeout
            match futures::future::select(
                Box::pin(receiver.next_event()),
                Box::pin(tokio::time::sleep(Duration::from_secs(1))),
            )
            .await
            {
                futures::future::Either::Left((
                    NetworkEvent::RequestReceived {
                        peer_id,
                        inbound_request_id,
                        request_type,
                    },
                    _,
                )) => {
                    if request_type == rpc_request {
                        // send the response
                        warn_with_peers!("Receiver got request");
                        message_info = Some((peer_id, inbound_request_id));
                    }
                }
                futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                _ => continue,
            }

            // if we need to send messages send them here. This will happen after a delay
            if message_info.is_some() {
                messages_sent += 1;
                let (peer_id, inbound_request_id) = message_info.as_ref().unwrap();
                receiver.send_response(*peer_id, *inbound_request_id, rpc_response.clone());
                debug_with_peers!("Sending message {}", messages_sent);
                if messages_sent == messages_to_send + extra_messages_to_send {
                    // stop sending messages
                    return;
                }
            }
        }
    }
    .instrument(info_span!("Receiver"));

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

/// Establishes a pair of nodes and disconnects the pair based on the selected protocol via an RPC
/// Goodbye message.
#[allow(clippy::single_match)]
async fn goodbye_test(log_level: &str, enable_logging: bool, protocol: Protocol) {
    build_tracing_subscriber(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        Phase::Phase0,
        protocol,
        false,
        None,
    )
    .await;

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a goodbye and disconnect
                    debug_with_peers!("Sending RPC");
                    sender.goodbye_peer(
                        &peer_id,
                        GoodbyeReason::IrrelevantNetwork,
                        ReportSource::SyncService,
                    );
                }
                NetworkEvent::PeerDisconnected(_) => {
                    return;
                }
                _ => {} // Ignore other RPC messages
            }
        }
    }
    .instrument(info_span!("Sender"));

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::PeerDisconnected(_) => {
                    // Should receive sent RPC request
                    return;
                }
                _ => {} // Ignore other events
            }
        }
    }
    .instrument(info_span!("Receiver"));

    let total_future = futures::future::join(sender_future, receiver_future);

    tokio::select! {
        _ = total_future => {}
        _ = sleep(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

// Tests a Goodbye RPC message
#[tokio::test]
#[allow(clippy::single_match)]
async fn tcp_test_goodbye_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;
    goodbye_test(log_level, enable_logging, Protocol::Tcp).await;
}

// Tests a Goodbye RPC message
#[tokio::test]
#[allow(clippy::single_match)]
async fn quic_test_goodbye_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;
    goodbye_test(log_level, enable_logging, Protocol::Quic).await;
}

// Test that the receiver delays the responses during response rate-limiting.
#[tokio::test]
async fn test_delayed_rpc_response() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;
    let config = Arc::new(Config::mainnet().rapid_upgrade());
    build_tracing_subscriber(log_level, enable_logging);

    // Allow 1 token to be use used every 3 seconds.
    const QUOTA_SEC: u64 = 3;

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &config,
        Phase::Phase0,
        Protocol::Tcp,
        false,
        // Configure a quota for STATUS responses of 1 token every 3 seconds.
        Some(format!("status:1/{QUOTA_SEC}").parse().unwrap()),
    )
    .await;

    // Dummy STATUS RPC message
    let rpc_request = RequestType::Status(StatusMessage::V2(StatusMessageV2 {
        fork_digest: H32::default(),
        finalized_root: H256::default(),
        finalized_epoch: 1,
        head_root: H256::default(),
        head_slot: 1,
        earliest_available_slot: 0,
    }));

    // Dummy STATUS RPC message
    let rpc_response = Response::Status(StatusMessage::V2(StatusMessageV2 {
        fork_digest: H32::default(),
        finalized_root: H256::default(),
        finalized_epoch: 1,
        head_root: H256::default(),
        head_slot: 1,
        earliest_available_slot: 0,
    }));

    // build the sender future
    let sender_future = async {
        let mut request_id = 1;
        let mut request_sent_at = Instant::now();
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    debug_with_peers!(%request_id, "Sending RPC request");
                    sender
                        .send_request(
                            peer_id,
                            AppRequestId::Application(request_id),
                            rpc_request.clone(),
                        )
                        .unwrap();
                    request_sent_at = Instant::now();
                }
                NetworkEvent::ResponseReceived {
                    peer_id,
                    app_request_id: _,
                    response,
                } => {
                    debug_with_peers!(%request_id, elapsed = ?request_sent_at.elapsed(), "Sender received response");
                    assert_eq!(response, rpc_response);

                    match request_id {
                        1 => {
                            // The first response is returned instantly.
                            assert!(request_sent_at.elapsed() < Duration::from_millis(100));
                        }
                        2..=5 => {
                            // The second and subsequent responses are delayed due to the response rate-limiter on the receiver side.
                            // Adding a slight margin to the elapsed time check to account for potential timing issues caused by system
                            // scheduling or execution delays during testing.
                            // https://github.com/sigp/lighthouse/issues/7466
                            let margin = 500;
                            assert!(
                                request_sent_at.elapsed()
                                    > (Duration::from_secs(QUOTA_SEC)
                                        - Duration::from_millis(margin))
                            );
                            if request_id == 5 {
                                // End the test
                                return;
                            }
                        }
                        _ => unreachable!(),
                    }

                    request_id += 1;
                    debug_with_peers!(%request_id, "Sending RPC request");
                    sender
                        .send_request(
                            peer_id,
                            AppRequestId::Application(request_id),
                            rpc_request.clone(),
                        )
                        .unwrap();
                    request_sent_at = Instant::now();
                }
                NetworkEvent::RPCFailed {
                    app_request_id: _,
                    peer_id: _,
                    error,
                } => {
                    error_with_peers!(?error, "RPC Failed");
                    panic!("Rpc failed.");
                }
                _ => {}
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            if let NetworkEvent::RequestReceived {
                peer_id,
                inbound_request_id,
                request_type,
            } = receiver.next_event().await
            {
                assert_eq!(request_type, rpc_request);
                debug_with_peers!("Receiver received request");
                receiver.send_response(peer_id, inbound_request_id, rpc_response.clone());
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}

// Test that a rate-limited error doesn't occur even if the sender attempts to send many requests at
// once, thanks to the self-limiter on the sender side.
#[tokio::test]
async fn test_active_requests() {
    // set up the logging. The level and enabled logging or not
    let log_level = "debug";
    let enable_logging = false;
    let config = Arc::new(Config::mainnet().rapid_upgrade());
    build_tracing_subscriber(log_level, enable_logging);

    // Get sender/receiver.
    let (mut sender, mut receiver) =
        common::build_node_pair::<Mainnet>(&config, Phase::Phase0, Protocol::Tcp, false, None)
            .await;

    // Dummy STATUS RPC request.
    let rpc_request = RequestType::Status(StatusMessage::V1(StatusMessageV1 {
        fork_digest: H32::default(),
        finalized_root: H256::default(),
        finalized_epoch: 1,
        head_root: H256::default(),
        head_slot: 1,
    }));

    // Dummy STATUS RPC response.
    let rpc_response = Response::Status(StatusMessage::V1(StatusMessageV1 {
        fork_digest: H32::default(),
        finalized_root: H256::default(),
        finalized_epoch: 1,
        head_root: H256::default(),
        head_slot: 1,
    }));

    // Number of requests.
    const REQUESTS: usize = 10;

    // Build the sender future.
    let sender_future = async {
        let mut response_received = 0;
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    debug_with_peers!("Sending RPC request");
                    // Send requests in quick succession to intentionally trigger request queueing in the self-limiter.
                    for i in 0..REQUESTS {
                        sender
                            .send_request(
                                peer_id,
                                AppRequestId::Application(i),
                                rpc_request.clone(),
                            )
                            .unwrap();
                    }
                }
                NetworkEvent::ResponseReceived { response, .. } => {
                    debug_with_peers!(?response, "Sender received response");
                    if matches!(response, Response::Status(_)) {
                        response_received += 1;
                    }
                }
                NetworkEvent::RPCFailed {
                    app_request_id: _,
                    peer_id: _,
                    error,
                } => panic!("RPC failed: {:?}", error),
                _ => {}
            }

            if response_received == REQUESTS {
                return;
            }
        }
    };

    // Build the receiver future.
    let receiver_future = async {
        let mut received_requests = vec![];
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NetworkEvent::RequestReceived { peer_id, inbound_request_id, request_type } = event {
                        debug_with_peers!(?request_type, "Receiver received request");
                        if matches!(request_type, RequestType::Status(_)) {
                            received_requests.push((peer_id, inbound_request_id));
                        }
                    }
                }
                // Introduce a delay in sending responses to trigger request queueing on the sender side.
                _ = sleep(Duration::from_secs(3)) => {
                    for (peer_id, inbound_request_id) in received_requests.drain(..) {
                        receiver.send_response(peer_id, inbound_request_id, rpc_response.clone());
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = sender_future => {}
        _ = receiver_future => {}
        _ = sleep(Duration::from_secs(30)) => {
            panic!("Future timed out");
        }
    }
}
