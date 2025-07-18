#![cfg(test)]
use common::Protocol;
use eth2_libp2p::rpc::{methods::*, RequestType};
use eth2_libp2p::{NetworkEvent, ReportSource, Response};
use slog::{debug, warn, Level};
use ssz::{ByteList, ContiguousList, SszReadDefault as _, SszWrite as _};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use try_from_iterator::TryFromIterator as _;
use types::deneb::containers::BlobSidecar;
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
fn bellatrix_block_small<P: Preset>() -> BellatrixSignedBeaconBlock<P> {
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
fn bellatrix_block_large<P: Preset>() -> BellatrixSignedBeaconBlock<P> {
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
    let log_level = Level::Debug;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair(
        &Config::mainnet().rapid_upgrade().into(),
        &log,
        Phase::Phase0,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // Dummy STATUS RPC message
    let rpc_request = RequestType::Status(StatusMessage {
        fork_digest: ForkDigest::zero(),
        finalized_root: H256::zero(),
        finalized_epoch: 1,
        head_root: H256::zero(),
        head_slot: 1,
    });

    // Dummy STATUS RPC message
    let rpc_response = Response::Status::<Mainnet>(StatusMessage {
        fork_digest: ForkDigest::zero(),
        finalized_root: H256::zero(),
        finalized_epoch: 1,
        head_root: H256::zero(),
        head_slot: 1,
    });

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, 10, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    id: 10,
                    response,
                } => {
                    // Should receive the RPC response
                    debug!(log, "Sender Received");
                    assert_eq!(response, rpc_response.clone());
                    debug!(log, "Sender Completed");
                    return;
                }
                _ => {}
            }
        }
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                } => {
                    if request.r#type == rpc_request {
                        // send the response
                        debug!(log, "Receiver Received");
                        receiver.send_response(peer_id, id, request.id, rpc_response.clone());
                    }
                }
                _ => {} // Ignore other events
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

// Tests a streamed BlocksByRange RPC Message
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_blocks_by_range_chunked_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 6;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        &log,
        Phase::Bellatrix,
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
    let signed_full_block = factory::full_phase0_signed_beacon_block().into();
    let rpc_response_base = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

    let signed_full_block = factory::full_altair_signed_beacon_block().into();
    let rpc_response_altair = Response::BlocksByRange(Some(Arc::new(signed_full_block)));
    let signed_full_block = bellatrix_block_small().into();
    let rpc_response_merge_small = Response::BlocksByRange(Some(Arc::new(signed_full_block)));

    // keep count of the number of messages received
    let mut messages_received = 0;
    let request_id = messages_to_send as usize;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, request_id, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    id: _,
                    response,
                } => {
                    warn!(log, "Sender received a response");
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
                            warn!(log, "Chunk received");
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
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                } => {
                    if request.r#type == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
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
                            debug!(log, "Sending RPC response");
                            receiver.send_response(peer_id, id, request.id, rpc_response.clone());
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            id,
                            request.id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };

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
    let log_level = Level::Debug;
    let enable_logging = false;

    let slot_count = 32;
    let messages_to_send = 34;

    let log = common::build_log(log_level, enable_logging);

    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        &log,
        Phase::Deneb,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // BlobsByRange Request
    let rpc_request = RequestType::BlobsByRange(BlobsByRangeRequest {
        start_slot: 0,
        count: slot_count,
    });

    // BlocksByRange Response
    let blob = BlobSidecar::<Mainnet>::default();

    let rpc_response = Response::BlobsByRange(Some(Arc::new(blob)));

    // keep count of the number of messages received
    let mut messages_received = 0;
    let request_id = messages_to_send as usize;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, request_id, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    id: _,
                    response,
                } => {
                    warn!(log, "Sender received a response");
                    match response {
                        Response::BlobsByRange(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                            warn!(log, "Chunk received");
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
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                } => {
                    if request.r#type == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
                        for _ in 0..messages_to_send {
                            // Send first third of responses as base blocks,
                            // second as altair and third as merge.
                            receiver.send_response(peer_id, id, request.id, rpc_response.clone());
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            id,
                            request.id,
                            Response::BlobsByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
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

// Tests rejection of blocks over `MAX_RPC_SIZE`.
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_blocks_by_range_over_limit() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 5;

    // BlocksByRange Request
    let rpc_request =
        RequestType::BlocksByRange(OldBlocksByRangeRequest::V1(OldBlocksByRangeRequestV1 {
            start_slot: 0,
            count: messages_to_send,
            step: 1,
        }));

    let log = common::build_log(log_level, enable_logging);
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        &log,
        Phase::Bellatrix,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // BlocksByRange Response
    let signed_full_block = bellatrix_block_large().into();
    let rpc_response_merge_large = Response::BlocksByRange(Some(Arc::new(signed_full_block)));
    let request_id = messages_to_send as usize;

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, request_id, rpc_request.clone())
                        .unwrap();
                }
                // The request will fail because the sender will refuse to send anything > MAX_RPC_SIZE
                NetworkEvent::RPCFailed { id, .. } => {
                    assert_eq!(id, request_id);
                    return;
                }
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
                    id,
                    request,
                } => {
                    if request.r#type == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
                        for _ in 0..messages_to_send {
                            let rpc_response = rpc_response_merge_large.clone();
                            receiver.send_response(peer_id, id, request.id, rpc_response.clone());
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            id,
                            request.id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
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

// Tests that a streamed BlocksByRange RPC Message terminates when all expected chunks were received
#[tokio::test]
async fn test_tcp_blocks_by_range_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 10;
    let extra_messages_to_send = 10;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        &log,
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
    let request_id = messages_to_send as usize;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, request_id, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    id: _,
                    response,
                } =>
                // Should receive the RPC response
                {
                    debug!(log, "Sender received a response");
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
    };

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
                        id,
                        request,
                    },
                    _,
                )) => {
                    if request.r#type == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
                        message_info = Some((peer_id, id, request.id));
                    }
                }
                futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                _ => continue,
            }

            // if we need to send messages send them here. This will happen after a delay
            if message_info.is_some() {
                messages_sent += 1;
                let (peer_id, stream_id, request_id) = message_info.as_ref().unwrap();
                receiver.send_response(*peer_id, *stream_id, *request_id, rpc_response.clone());
                debug!(log, "Sending message {}", messages_sent);
                if messages_sent == messages_to_send + extra_messages_to_send {
                    // stop sending messages
                    return;
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

// Tests an empty response to a BlocksByRange RPC Message
#[tokio::test]
#[allow(clippy::single_match)]
async fn test_tcp_blocks_by_range_single_empty_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        &log,
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
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, 10, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    id: 10,
                    response,
                } => match response {
                    Response::BlocksByRange(Some(_)) => {
                        assert_eq!(response, rpc_response.clone());
                        messages_received += 1;
                        warn!(log, "Chunk received");
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
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                } => {
                    if request.r#type == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");

                        for _ in 1..=messages_to_send {
                            receiver.send_response(peer_id, id, request.id, rpc_response.clone());
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            id,
                            request.id,
                            Response::BlocksByRange(None),
                        );
                    }
                }
                _ => {} // Ignore other events
            }
        }
    };
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
    let log_level = Level::Debug;
    let enable_logging = false;

    let messages_to_send = 6;

    let log = common::build_log(log_level, enable_logging);
    let config = Arc::new(Config::mainnet().rapid_upgrade());

    // get sender/receiver
    let (mut sender, mut receiver) =
        common::build_node_pair(&config, &log, Phase::Bellatrix, Protocol::Tcp, false, None).await;

    // BlocksByRoot Request
    let rpc_request = RequestType::BlocksByRoot(BlocksByRootRequest::new(
        &config,
        Phase::Phase0,
        vec![H256::zero(); 6].into_iter(),
    ));
    // BlocksByRoot Response
    let signed_full_block = factory::full_phase0_signed_beacon_block().into();
    let rpc_response_base = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

    let signed_full_block = factory::full_altair_signed_beacon_block().into();
    let rpc_response_altair = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));
    let signed_full_block = bellatrix_block_small::<Mainnet>().into();
    let rpc_response_merge_small = Response::BlocksByRoot(Some(Arc::new(signed_full_block)));

    // keep count of the number of messages received
    let mut messages_received = 0;
    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a STATUS message
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, 6, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    id: 6,
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
                        debug!(log, "Chunk received");
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
    };

    // build the receiver future
    let receiver_future = async {
        loop {
            match receiver.next_event().await {
                NetworkEvent::RequestReceived {
                    peer_id,
                    id,
                    request,
                } => {
                    if request.r#type == rpc_request {
                        // send the response
                        debug!(log, "Receiver got request");

                        for i in 0..messages_to_send {
                            // Send first half of responses as base blocks and
                            // second half as altair blocks.
                            let rpc_response = if i < 2 {
                                // debug!(log, "Sending base block");
                                rpc_response_base.clone()
                            } else if i < 4 {
                                // debug!(log, "Sending altair block");
                                rpc_response_altair.clone()
                            } else {
                                // debug!(log, "Sending merge block");
                                rpc_response_merge_small.clone()
                            };
                            receiver.send_response(peer_id, id, request.id, rpc_response);
                            debug!(log, "Sending message");
                        }
                        // send the stream termination
                        receiver.send_response(
                            peer_id,
                            id,
                            request.id,
                            Response::BlocksByRange(None),
                        );
                        debug!(log, "Send stream term");
                    }
                }
                _ => {} // Ignore other events
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

// Tests a streamed, chunked BlocksByRoot RPC Message terminates when all expected reponses have been received
#[tokio::test]
async fn test_tcp_blocks_by_root_chunked_rpc_terminates_correctly() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;
    let messages_to_send: u64 = 10;
    let extra_messages_to_send: u64 = 10;
    let config = Arc::new(Config::mainnet().rapid_upgrade());

    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver

    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &config,
        &log,
        Phase::Bellatrix,
        Protocol::Tcp,
        false,
        None,
    )
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
                    debug!(log, "Sending RPC");
                    sender
                        .send_request(peer_id, 10, rpc_request.clone())
                        .unwrap();
                }
                NetworkEvent::ResponseReceived {
                    peer_id: _,
                    id: 10,
                    response,
                } => {
                    debug!(log, "Sender received a response");
                    match response {
                        Response::BlocksByRoot(Some(_)) => {
                            assert_eq!(response, rpc_response.clone());
                            messages_received += 1;
                            debug!(log, "Chunk received");
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
    };

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
                        id,
                        request,
                    },
                    _,
                )) => {
                    if request.r#type == rpc_request {
                        // send the response
                        warn!(log, "Receiver got request");
                        message_info = Some((peer_id, id, request.id));
                    }
                }
                futures::future::Either::Right((_, _)) => {} // The timeout hit, send messages if required
                _ => continue,
            }

            // if we need to send messages send them here. This will happen after a delay
            if message_info.is_some() {
                messages_sent += 1;
                let (peer_id, stream_id, request_id) = message_info.as_ref().unwrap();
                receiver.send_response(*peer_id, *stream_id, *request_id, rpc_response.clone());
                debug!(log, "Sending message {}", messages_sent);
                if messages_sent == messages_to_send + extra_messages_to_send {
                    // stop sending messages
                    return;
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

/// Establishes a pair of nodes and disconnects the pair based on the selected protocol via an RPC
/// Goodbye message.
#[allow(clippy::single_match)]
async fn goodbye_test(log_level: Level, enable_logging: bool, protocol: Protocol) {
    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &Config::mainnet().rapid_upgrade().into(),
        &log,
        Phase::Phase0,
        protocol,
    )
    .await;

    // build the sender future
    let sender_future = async {
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    // Send a goodbye and disconnect
                    debug!(log, "Sending RPC");
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
    };

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
    };

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
    let log_level = Level::Debug;
    let enable_logging = false;
    goodbye_test(log_level, enable_logging, Protocol::Tcp).await;
}

// Tests a Goodbye RPC message
#[tokio::test]
#[allow(clippy::single_match)]
async fn quic_test_goodbye_rpc() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Debug;
    let enable_logging = false;
    goodbye_test(log_level, enable_logging, Protocol::Quic).await;
}

// Test that the receiver delays the responses during response rate-limiting.
#[tokio::test]
async fn test_delayed_rpc_response() {
    let log_level = Level::Debug;
    let enable_logging = false;
    let config = Arc::new(Config::mainnet().rapid_upgrade());
    let log = common::build_log(log_level, enable_logging);

    // Allow 1 token to be use used every 3 seconds.
    const QUOTA_SEC: u64 = 3;

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &config,
        &log,
        Phase::Phase0,
        Protocol::Tcp,
        false,
        // Configure a quota for STATUS responses of 1 token every 3 seconds.
        Some(format!("status:1/{QUOTA_SEC}").parse().unwrap()),
    )
    .await;

    // Dummy STATUS RPC message
    let rpc_request = RequestType::Status(StatusMessage {
        fork_digest: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    // Dummy STATUS RPC message
    let rpc_response = Response::Status(StatusMessage {
        fork_digest: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    // build the sender future
    let sender_future = async {
        let mut request_id = 1;
        let mut request_sent_at = Instant::now();
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    debug!(log, "Sending RPC request"; "request_id" => %request_id);
                    sender
                        .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                        .unwrap();
                    request_sent_at = Instant::now();
                }
                NetworkEvent::ResponseReceived {
                    peer_id,
                    id: _,
                    response,
                } => {
                    debug!(log, "Sender received"; "request_id" => %request_id);
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
                            assert!(
                                request_sent_at.elapsed()
                                    > (Duration::from_secs(QUOTA_SEC) - Duration::from_millis(100))
                            );
                            if request_id == 5 {
                                // End the test
                                return;
                            }
                        }
                        _ => unreachable!(),
                    }

                    request_id += 1;
                    debug!(log, "Sending RPC request"; "request_id" => %request_id);
                    sender
                        .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                        .unwrap();
                    request_sent_at = Instant::now();
                }
                NetworkEvent::RPCFailed {
                    id: _,
                    peer_id: _,
                    error,
                } => {
                    error!(?error, "RPC Failed");
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
                id,
                request,
            } = receiver.next_event().await
            {
                assert_eq!(request.r#type, rpc_request);
                debug!(log, "Receiver received request");
                receiver.send_response(peer_id, id, rpc_response.clone());
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
    let log_level = Level::Debug;
    let enable_logging = false;
    let config = Arc::new(Config::mainnet().rapid_upgrade());
    let log = common::build_log(log_level, enable_logging);

    // get sender/receiver
    let (mut sender, mut receiver) = common::build_node_pair::<Mainnet>(
        &config,
        &log,
        Phase::Phase0,
        Protocol::Tcp,
        false,
        None,
    )
    .await;

    // Dummy STATUS RPC request.
    let rpc_request = RequestType::Status(StatusMessage {
        fork_digest: [0; 4],
        finalized_root: Hash256::from_low_u64_be(0),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::from_low_u64_be(0),
        head_slot: Slot::new(1),
    });

    // Dummy STATUS RPC response.
    let rpc_response = Response::Status(StatusMessage {
        fork_digest: [0; 4],
        finalized_root: Hash256::zero(),
        finalized_epoch: Epoch::new(1),
        head_root: Hash256::zero(),
        head_slot: Slot::new(1),
    });

    // Number of requests.
    const REQUESTS: u8 = 10;

    // Build the sender future.
    let sender_future = async {
        let mut response_received = 0;
        loop {
            match sender.next_event().await {
                NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                    debug!(log, "Sending RPC request");
                    // Send requests in quick succession to intentionally trigger request queueing in the self-limiter.
                    for _ in 0..REQUESTS {
                        sender
                            .send_request(peer_id, AppRequestId::Router, rpc_request.clone())
                            .unwrap();
                    }
                }
                NetworkEvent::ResponseReceived { response, .. } => {
                    debug!(log, "Sender received response"; "response" => ?response);
                    if matches!(response, Response::Status(_)) {
                        response_received += 1;
                    }
                }
                NetworkEvent::RPCFailed {
                    id: _,
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
                    if let NetworkEvent::RequestReceived { peer_id, id, request} = event {
                        debug!(log, "Receiver received request"; "request_type" => ?request.r#type);
                        if matches!(request.r#type, RequestType::Status(_)) {
                            received_requests.push((peer_id, id));
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
