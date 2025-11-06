use crate::rpc::methods::{ResponseTermination, RpcResponse, RpcSuccessResponse, StatusMessage};
use std::sync::Arc;

use types::{
    combined::{
        DataColumnSidecar, LightClientBootstrap, LightClientFinalityUpdate,
        LightClientOptimisticUpdate, LightClientUpdate, SignedBeaconBlock,
    },
    deneb::containers::BlobSidecar,
    gloas::containers::SignedExecutionPayloadEnvelope,
    preset::Preset,
};

pub type Id = usize;

/// Identifier of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppRequestId {
    Application(Id),
    Internal,
}

/// The type of RPC responses the Behaviour informs it has received, and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level responses that can be
//       sent. The main difference is the absense of Pong and Metadata, which don't leave the
//       Behaviour. For all protocol reponses managed by RPC see `RPCResponse` and
//       `RPCCodedResponse`.
#[derive(Debug, Clone, PartialEq)]
pub enum Response<P: Preset> {
    /// A Status message.
    Status(StatusMessage),
    /// A response to a get BLOCKS_BY_RANGE request. A None response signals the end of the batch.
    BlocksByRange(Option<Arc<SignedBeaconBlock<P>>>),
    /// A response to a get BLOBS_BY_RANGE request. A None response signals the end of the batch.
    BlobsByRange(Option<Arc<BlobSidecar<P>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_Range request.
    DataColumnsByRange(Option<Arc<DataColumnSidecar<P>>>),
    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Option<Arc<SignedBeaconBlock<P>>>),
    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Option<Arc<BlobSidecar<P>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_ROOT request.
    DataColumnsByRoot(Option<Arc<DataColumnSidecar<P>>>),
    // A responcse to a get EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE request.
    ExecutionPayloadEnvelopesByRange(Option<Arc<SignedExecutionPayloadEnvelope<P>>>),
    // A response to a get EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT request.
    ExecutionPayloadEnvelopesByRoot(Option<Arc<SignedExecutionPayloadEnvelope<P>>>),
    /// A response to a LightClientUpdate request.
    LightClientBootstrap(Arc<LightClientBootstrap<P>>),
    /// A response to a LightClientOptimisticUpdate request.
    LightClientOptimisticUpdate(Arc<LightClientOptimisticUpdate<P>>),
    /// A response to a LightClientFinalityUpdate request.
    LightClientFinalityUpdate(Arc<LightClientFinalityUpdate<P>>),
    /// A response to a LightClientUpdatesByRange request.
    LightClientUpdatesByRange(Option<Arc<LightClientUpdate<P>>>),
}

impl<P: Preset> std::convert::From<Response<P>> for RpcResponse<P> {
    fn from(resp: Response<P>) -> RpcResponse<P> {
        match resp {
            Response::BlocksByRoot(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlocksByRoot),
            },
            Response::BlocksByRange(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlocksByRange(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlocksByRange),
            },
            Response::BlobsByRoot(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlobsByRoot(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlobsByRoot),
            },
            Response::BlobsByRange(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlobsByRange(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlobsByRange),
            },
            Response::DataColumnsByRoot(r) => match r {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::DataColumnsByRoot(d)),
                None => RpcResponse::StreamTermination(ResponseTermination::DataColumnsByRoot),
            },
            Response::DataColumnsByRange(r) => match r {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::DataColumnsByRange(d)),
                None => RpcResponse::StreamTermination(ResponseTermination::DataColumnsByRange),
            },
            Response::ExecutionPayloadEnvelopesByRoot(r) => match r {
                Some(e) => {
                    RpcResponse::Success(RpcSuccessResponse::ExecutionPayloadEnvelopesByRoot(e))
                }
                None => RpcResponse::StreamTermination(
                    ResponseTermination::ExecutionPayloadEnvelopesByRoot,
                ),
            },
            Response::ExecutionPayloadEnvelopesByRange(r) => match r {
                Some(e) => {
                    RpcResponse::Success(RpcSuccessResponse::ExecutionPayloadEnvelopesByRange(e))
                }
                None => RpcResponse::StreamTermination(
                    ResponseTermination::ExecutionPayloadEnvelopesByRange,
                ),
            },
            Response::Status(s) => RpcResponse::Success(RpcSuccessResponse::Status(s)),
            Response::LightClientBootstrap(b) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientBootstrap(b))
            }
            Response::LightClientOptimisticUpdate(o) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientOptimisticUpdate(o))
            }
            Response::LightClientFinalityUpdate(f) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientFinalityUpdate(f))
            }
            Response::LightClientUpdatesByRange(f) => match f {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::LightClientUpdatesByRange(d)),
                None => {
                    RpcResponse::StreamTermination(ResponseTermination::LightClientUpdatesByRange)
                }
            },
        }
    }
}
