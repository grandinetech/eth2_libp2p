use super::protocol::ProtocolId;
use super::RPCError;
use super::RequestType;
use crate::rpc::codec::SSZSnappyOutboundCodec;
use crate::rpc::protocol::Encoding;
use crate::types::ForkContext;
use futures::future::BoxFuture;
use futures::prelude::{AsyncRead, AsyncWrite};
use futures::{FutureExt, SinkExt};
use libp2p::core::{OutboundUpgrade, UpgradeInfo};
use std::sync::Arc;
use tokio_util::{
    codec::Framed,
    compat::{Compat, FuturesAsyncReadCompatExt},
};
use types::preset::Preset;
/* Outbound request */

// Combines all the RPC requests into a single enum to implement `UpgradeInfo` and
// `OutboundUpgrade`

#[derive(Debug, Clone)]
pub struct OutboundRequestContainer<P: Preset> {
    pub req: RequestType<P>,
    pub fork_context: Arc<ForkContext>,
    pub max_rpc_size: usize,
}

impl<P: Preset> UpgradeInfo for OutboundRequestContainer<P> {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    // add further protocols as we support more encodings/versions
    fn protocol_info(&self) -> Self::InfoIter {
        self.req.supported_protocols()
    }
}

/* RPC Response type - used for outbound upgrades */

/* Outbound upgrades */

pub type OutboundFramed<TSocket, P> = Framed<Compat<TSocket>, SSZSnappyOutboundCodec<P>>;

impl<TSocket, P> OutboundUpgrade<TSocket> for OutboundRequestContainer<P>
where
    P: Preset + Send + 'static,
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = OutboundFramed<TSocket, P>;
    type Error = RPCError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: TSocket, protocol: Self::Info) -> Self::Future {
        // convert to a tokio compatible socket
        let socket = socket.compat();
        let codec = match protocol.encoding {
            Encoding::SSZSnappy => {
                SSZSnappyOutboundCodec::new(protocol, self.max_rpc_size, self.fork_context.clone())
            }
        };

        let mut socket = Framed::new(socket, codec);

        async {
            socket.send(self.req).await?;
            socket.close().await?;
            Ok(socket)
        }
        .boxed()
    }
}
