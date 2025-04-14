use serde::{Serialize, Deserialize};

use crate::{ConnectionDirection, PeerConnectionStatus};

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

// TODO(Grandine Team): This could be simplified if `ConnectionDirection` implemented `Copy`.
impl From<&ConnectionDirection> for PeerDirection {
    fn from(direction: &ConnectionDirection) -> Self {
        match direction {
            ConnectionDirection::Incoming => Self::Inbound,
            ConnectionDirection::Outgoing => Self::Outbound,
        }
    }
}


#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Connected,
    Connecting,
    Disconnected,
    Disconnecting,
}

impl PeerState {
    // TODO(Grandine Team): This could be simplified if `PeerConnectionStatus` implemented `Copy`.
    pub const fn try_from(status: &PeerConnectionStatus) -> Option<Self> {
        match status {
            PeerConnectionStatus::Connected { .. } => Some(Self::Connected),
            PeerConnectionStatus::Dialing { .. } => Some(Self::Connecting),
            PeerConnectionStatus::Disconnected { .. } => Some(Self::Disconnected),
            PeerConnectionStatus::Disconnecting { .. } => Some(Self::Disconnecting),
            _ => None,
        }
    }
}
