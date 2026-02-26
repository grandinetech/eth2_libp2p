use crate::PeerId;
use itertools::Itertools;
use libp2p::gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError};
use parking_lot::Mutex;
use ssz::{ContiguousList, H256, SszReadDefault, SszWrite as _};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::debug;
use types::{
    combined::PartialDataColumnHeader,
    fulu::{
        containers::{PartialDataColumnPartsMetadata, PartialDataColumnSidecar},
        primitives::CellBitmap,
    },
    nonstandard::PartialDataColumn,
    preset::Preset,
};

const PARTIAL_COLUMNS_VERSION_BYTE: u8 = 0;

pub type HeaderSentSet = Arc<Mutex<HashSet<PeerId>>>;

#[derive(Debug, Clone)]
pub struct OutgoingPartialColumn<P: Preset> {
    partial_column: Arc<PartialDataColumn<P>>,
    metadata: MaybeKnownMetadata<P>,
    header_message: Vec<u8>,
    header_sent_set: HeaderSentSet,
}

impl<P: Preset> OutgoingPartialColumn<P> {
    pub fn new(
        partial_column: Arc<PartialDataColumn<P>>,
        header: &PartialDataColumnHeader<P>,
        header_sent_set: HeaderSentSet,
    ) -> Self {
        // For now, always request or provide all cells
        let mut requests = partial_column.sidecar.cells_present_bitmap.clone();
        for idx in 0..requests.len() {
            requests.set(idx, true);
        }
        let metadata = PartialDataColumnPartsMetadata {
            available: partial_column.sidecar.cells_present_bitmap.clone(),
            requests,
        }
        .into();

        let header_message = PartialDataColumnSidecar {
            cells_present_bitmap: CellBitmap::<P>::with_length(
                partial_column.sidecar.cells_present_bitmap.len(),
            ),
            partial_column: ContiguousList::default(),
            kzg_proofs: ContiguousList::default(),
            header: ContiguousList::full(header.clone()),
        }
        .to_ssz()
        .expect("Serializing partial data column sidecar ref");

        OutgoingPartialColumn {
            partial_column,
            metadata,
            header_message,
            header_sent_set,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MaybeKnownMetadata<P: Preset> {
    Unknown,
    Known {
        metadata: Box<PartialDataColumnPartsMetadata<P>>,
        encoded: Vec<u8>,
    },
}

impl<P: Preset> MaybeKnownMetadata<P> {
    fn do_update(
        &mut self,
        received: PartialDataColumnPartsMetadata<P>,
    ) -> Result<bool, PartialError> {
        let MaybeKnownMetadata::Known { metadata, encoded } = self else {
            *self = received.into();
            return Ok(true);
        };

        if ![
            received.available.len(),
            received.requests.len(),
            metadata.available.len(),
            metadata.requests.len(),
        ]
        .into_iter()
        .all_equal()
        {
            return Err(PartialError::OutOfRange);
        }
        let new_available = metadata.available.union(&received.available);
        let new_requests = metadata.requests.union(&received.requests);
        if metadata.available == new_available && metadata.requests == new_requests {
            return Ok(false);
        }
        metadata.available = new_available;
        metadata.requests = new_requests;
        *encoded = metadata.to_ssz().map_err(|_| PartialError::InvalidFormat)?;
        Ok(true)
    }
}

impl<P: Preset> Metadata for MaybeKnownMetadata<P> {
    fn as_slice(&self) -> &[u8] {
        match self {
            MaybeKnownMetadata::Unknown => &[],
            MaybeKnownMetadata::Known { encoded, .. } => encoded,
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialError> {
        let received = PartialDataColumnPartsMetadata::<P>::from_ssz_default(data)
            .map_err(|_| PartialError::InvalidFormat)?;

        self.do_update(received)
    }

    fn update_from_data(&mut self, data: &[u8]) -> Result<(), PartialError> {
        if data.is_empty() {
            return Ok(());
        }

        let sidecar = PartialDataColumnSidecar::<P>::from_ssz_default(data)
            .map_err(|_| PartialError::InvalidFormat)?;

        self.do_update(PartialDataColumnPartsMetadata {
            available: sidecar.cells_present_bitmap.clone(),
            requests: sidecar.cells_present_bitmap,
        })
        .map(|_| ())
    }
}

impl<P: Preset> From<PartialDataColumnPartsMetadata<P>> for MaybeKnownMetadata<P> {
    fn from(metadata: PartialDataColumnPartsMetadata<P>) -> Self {
        Self::Known {
            encoded: metadata.to_ssz().expect("Serializing parts metadata"),
            metadata: Box::new(metadata),
        }
    }
}

impl<P: Preset> Partial for OutgoingPartialColumn<P> {
    fn group_id(&self) -> Vec<u8> {
        let mut group_id = Vec::with_capacity(H256::len_bytes() + 1);
        group_id.push(PARTIAL_COLUMNS_VERSION_BYTE);
        group_id.extend_from_slice(self.partial_column.block_root.as_bytes());
        group_id
    }

    fn metadata(&self) -> Box<dyn Metadata> {
        Box::new(self.metadata.clone())
    }

    fn partial_action_from_metadata(
        &self,
        peer_id: PeerId,
        metadata: Option<&[u8]>,
    ) -> Result<PartialAction, PartialError> {
        match metadata {
            None => {
                // send the header-only messsage to the peer if we have not yet
                let send = self.header_sent_set.lock().insert(peer_id).then(|| {
                    (
                        self.header_message.clone(),
                        Box::new(MaybeKnownMetadata::<P>::Unknown) as Box<dyn Metadata>,
                    )
                });
                debug!(
                    peer=%peer_id,
                    group_id=%self.partial_column.block_root,
                    column_index=self.partial_column.index,
                    sending_header=send.is_some(),
                    "Partial send: No metadata"
                );

                Ok(PartialAction { need: false, send })
            }
            Some([]) => Ok(PartialAction {
                need: false,
                send: None,
            }),
            Some(metadata) => {
                // The peer is apparently aware of the header, make sure we track that:
                self.header_sent_set.lock().insert(peer_id);

                let peer_metadata = PartialDataColumnPartsMetadata::<P>::from_ssz_default(metadata)
                    .map_err(|_| PartialError::InvalidFormat)?;
                let expected_len = self.partial_column.sidecar.cells_present_bitmap.len();
                if peer_metadata.available.len() != expected_len
                    || peer_metadata.requests.len() != expected_len
                {
                    return Err(PartialError::InvalidFormat);
                }

                let need = !peer_metadata
                    .available
                    .is_subset(&self.partial_column.sidecar.cells_present_bitmap);
                let want = peer_metadata.requests.difference(&peer_metadata.available);

                let send = self
                    .partial_column
                    .sidecar
                    .filter(|idx| *want.get(idx).expect("Bound checked above"))
                    .map(|sidecar| {
                        debug!(
                            peer=%peer_id,
                            group_id=%self.partial_column.block_root,
                            column_index=self.partial_column.index,
                            metadata=?peer_metadata,
                            sending=?sidecar.cells_present_bitmap,
                            "Partial send: Sending"
                        );
                        (
                            sidecar
                                .to_ssz()
                                .expect("Serializing partial data column sidecar"),
                            Box::new(MaybeKnownMetadata::<P>::from(
                                PartialDataColumnPartsMetadata {
                                    available: peer_metadata
                                        .available
                                        .union(&sidecar.cells_present_bitmap),
                                    requests: peer_metadata
                                        .requests
                                        .union(&sidecar.cells_present_bitmap),
                                },
                            )) as Box<dyn Metadata + 'static>,
                        )
                    });

                if send.is_none() {
                    debug!(
                        peer=%peer_id,
                        group_id=%self.partial_column.block_root,
                        column_index=self.partial_column.index,
                        metadata=?peer_metadata,
                        "Partial send: Nothing to send"
                    );
                }

                Ok(PartialAction { need, send })
            }
        }
    }
}
