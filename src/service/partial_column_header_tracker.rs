use crate::types::HeaderSentSet;
use lru::LruCache;
use parking_lot::Mutex;
use ssz::H256;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

const MAX_BLOCKS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

pub struct PartialColumnHeaderTracker {
    blocks: LruCache<H256, HeaderSentSet>,
}

impl PartialColumnHeaderTracker {
    pub fn new() -> Self {
        PartialColumnHeaderTracker {
            blocks: LruCache::new(MAX_BLOCKS),
        }
    }

    pub fn get_for_block(&mut self, hash: H256) -> HeaderSentSet {
        Arc::clone(
            self.blocks
                .get_or_insert(hash, || Arc::new(Mutex::new(HashSet::new()))),
        )
    }
}
