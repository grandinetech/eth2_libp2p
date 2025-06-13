use parking_lot::RwLock;
use std::sync::Arc;

use helper_functions::misc;
use std::collections::HashMap;
use types::{
    config::Config,
    nonstandard::Phase,
    phase0::primitives::{ForkDigest, Slot, H256},
    preset::Preset,
};

/// Provides fork specific info like the current phase and the fork digests corresponding to every valid fork.
#[derive(Debug)]
pub struct ForkContext {
    chain_config: Arc<Config>,
    current_fork: RwLock<Phase>,
    fork_to_digest: HashMap<Phase, ForkDigest>,
    digest_to_fork: HashMap<ForkDigest, Phase>,
}

impl ForkContext {
    /// Creates a new `ForkContext` object by enumerating all enabled forks and computing their
    /// fork digest.
    pub fn new<P: Preset>(
        config: &Arc<Config>,
        current_slot: Slot,
        genesis_validators_root: H256,
    ) -> Self {
        let fork_to_digest = enum_iterator::all::<Phase>()
            .filter(|phase| config.is_phase_enabled::<P>(*phase))
            .map(|phase| {
                let version = config.version(phase);
                let digest = misc::compute_fork_digest(version, genesis_validators_root);
                (phase, digest)
            })
            .collect::<HashMap<_, _>>();

        let digest_to_fork = fork_to_digest.iter().map(|(k, v)| (*v, *k)).collect();
        let current_fork = RwLock::new(config.phase_at_slot::<P>(current_slot));

        Self {
            chain_config: config.clone(),
            current_fork,
            fork_to_digest,
            digest_to_fork,
        }
    }

    /// Returns a dummy fork context for testing.
    pub fn dummy<P: Preset>(config: &Arc<Config>, phase: Phase) -> ForkContext {
        let current_slot = config
            .fork_slot::<P>(phase)
            .expect("all phases should be enabled in configuration");

        Self::new::<P>(config, current_slot, H256::zero())
    }

    /// Returns `true` if the provided `phase` exists in the `ForkContext` object.
    pub fn fork_exists(&self, phase: Phase) -> bool {
        self.fork_to_digest.contains_key(&phase)
    }

    /// Returns the `current_fork`.
    pub fn current_fork(&self) -> Phase {
        *self.current_fork.read()
    }

    /// Updates the `current_fork` field to a new fork.
    pub fn update_current_fork(&self, new_fork: Phase) {
        *self.current_fork.write() = new_fork;
    }

    /// Returns the context bytes/fork_digest corresponding to the genesis fork version.
    pub fn genesis_context_bytes(&self) -> ForkDigest {
        *self
            .fork_to_digest
            .get(&Phase::Phase0)
            .expect("ForkContext must contain genesis context bytes")
    }

    /// Returns the fork type given the context bytes/fork_digest.
    /// Returns `None` if context bytes doesn't correspond to any valid `Phase`.
    pub fn from_context_bytes(&self, context: ForkDigest) -> Option<&Phase> {
        self.digest_to_fork.get(&context)
    }

    /// Returns the context bytes/fork_digest corresponding to a fork name.
    /// Returns `None` if the `Phase` has not been initialized.
    pub fn to_context_bytes(&self, phase: Phase) -> Option<ForkDigest> {
        self.fork_to_digest.get(&phase).cloned()
    }

    /// Returns all `fork_digest`s that are currently in the `ForkContext` object.
    pub fn all_fork_digests(&self) -> Vec<ForkDigest> {
        self.digest_to_fork.keys().cloned().collect()
    }

    pub fn chain_config(&self) -> &Arc<Config> {
        &self.chain_config
    }
}
