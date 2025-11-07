use parking_lot::RwLock;
use std::{collections::BTreeMap, sync::Arc};

use helper_functions::misc;
use types::{
    config::Config,
    nonstandard::Phase,
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        primitives::{Epoch, ForkDigest, H256, Slot},
    },
    preset::Preset,
};

/// Represents a hard fork in the consensus protocol.
///
/// A hard fork can be one of two types:
/// * A named fork (represented by `ForkName`) which introduces protocol changes.
/// * A blob-parameter-only (BPO) fork which only modifies blob parameters.
///
/// For BPO forks, the `fork_name` remains unchanged from the previous fork,
/// but the `fork_epoch` and `fork_digest` will be different to reflect the
/// new blob parameter changes.
#[derive(Debug, Clone)]
pub struct HardFork {
    fork_name: Phase,
    fork_epoch: Epoch,
    fork_digest: ForkDigest,
}

impl HardFork {
    pub fn new(fork_name: Phase, fork_digest: ForkDigest, fork_epoch: Epoch) -> HardFork {
        HardFork {
            fork_name,
            fork_epoch,
            fork_digest,
        }
    }
}

/// Provides fork specific info like the current phase and the fork digests corresponding to every valid fork.
#[derive(Debug)]
pub struct ForkContext {
    chain_config: Arc<Config>,
    current_fork: RwLock<HardFork>,
    epoch_to_forks: BTreeMap<Epoch, HardFork>,
}

impl ForkContext {
    /// Creates a new `ForkContext` object by enumerating all enabled forks and computing their
    /// fork digest.
    pub fn new<P: Preset>(
        config: &Arc<Config>,
        current_slot: Slot,
        genesis_validators_root: H256,
    ) -> Self {
        let epoch_to_forks: BTreeMap<_, _> = enum_iterator::all::<Phase>()
            .filter(|phase| config.is_phase_enabled::<P>(*phase))
            .map(|phase| config.fork_epoch(phase))
            .chain(config.blob_schedule.iter().map(|entry| entry.epoch))
            .map(|epoch| {
                let phase = config.phase_at_epoch(epoch);
                let digest = misc::compute_fork_digest(config, genesis_validators_root, epoch);
                (epoch, HardFork::new(phase, digest, epoch))
            })
            .collect();

        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);
        let current_fork = epoch_to_forks
            .values()
            .filter(|&fork| fork.fork_epoch <= current_epoch)
            .next_back()
            .cloned()
            .expect("should match at least genesis epoch");

        Self {
            chain_config: config.clone(),
            current_fork: RwLock::new(current_fork),
            epoch_to_forks,
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
        self.chain_config.fork_epoch(phase) != FAR_FUTURE_EPOCH
    }

    /// Returns the current fork name.
    pub fn current_fork_name(&self) -> Phase {
        self.current_fork.read().fork_name
    }

    /// Returns the current fork epoch.
    pub fn current_fork_epoch(&self) -> Epoch {
        self.current_fork.read().fork_epoch
    }

    /// Return the current fork digest.
    pub fn current_fork_digest(&self) -> ForkDigest {
        self.current_fork.read().fork_digest
    }

    /// Returns the next fork digest. If there's no future fork, returns the current fork digest.
    pub fn next_fork_digest(&self) -> Option<ForkDigest> {
        let current_fork_epoch = self.current_fork_epoch();
        self.epoch_to_forks
            .range(current_fork_epoch..)
            .nth(1)
            .map(|(_, fork)| fork.fork_digest)
    }

    /// Returns the next fork digest and next fork epoch.
    pub fn next_fork(&self) -> Option<(Phase, ForkDigest, Epoch)> {
        let current_fork_epoch = self.current_fork_epoch();
        self.epoch_to_forks
            .range(current_fork_epoch..)
            .nth(1)
            .map(|(_, fork)| (fork.fork_name, fork.fork_digest, fork.fork_epoch))
    }

    /// Updates the `current_fork` field to the next fork.
    pub fn update_current_fork(&self) {
        let current_fork_epoch = self.current_fork_epoch();
        let next_fork = self
            .epoch_to_forks
            .range(current_fork_epoch..)
            .nth(1)
            .map(|(_, fork)| fork.clone())
            .unwrap_or(HardFork::new(
                self.current_fork_name(),
                ForkDigest::default(),
                FAR_FUTURE_EPOCH,
            ));

        *self.current_fork.write() = next_fork;
    }

    /// Returns the context bytes/fork_digest corresponding to the genesis fork version.
    pub fn genesis_context_bytes(&self) -> ForkDigest {
        self.epoch_to_forks
            .first_key_value()
            .expect("must contain genesis epoch")
            .1
            .fork_digest
    }

    /// Returns the fork type given the context bytes/fork_digest.
    /// Returns `None` if context bytes doesn't correspond to any valid `Phase`.
    pub fn get_fork_from_context_bytes(&self, context: ForkDigest) -> Option<Phase> {
        self.epoch_to_forks
            .values()
            .find(|fork| fork.fork_digest == context)
            .map(|fork| fork.fork_name)
    }

    /// Returns the context bytes/fork_digest corresponding to an epoch.
    pub fn context_bytes(&self, epoch: Epoch) -> ForkDigest {
        self.epoch_to_forks
            .range(..=epoch)
            .next_back()
            .expect("should match at least genesis epoch")
            .1
            .fork_digest
    }

    /// Returns the context bytes/fork_digest corresponding to a fork name.
    /// Returns `None` if the `Phase` has not been initialized.
    pub fn to_context_bytes(&self, phase: Phase) -> ForkDigest {
        let fork_epoch = self.chain_config.fork_epoch(phase);
        self.context_bytes(fork_epoch)
    }

    /// Returns all `fork_digest`s that are currently in the `ForkContext` object.
    pub fn all_fork_digests(&self) -> Vec<ForkDigest> {
        self.epoch_to_forks
            .values()
            .map(|fork| fork.fork_digest)
            .collect()
    }

    /// Returns all `fork_epoch`s that are currently in the `ForkContext` object.
    pub fn all_fork_epochs(&self) -> Vec<Epoch> {
        self.epoch_to_forks.keys().cloned().collect()
    }

    pub fn chain_config(&self) -> &Arc<Config> {
        &self.chain_config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        config::{BlobScheduleEntry, Config},
        phase0::consts::GENESIS_EPOCH,
        preset::Mainnet,
    };

    fn make_chain_config() -> Arc<Config> {
        let mut chain_config = Config::mainnet().rapid_upgrade();
        chain_config.blob_schedule = vec![
            BlobScheduleEntry::new(6, 12),
            BlobScheduleEntry::new(50, 24),
            BlobScheduleEntry::new(100, 48),
        ];
        Arc::new(chain_config)
    }

    #[test]
    fn test_fork_exists() {
        let chain_config = make_chain_config();
        let context = ForkContext::dummy::<Mainnet>(&chain_config, Phase::Fulu);

        assert!(context.fork_exists(Phase::Electra));
        assert!(context.fork_exists(Phase::Fulu));
    }

    #[test]
    fn test_current_fork_name_and_epoch() {
        let chain_config = make_chain_config();
        let electra_end_slot =
            misc::compute_start_slot_at_epoch::<Mainnet>(chain_config.electra_fork_epoch + 1)
                .saturating_sub(1);
        let genesis_root = H256::zero();

        let context = ForkContext::new::<Mainnet>(&chain_config, electra_end_slot, genesis_root);

        assert_eq!(context.current_fork_name(), Phase::Electra);
        assert_eq!(
            context.current_fork_epoch(),
            chain_config.electra_fork_epoch
        );
    }

    #[test]
    fn test_next_fork_digest() {
        let chain_config = make_chain_config();
        let electra_end_slot =
            misc::compute_start_slot_at_epoch::<Mainnet>(chain_config.electra_fork_epoch + 1)
                .saturating_sub(1);
        let genesis_root = H256::zero();

        let context = ForkContext::new::<Mainnet>(&chain_config, electra_end_slot, genesis_root);

        let next_digest = context.next_fork_digest().unwrap();
        let expected_digest =
            misc::compute_fork_digest(&chain_config, genesis_root, chain_config.fulu_fork_epoch);
        assert_eq!(next_digest, expected_digest);
    }

    #[test]
    fn test_get_fork_from_context_bytes() {
        let chain_config = make_chain_config();
        let genesis_root = H256::zero();
        let context = ForkContext::dummy::<Mainnet>(&chain_config, Phase::Phase0);

        let electra_digest =
            misc::compute_fork_digest(&chain_config, genesis_root, chain_config.electra_fork_epoch);
        assert_eq!(
            context.get_fork_from_context_bytes(electra_digest),
            Some(Phase::Electra)
        );

        let invalid_digest = ForkDigest::from_slice(&[9, 9, 9, 9]);
        assert!(
            context
                .get_fork_from_context_bytes(invalid_digest)
                .is_none()
        );
    }

    #[test]
    fn test_context_bytes() {
        let chain_config = make_chain_config();
        let genesis_root = H256::zero();
        let context = ForkContext::dummy::<Mainnet>(&chain_config, Phase::Phase0);

        assert_eq!(
            context.context_bytes(GENESIS_EPOCH),
            misc::compute_fork_digest(&chain_config, genesis_root, GENESIS_EPOCH)
        );

        assert_eq!(
            context.context_bytes(12),
            misc::compute_fork_digest(&chain_config, genesis_root, 10)
        );
    }
}
