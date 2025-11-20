use bls::SignatureBytes;
use helper_functions::misc;
use ssz::{BitList, ContiguousList};
use types::{
    altair::containers::{
        BeaconBlock as AltairBeaconBlock, BeaconBlockBody as AltairBeaconBlockBody,
        SignedBeaconBlock as AltairSignedBeaconBlock,
    },
    config::Config,
    phase0::containers::{
        Attestation, AttesterSlashing, BeaconBlock as Phase0BeaconBlock,
        BeaconBlockBody as Phase0BeaconBlockBody, BeaconBlockHeader, Deposit, IndexedAttestation,
        ProposerSlashing, SignedBeaconBlock as Phase0SignedBeaconBlock, SignedBeaconBlockHeader,
        SignedVoluntaryExit, VoluntaryExit,
    },
    preset::Preset,
};

pub fn empty_phase0_signed_beacon_block<P: Preset>() -> Phase0SignedBeaconBlock<P> {
    Phase0SignedBeaconBlock::default()
}

pub fn full_phase0_signed_beacon_block<P: Preset>() -> Phase0SignedBeaconBlock<P> {
    Phase0SignedBeaconBlock {
        message: Phase0BeaconBlock {
            body: Phase0BeaconBlockBody {
                proposer_slashings: ContiguousList::full(nonzero_proposer_slashing()),
                attester_slashings: ContiguousList::full(full_attester_slashing()),
                attestations: ContiguousList::full(full_attestation()),
                deposits: ContiguousList::full(Deposit::default()),
                voluntary_exits: ContiguousList::full(SignedVoluntaryExit::default()),
                ..Phase0BeaconBlockBody::default()
            },
            ..Phase0BeaconBlock::default()
        }
        .into(),
        signature: SignatureBytes::default(),
    }
}

pub fn full_altair_signed_beacon_block<P: Preset>(config: &Config) -> AltairSignedBeaconBlock<P> {
    AltairSignedBeaconBlock {
        message: AltairBeaconBlock {
            body: AltairBeaconBlockBody {
                proposer_slashings: ContiguousList::full(nonzero_proposer_slashing()),
                attester_slashings: ContiguousList::full(full_attester_slashing()),
                attestations: ContiguousList::full(full_attestation()),
                deposits: ContiguousList::full(Deposit::default()),
                voluntary_exits: ContiguousList::full(nonzero_signed_voluntary_exit()),
                ..AltairBeaconBlockBody::default()
            },
            slot: misc::compute_start_slot_at_epoch::<P>(config.altair_fork_epoch),
            ..AltairBeaconBlock::default()
        }
        .into(),
        signature: SignatureBytes::default(),
    }
}

// pub fn full_bellatrix_signed_beacon_block<P: Preset>() -> BellatrixSignedBeaconBlock<P> {
//     BellatrixSignedBeaconBlock {
//         message: BellatrixBeaconBlock {
//             body: BellatrixBeaconBlockBody {
//                 proposer_slashings: ContiguousList::full(nonzero_proposer_slashing()),
//                 attester_slashings: ContiguousList::full(full_attester_slashing()),
//                 attestations: ContiguousList::full(full_attestation()),
//                 deposits: ContiguousList::full(Deposit::default()),
//                 voluntary_exits: ContiguousList::full(nonzero_signed_voluntary_exit()),
//                 ..BellatrixBeaconBlockBody::default()
//             },
//             ..BellatrixBeaconBlock::default()
//         },
//         signature: SignatureBytes::default(),
//     }
// }

fn full_attester_slashing<P: Preset>() -> AttesterSlashing<P> {
    AttesterSlashing {
        attestation_1: full_indexed_attestation(),
        attestation_2: full_indexed_attestation(),
    }
}

fn full_indexed_attestation<P: Preset>() -> IndexedAttestation<P> {
    IndexedAttestation {
        attesting_indices: ContiguousList::full(0),
        ..IndexedAttestation::default()
    }
}

fn full_attestation<P: Preset>() -> Attestation<P> {
    Attestation {
        aggregation_bits: BitList::full(false),
        ..Attestation::default()
    }
}

fn nonzero_proposer_slashing() -> ProposerSlashing {
    ProposerSlashing {
        signed_header_1: nonzero_signed_beacon_block_header(),
        signed_header_2: nonzero_signed_beacon_block_header(),
    }
}

fn nonzero_signed_beacon_block_header() -> SignedBeaconBlockHeader {
    SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: 1,
            ..BeaconBlockHeader::default()
        },
        ..SignedBeaconBlockHeader::default()
    }
}

fn nonzero_signed_voluntary_exit() -> SignedVoluntaryExit {
    SignedVoluntaryExit {
        message: VoluntaryExit {
            epoch: 1,
            validator_index: 1,
        },
        ..SignedVoluntaryExit::default()
    }
}
