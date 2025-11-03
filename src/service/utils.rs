use crate::multiaddr::Protocol;
use crate::rpc::{MetaData, MetaDataV1, MetaDataV2, MetaDataV3};
use crate::types::{
    EnrAttestationBitfield, EnrForkId, EnrSyncCommitteeBitfield, ForkContext, GossipEncoding,
    GossipKind,
};
use crate::{GossipTopic, NetworkConfig};
use anyhow::{anyhow, Result};
use futures::future::Either;
use gossipsub;
use libp2p::core::{multiaddr::Multiaddr, muxing::StreamMuxerBox, transport::Boxed};
use libp2p::identity::{secp256k1, Keypair};
use libp2p::metrics::Registry;
use libp2p::{core, noise, yamux, PeerId, Transport};
use logging::{debug_with_peers, warn_with_peers};
use ssz::SszReadDefault;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use types::{
    config::Config as ChainConfig,
    phase0::{consts::FAR_FUTURE_EPOCH, primitives::ForkDigest},
};

pub const NETWORK_KEY_FILENAME: &str = "key";
/// The filename to store our local metadata.
pub const METADATA_FILENAME: &str = "metadata";

pub struct Context<'a> {
    pub chain_config: Arc<ChainConfig>,
    pub config: Arc<NetworkConfig>,
    pub enr_fork_id: EnrForkId,
    pub fork_context: Arc<ForkContext>,
    pub libp2p_registry: Option<&'a mut Registry>,
}

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

/// The implementation supports TCP/IP, QUIC (experimental) over UDP, noise as the encryption layer, and
/// mplex/yamux as the multiplexing layer (when using TCP).
pub fn build_transport(
    local_private_key: Keypair,
    quic_support: bool,
) -> std::io::Result<BoxedTransport> {
    // mplex config
    let mut mplex_config = libp2p_mplex::Config::new();
    mplex_config.set_max_buffer_size(256);
    mplex_config.set_max_buffer_behaviour(libp2p_mplex::MaxBufferBehaviour::Block);

    // yamux config
    let yamux_config = yamux::Config::default();
    // Creates the TCP transport layer
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
        .upgrade(core::upgrade::Version::V1)
        .authenticate(generate_noise_config(&local_private_key))
        .multiplex(core::upgrade::SelectUpgrade::new(
            yamux_config,
            mplex_config,
        ))
        .timeout(Duration::from_secs(10));
    let transport = if quic_support {
        // Enables Quic
        // The default quic configuration suits us for now.
        let quic_config = libp2p::quic::Config::new(&local_private_key);
        let quic = libp2p::quic::tokio::Transport::new(quic_config);
        let transport = tcp
            .or_transport(quic)
            .map(|either_output, _| match either_output {
                Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
                Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            });
        transport.boxed()
    } else {
        tcp.boxed()
    };

    // Enables DNS over the transport.
    let transport = libp2p::dns::tokio::Transport::system(transport)?.boxed();

    Ok(transport)
}

fn keypair_from_hex(hex_bytes: &str) -> Result<Keypair> {
    let hex_bytes = if let Some(stripped) = hex_bytes.strip_prefix("0x") {
        stripped.to_string()
    } else {
        hex_bytes.to_string()
    };

    hex::decode(hex_bytes)
        .map_err(|e| anyhow!("Failed to parse p2p secret key bytes: {:?}", e).into())
        .and_then(keypair_from_bytes)
}

fn keypair_from_bytes(mut bytes: Vec<u8>) -> Result<Keypair> {
    secp256k1::SecretKey::try_from_bytes(&mut bytes)
        .map(|secret| {
            let keypair: secp256k1::Keypair = secret.into();
            keypair.into()
        })
        .map_err(|e| anyhow!("Unable to parse p2p secret key: {:?}", e).into())
}

/// Loads a private key from disk. If this fails, a new key is
/// generated and is then saved to disk.
///
/// Currently only secp256k1 keys are allowed, as these are the only keys supported by discv5.
/// Supports both hex format (with or without 0x prefix) and raw bytes format.
pub fn load_private_key(config: &NetworkConfig) -> Keypair {
    // check for key from disk
    let mut network_key_f = None;

    if let Some(network_dir) = config.network_dir.as_ref() {
        network_key_f = Some(network_dir.join(NETWORK_KEY_FILENAME));
    }

    if let Some(libp2p_private_key_file_path) = config.libp2p_private_key_file.as_ref() {
        network_key_f = Some(libp2p_private_key_file_path.clone());
    }

    if let Some(network_key_f) = network_key_f.as_ref() {
        if let Ok(mut network_key_file) = File::open(network_key_f.clone()) {
            // Limit read to reasonable hex key size: 32 bytes = 64 hex chars + "0x" prefix + whitespace
            let mut buffer = vec![0u8; 70];
            match network_key_file.read(&mut buffer) {
                Ok(bytes_read) => {
                    if let Ok(hex_string) = String::from_utf8(buffer[..bytes_read].to_vec()) {
                        // First try to parse as hex string
                        let hex_content = hex_string.trim();
                        if let Ok(keypair) = keypair_from_hex(hex_content) {
                            debug_with_peers!("Loaded network key from disk (hex format).");
                            return keypair;
                        }
                    }
                }
                Err(_) => {
                    debug_with_peers!(
                        "Could not read network key file as string, trying binary format"
                    )
                }
            }

            // If hex parsing failed or file couldn't be read as string, try binary format
            if let Ok(mut network_key_file) = File::open(network_key_f.clone()) {
                let mut key_bytes: Vec<u8> = Vec::with_capacity(36);
                match network_key_file.read_to_end(&mut key_bytes) {
                    Err(_) => debug_with_peers!("Could not read network key file"),
                    Ok(_) => {
                        // only accept secp256k1 keys for now
                        if let Ok(secret_key) = secp256k1::SecretKey::try_from_bytes(&mut key_bytes)
                        {
                            let kp: secp256k1::Keypair = secret_key.clone().into();
                            debug_with_peers!(
                            "Loaded network key from disk (binary format), migrating to hex format."
                        );

                            // Migrate binary key to hex format
                            let hex_key = hex::encode(secret_key.to_bytes());
                            if let Err(e) = File::create(network_key_f.clone())
                                .and_then(|mut f| f.write_all(hex_key.as_bytes()))
                            {
                                debug_with_peers!("Failed to migrate key to hex format: {}", e);
                            } else {
                                debug_with_peers!("Successfully migrated key to hex format.");
                            }

                            return kp.into();
                        } else {
                            debug_with_peers!("Network key file is not a valid secp256k1 key");
                        }
                    }
                }
            }
        }
    }

    // if a key could not be loaded from disk, generate a new one and optionally save it
    let local_private_key = secp256k1::Keypair::generate();

    if let Some(network_dir) = config.network_dir.as_ref() {
        let network_key_f = network_dir.join(NETWORK_KEY_FILENAME);
        let _ = std::fs::create_dir_all(network_dir);
        let hex_key = hex::encode(local_private_key.secret().to_bytes());

        match File::create(network_key_f.clone()).and_then(|mut f| f.write_all(hex_key.as_bytes()))
        {
            Ok(_) => {
                debug_with_peers!("New network key generated and written to disk");
            }
            Err(e) => {
                warn_with_peers!(
                    "Could not write node key to file: {:?}. error: {}",
                    network_key_f,
                    e
                );
            }
        }
    }

    local_private_key.into()
}

/// Generate authenticated XX Noise config from identity keys
fn generate_noise_config(identity_keypair: &Keypair) -> noise::Config {
    noise::Config::new(identity_keypair).expect("signing can fail only once during starting a node")
}

/// For a multiaddr that ends with a peer id, this strips this suffix. Rust-libp2p
/// only supports dialing to an address without providing the peer id.
pub fn strip_peer_id(addr: &mut Multiaddr) {
    let last = addr.pop();
    match last {
        Some(Protocol::P2p(_)) => {}
        Some(other) => addr.push(other),
        _ => {}
    }
}

/// Load metadata from persisted file. Return default metadata if loading fails.
pub fn load_or_build_metadata(
    network_dir: Option<&Path>,
    custody_group_count_opt: Option<u64>,
) -> MetaData {
    // We load a V3 metadata version by default
    // since a V3 metadata can be converted to V2 and V1. The RPC encoder is responsible
    // for sending the correct metadata version based on the negotiated protocol version.
    let mut meta_data = if let Some(custody_group_count) = custody_group_count_opt {
        MetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: EnrAttestationBitfield::default(),
            syncnets: EnrSyncCommitteeBitfield::default(),
            custody_group_count,
        })
    } else {
        MetaData::V2(MetaDataV2 {
            seq_number: 0,
            attnets: EnrAttestationBitfield::default(),
            syncnets: EnrSyncCommitteeBitfield::default(),
        })
    };

    // Read metadata from persisted file if available
    if let Some(network_dir) = network_dir {
        let metadata_path = network_dir.join(METADATA_FILENAME);
        if let Ok(mut metadata_file) = File::open(metadata_path) {
            let mut metadata_ssz = Vec::new();
            if metadata_file.read_to_end(&mut metadata_ssz).is_ok() {
                // Attempt to read a MetaDataV3 version from the persisted file,
                // if that fails, read MetaDataV2, and MetaDataV1 respectively.
                match MetaDataV3::from_ssz_default(&metadata_ssz) {
                    Ok(persisted_metadata) => {
                        *meta_data.seq_number_mut() = persisted_metadata.seq_number;
                        // Increment seq number if persisted attnet is not default
                        if persisted_metadata.attnets != meta_data.attnets()
                            || meta_data
                                .syncnets()
                                .is_some_and(|syncnets| persisted_metadata.syncnets != syncnets)
                        {
                            *meta_data.seq_number_mut() += 1;
                        }
                        if let Some(custody_group_count) = meta_data.custody_group_count_mut() {
                            *custody_group_count = persisted_metadata.custody_group_count;
                        }
                        debug_with_peers!("Loaded metadata from disk");
                    }
                    Err(_) => match MetaDataV2::from_ssz_default(&metadata_ssz) {
                        Ok(persisted_metadata) => {
                            *meta_data.seq_number_mut() = persisted_metadata.seq_number;
                            // Increment seq number if persisted attnet is not default
                            if persisted_metadata.attnets != meta_data.attnets()
                                || meta_data
                                    .syncnets()
                                    .is_some_and(|syncnets| persisted_metadata.syncnets != syncnets)
                            {
                                *meta_data.seq_number_mut() += 1;
                            }
                            debug_with_peers!("Loaded metadata from disk");
                        }
                        Err(_) => match MetaDataV1::from_ssz_default(&metadata_ssz) {
                            Ok(persisted_metadata) => {
                                let persisted_metadata = MetaData::V1(persisted_metadata);
                                // Increment seq number as the persisted metadata version is updated
                                *meta_data.seq_number_mut() = persisted_metadata.seq_number() + 1;
                                debug_with_peers!("Loaded metadata from disk");
                            }
                            Err(e) => {
                                debug_with_peers!(
                                    error = ?e,
                                    "Metadata from file could not be decoded"
                                );
                            }
                        },
                    },
                }
            }
        };
    }

    debug_with_peers!(seq_num = meta_data.seq_number(), "Metadata sequence number");
    save_metadata_to_disk(network_dir, meta_data.clone());
    meta_data
}

/// Creates a whitelist topic filter that covers all possible topics using the given set of
/// possible fork digests.
pub(crate) fn create_whitelist_filter(
    possible_fork_digests: Vec<ForkDigest>,
    chain_config: &ChainConfig,
    attestation_subnet_count: u64,
    sync_committee_subnet_count: u64,
) -> gossipsub::WhitelistSubscriptionFilter {
    let mut possible_hashes = HashSet::new();
    for fork_digest in possible_fork_digests {
        let mut add = |kind| {
            let topic: gossipsub::IdentTopic =
                GossipTopic::new(kind, GossipEncoding::SSZSnappy, fork_digest).into();
            possible_hashes.insert(topic.hash());
        };

        use GossipKind::*;
        add(BeaconBlock);
        add(BeaconAggregateAndProof);
        add(VoluntaryExit);
        add(ProposerSlashing);
        add(AttesterSlashing);
        add(SignedContributionAndProof);
        add(BlsToExecutionChange);
        add(LightClientFinalityUpdate);
        add(LightClientOptimisticUpdate);
        for id in 0..attestation_subnet_count {
            add(Attestation(id));
        }
        for id in 0..sync_committee_subnet_count {
            add(SyncCommitteeMessage(id));
        }
        let blob_subnet_count = if chain_config.electra_fork_epoch != FAR_FUTURE_EPOCH {
            chain_config.blob_sidecar_subnet_count_electra.get()
        } else {
            chain_config.blob_sidecar_subnet_count.get()
        };
        for id in 0..blob_subnet_count {
            add(BlobSidecar(id));
        }
        for id in 0..chain_config.data_column_sidecar_subnet_count {
            add(DataColumnSidecar(id));
        }
    }
    gossipsub::WhitelistSubscriptionFilter(possible_hashes)
}

/// Persist metadata to disk
pub(crate) fn save_metadata_to_disk(dir: Option<&Path>, metadata: MetaData) {
    let Some(dir) = dir else {
        debug_with_peers!("Skipping Metadata writing to disk");
        return;
    };

    let write_to_disk = || -> Result<()> {
        let ssz_bytes = metadata.to_ssz()?;

        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(METADATA_FILENAME), ssz_bytes)?;

        Ok(())
    };

    match write_to_disk() {
        Ok(_) => {
            debug_with_peers!("Metadata written to disk");
        }
        Err(e) => {
            warn_with_peers!(
                file = format!("{:?}{:?}", dir, METADATA_FILENAME),
                error = %e,
                "Could not write metadata to disk"
            );
        }
    }
}
