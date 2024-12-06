//! The subnet predicate used for searching for a particular subnet.
use super::*;
use eip_7594::get_custody_groups;
use slog::trace;
use ssz::Uint256;
use std::sync::Arc;
use types::config::Config as ChainConfig;

/// Returns the predicate for a given subnet.
pub fn subnet_predicate(
    chain_config: Arc<ChainConfig>,
    subnets: Vec<Subnet>,
    log: &slog::Logger,
) -> impl Fn(&Enr) -> bool + Send {
    let log_clone = log.clone();

    move |enr| {
        let Ok(attestation_bitfield) = enr.attestation_bitfield() else {
            return false;
        };

        // Pre-fork/fork-boundary enrs may not contain a syncnets field.
        // Don't return early here.
        let sync_committee_bitfield = enr.sync_committee_bitfield();

        let predicate = subnets.iter().any(|subnet| match subnet {
            Subnet::Attestation(subnet_id) => attestation_bitfield
                .get(*subnet_id as usize)
                .unwrap_or_default(),
            Subnet::SyncCommittee(subnet_id) => sync_committee_bitfield
                .is_ok_and(|bitfield| bitfield.get(*subnet_id as usize).unwrap_or_default()),
            Subnet::DataColumn(subnet_id) => {
                if let Ok(custody_subnet_count) = enr.custody_subnet_count(&chain_config) {
                    // TODO(feature/fulu): review this
                    let subnets = get_custody_groups(
                        Uint256::from_be_bytes(enr.node_id().raw()),
                        custody_subnet_count,
                        &chain_config,
                    );

                    subnets.contains(subnet_id)
                } else {
                    false
                }
            }
        });

        if !predicate {
            trace!(
                log_clone,
                "Peer found but not on any of the desired subnets";
                "peer_id" => %enr.peer_id()
            );
        }
        predicate
    }
}
