use anyhow::Result;
use num_traits::One as _;
use sha2::{Digest as _, Sha256};
use ssz::Uint256;
use thiserror::Error;
use typenum::Unsigned as _;
use types::{
    config::Config,
    fulu::{consts::NumberOfColumns, primitives::ColumnIndex},
    phase0::primitives::SubnetId,
};

// Stubs for EIP7594. Add actual functionality when merging DAS branch
pub fn compute_custody_subnets(
    raw_node_id: [u8; 32],
    custody_subnet_count: u64,
    config: &Config,
) -> Result<impl Iterator<Item = SubnetId>> {
    if custody_subnet_count > config.data_column_sidecar_subnet_count {
        return Err(ComputeSubnetsError::InvalidCustodySubnetCount {
            custody_subnet_count,
            data_column_sidecar_subnet_count: config.data_column_sidecar_subnet_count,
        }
        .into());
    }

    let mut subnet_ids = vec![];
    let mut current_id = Uint256::from_be_bytes(raw_node_id);

    while (subnet_ids.len() as u64) < custody_subnet_count {
        let mut hasher = Sha256::new();
        let mut bytes = [0u8; 32];

        current_id.into_raw().to_little_endian(&mut bytes);

        hasher.update(&bytes);
        bytes = hasher.finalize().into();

        // let output_prefix = [
        //     bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        // ];
        let output_prefix: [u8; 8] = bytes[0..8].try_into().expect("slice with incorrect length");

        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let subnet_id = output_prefix_u64 % config.data_column_sidecar_subnet_count;

        if !subnet_ids.contains(&subnet_id) {
            subnet_ids.push(subnet_id);
        }

        if current_id == Uint256::MAX {
            current_id = Uint256::ZERO;
        }

        current_id = current_id + Uint256::one();
    }

    Ok(subnet_ids.into_iter())
}

pub fn columns_for_data_column_subnet(
    subnet_id: SubnetId,
    config: &Config,
) -> impl Iterator<Item = ColumnIndex> {
    let data_column_sidecar_subnet_count = config.data_column_sidecar_subnet_count;
    let columns_per_subnet = NumberOfColumns::U64 / data_column_sidecar_subnet_count;

    (0..columns_per_subnet)
        .map(move |column_index| (data_column_sidecar_subnet_count * column_index + subnet_id))
}

pub fn from_column_index(column_index: usize, chain_config: &Config) -> SubnetId {
    (column_index
        .checked_rem(chain_config.data_column_sidecar_subnet_count as usize)
        .expect("data_column_sidecar_subnet_count should never be zero if this function is called")
        as u64)
        .into()
}

pub fn compute_custody_requirement_subnets(
    node_id: [u8; 32],
    chain_config: &Config,
) -> impl Iterator<Item = SubnetId> {
    compute_custody_subnets(node_id, chain_config.custody_requirement, chain_config)
        .expect("should be able to compute subnets with custody requirement")
}

#[derive(Debug, Error)]
pub enum ComputeSubnetsError {
    #[error(
        "Custody subnet count is invalid: {custody_subnet_count} expected <= {data_column_sidecar_subnet_count}",
    )]
    InvalidCustodySubnetCount {
        custody_subnet_count: u64,
        data_column_sidecar_subnet_count: u64,
    },
}
