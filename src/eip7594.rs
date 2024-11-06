use anyhow::Result;
use types::{config::Config, eip7594::ColumnIndex, phase0::primitives::SubnetId};

// Stubs for EIP7594. Add actual functionality when merging DAS branch
pub fn compute_custody_subnets(
    _raw_node_id: [u8; 32],
    _custody_subnet_count: u64,
) -> Result<impl Iterator<Item = SubnetId>> {
    Ok(core::iter::empty())
}

pub fn columns_for_data_column_subnet(_subnet_id: SubnetId) -> impl Iterator<Item = ColumnIndex> {
    core::iter::empty()
}

pub fn from_column_index(column_index: usize, chain_config: &Config) -> SubnetId {
    (column_index
        .checked_rem(chain_config.data_column_sidecar_subnet_count as usize)
        .expect("data_column_sidecar_subnet_count should never be zero if this function is called")
        as u64)
        .into()
}

pub fn compute_custody_requirement_subnets(
    _node_id: [u8; 32],
    _chain_config: &Config,
) -> impl Iterator<Item = SubnetId> {
    core::iter::empty()
}
