use serde::{Deserialize, Serialize};

/// Input data for ZisK rollup prover
/// Matches the data available in generate_aggregate_proof()
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZiskRollupInput {
    /// Aggregation instances (12 elements)
    pub agg_instances: Vec<[u8; 32]>,
    /// Previous state root
    pub old_root: [u8; 32],
    /// New state root after transactions
    pub new_root: [u8; 32],
    /// UTXO values (18 elements)
    pub utxo_hashes: Vec<[u8; 32]>,
    /// Block height
    pub height: u64,
    /// Number of transactions processed
    pub tx_count: usize,
}

/// Output data from ZisK rollup prover
/// Matches the output format of evm_verifier::gen_proof()
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZiskRollupOutput {
    /// EVM-compatible proof bytes
    pub proof: Vec<u8>,
    /// Public inputs for verification
    pub public_inputs: Vec<[u8; 32]>,
}

impl ZiskRollupInput {
    /// Create input from AggregateAgg<1> data
    pub fn from_aggregate_agg(
        agg_instances: &[u8; 32],
        old_root: &[u8; 32],
        new_root: &[u8; 32],
        utxo_hashes: &[Vec<u8>],
        height: u64,
        tx_count: usize,
    ) -> Self {
        Self {
            agg_instances: vec![*agg_instances; 12], // 12 aggregation instances
            old_root: *old_root,
            new_root: *new_root,
            utxo_hashes: utxo_hashes.iter().map(|h| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&h[..32]);
                hash
            }).collect(),
            height,
            tx_count,
        }
    }
}

/// Convert Fr (field element) to bytes
pub fn fr_to_bytes(fr: &[u8; 32]) -> [u8; 32] {
    *fr
}

/// Convert bytes to Fr (field element)
pub fn bytes_to_fr(bytes: &[u8; 32]) -> [u8; 32] {
    *bytes
}
