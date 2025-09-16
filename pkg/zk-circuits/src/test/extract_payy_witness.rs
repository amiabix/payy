use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

// Data structures that match Payy's test system
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PayyWitnessData {
    // From AggregateAgg<1> public inputs
    pub agg_instances: Vec<u64>,  // 12 instances
    pub old_root: [u8; 32],       // Previous Merkle root
    pub new_root: [u8; 32],       // New Merkle root  
    pub utxo_values: Vec<[u8; 32]>, // 18 values (3 per UTXO × 6 UTXOs)
    
    // From individual UTXO data (before aggregation)
    pub utxo_data: Vec<UtxoWitnessData>,
    
    // Metadata
    pub block_height: u64,
    pub num_utxos: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UtxoWitnessData {
    // Nullifiers (prevents double-spending)
    pub nullifiers: [u64; 2],  // Will convert from Fr to u64
    
    // Commitments (new notes created)
    pub commitments: [u64; 2], // Will convert from Fr to u64
    
    // Merkle path for inclusion proof
    pub merkle_path: [u64; 20], // Will convert from Vec<Fr> to [u64; 20]
    pub path_indices: [bool; 20], // Merkle path direction bits
    
    // Balance check values
    pub input_values: [u64; 2],
    pub output_values: [u64; 2],
    
    // Signature validity (assumed from Halo2)
    pub signature_valid: bool,
}

/// Extract real witness data from Payy's test system
/// This function should be called from Payy's test code
pub fn extract_payy_witness_data() -> PayyWitnessData {
    // This is a placeholder - the real implementation will be called
    // from within Payy's test system after witness generation
    
    // For now, return the structure we need
    PayyWitnessData {
        agg_instances: vec![0; 12],
        old_root: [0; 32],
        new_root: [0; 32],
        utxo_values: vec![[0; 32]; 18],
        utxo_data: vec![UtxoWitnessData {
            nullifiers: [0; 2],
            commitments: [0; 2],
            merkle_path: [0; 20],
            path_indices: [false; 20],
            input_values: [0; 2],
            output_values: [0; 2],
            signature_valid: true,
        }; 6],
        block_height: 0,
        num_utxos: 6,
    }
}

/// Save witness data for ZisK consumption
pub fn save_zisk_witness(data: &PayyWitnessData, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = bincode::serialize(data)?;
    fs::write(output_path, serialized)?;
    println!("✓ Saved Payy witness data to: {}", output_path);
    Ok(())
}

/// Load witness data for ZisK consumption
pub fn load_zisk_witness(input_path: &str) -> Result<PayyWitnessData, Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let witness: PayyWitnessData = bincode::deserialize(&data)?;
    println!("✓ Loaded Payy witness data from: {}", input_path);
    Ok(witness)
}
