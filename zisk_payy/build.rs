use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

// ZisK rollup prover input format
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ZiskRollupInput {
    verified_utxo_proofs: [VerifiedUtxoProof; 6],
    agg_instances: [u64; 12],
    old_root: [u8; 32],
    new_root: [u8; 32],
    utxo_values: [[u8; 32]; 18],
    block_height: u64,
    num_utxos: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct VerifiedUtxoProof {
    nullifiers: [[u8; 32]; 2],
    commitments: [[u8; 32]; 2],
    merkle_path: [u8; 32],
    path_indices: [u8; 20],
    input_values: [u64; 2],
    output_values: [u64; 2],
    signature_valid: bool,
}

fn main() {
    // Use existing ZiskRollupInput format (already working)
    let input = extract_rollup_prover_inputs();
    
    fs::create_dir_all("build").unwrap();
    let data = bincode::serialize(&input).unwrap();
    fs::write("build/input.bin", &data).unwrap();
    fs::write("witness.bin", &data).unwrap();
    
    println!("✓ Generated ZisK input data: {} UTXOs", input.num_utxos);
}

fn extract_rollup_prover_inputs() -> ZiskRollupInput {
    // Try to load real data from Payy's test system
    if Path::new("zisk_witness_data.bin").exists() {
        println!("✓ Loading real Payy witness data from zisk_witness_data.bin");
        load_real_payy_witness_data()
    } else {
        println!("⚠ No real Payy witness data found, generating test data");
        generate_test_inputs()
    }
}

fn load_real_payy_witness_data() -> ZiskRollupInput {
    // Load the real witness data from Payy's test system
    let data = fs::read("zisk_witness_data.bin").unwrap();
    let payy_data: PayyWitnessData = bincode::deserialize(&data).unwrap();
    
    // Convert PayyWitnessData to ZiskRollupInput
    let mut verified_utxo_proofs = [VerifiedUtxoProof {
        nullifiers: [[0u8; 32]; 2],
        commitments: [[0u8; 32]; 2],
        merkle_path: [0u8; 32],
        path_indices: [0u8; 20],
        input_values: [0u64; 2],
        output_values: [0u64; 2],
        signature_valid: true,
    }; 6];
    
    for (i, utxo_data) in payy_data.utxo_data.iter().enumerate() {
        if i < 6 {
            // Convert u64 nullifiers to [u8; 32]
            let nullifier_bytes_0 = utxo_data.nullifiers[0].to_le_bytes();
            let nullifier_bytes_1 = utxo_data.nullifiers[1].to_le_bytes();
            verified_utxo_proofs[i].nullifiers[0][0..8].copy_from_slice(&nullifier_bytes_0);
            verified_utxo_proofs[i].nullifiers[1][0..8].copy_from_slice(&nullifier_bytes_1);
            
            // Convert u64 commitments to [u8; 32]
            let commitment_bytes_0 = utxo_data.commitments[0].to_le_bytes();
            let commitment_bytes_1 = utxo_data.commitments[1].to_le_bytes();
            verified_utxo_proofs[i].commitments[0][0..8].copy_from_slice(&commitment_bytes_0);
            verified_utxo_proofs[i].commitments[1][0..8].copy_from_slice(&commitment_bytes_1);
            
            // Convert Merkle path
            for j in 0..20 {
                verified_utxo_proofs[i].merkle_path[j] = utxo_data.merkle_path[j] as u8;
                verified_utxo_proofs[i].path_indices[j] = utxo_data.path_indices[j] as u8;
            }
            
            verified_utxo_proofs[i].input_values = utxo_data.input_values;
            verified_utxo_proofs[i].output_values = utxo_data.output_values;
            verified_utxo_proofs[i].signature_valid = utxo_data.signature_valid;
        }
    }
    
    ZiskRollupInput {
        verified_utxo_proofs,
        agg_instances: payy_data.agg_instances.try_into().unwrap(),
        old_root: payy_data.old_root,
        new_root: payy_data.new_root,
        utxo_values: payy_data.utxo_values.try_into().unwrap(),
        block_height: payy_data.block_height,
        num_utxos: payy_data.num_utxos,
    }
}

fn generate_test_inputs() -> ZiskRollupInput {
    // Generate test data that matches Payy's structure
    let mut verified_utxo_proofs = [VerifiedUtxoProof {
        nullifiers: [[0u8; 32]; 2],
        commitments: [[0u8; 32]; 2],
        merkle_path: [0u8; 32],
        path_indices: [0u8; 20],
        input_values: [0u64; 2],
        output_values: [0u64; 2],
        signature_valid: true,
    }; 6];
    
    for i in 0..6 {
        let mut nullifier1 = [0u8; 32];
        let mut nullifier2 = [0u8; 32];
        let mut commitment1 = [0u8; 32];
        let mut commitment2 = [0u8; 32];
        
        // Generate unique nullifiers and commitments
        nullifier1[0] = (i * 4) as u8;
        nullifier1[1] = 0x01;
        nullifier1[2] = 0x02;
        nullifier2[0] = (i * 4 + 2) as u8;
        nullifier2[1] = 0x03;
        nullifier2[2] = 0x04;
        
        commitment1[0] = (i * 2 + 10) as u8;
        commitment1[1] = 0x03;
        commitment2[0] = (i * 2 + 11) as u8;
        commitment2[1] = 0x04;
        
        verified_utxo_proofs[i] = VerifiedUtxoProof {
            nullifiers: [nullifier1, nullifier2],
            commitments: [commitment1, commitment2],
            merkle_path: [i as u8; 32],
            path_indices: [0u8; 20],
            input_values: [100, 0],
            output_values: [100, 0],
            signature_valid: true,
        };
    }
    
    ZiskRollupInput {
        verified_utxo_proofs,
        agg_instances: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        old_root: [0x29, 0x92, 0x6d, 0xca, 0xb4, 0xeb, 0x70, 0xc2, 
                   0xd0, 0x4e, 0x58, 0xd7, 0x0e, 0x7f, 0x2a, 0xd4, 
                   0x9c, 0x6b, 0xfe, 0x40, 0xa2, 0xb1, 0x76, 0xb0, 
                   0xf6, 0x9d, 0x84, 0xbd, 0x7f, 0x86, 0x0a, 0x21],
        new_root: [0x17, 0x6a, 0xf7, 0x99, 0xdc, 0xa8, 0x41, 0xbd, 
                   0xca, 0x4b, 0xbf, 0x32, 0x07, 0xd9, 0xad, 0x8f, 
                   0x6a, 0x19, 0x1e, 0xcf, 0x50, 0xc6, 0x8f, 0x45, 
                   0xd5, 0xa4, 0xcc, 0xd0, 0x19, 0x1b, 0xa5, 0x3d],
        utxo_values: [[0u8; 32]; 18],
        block_height: 12345,
        num_utxos: 6,
    }
}

// Payy's witness data format
#[derive(Deserialize)]
struct PayyWitnessData {
    agg_instances: Vec<u64>,
    old_root: [u8; 32],
    new_root: [u8; 32],
    utxo_values: Vec<[u8; 32]>,
    utxo_data: Vec<UtxoWitnessData>,
    block_height: u64,
    num_utxos: usize,
}

#[derive(Deserialize)]
struct UtxoWitnessData {
    nullifiers: [u64; 2],
    commitments: [u64; 2],
    merkle_path: [u64; 20],
    path_indices: [bool; 20],
    input_values: [u64; 2],
    output_values: [u64; 2],
    signature_valid: bool,
}