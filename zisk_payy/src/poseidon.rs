// Simplified Poseidon hash implementation for ZisK
// This provides basic hashing functionality using SHA256 with domain separation

use sha2::{Digest, Sha256};

// Simple Poseidon-like hash using SHA256 with proper domain separation
pub fn poseidon_hash_merge(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_MERGE");
    hasher.update(&left);
    hasher.update(&right);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

pub fn poseidon_hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_BYTES");
    hasher.update(data);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

pub fn poseidon_merkle_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    poseidon_hash_merge(left, right)
}

pub fn poseidon_commitment_hash(address: [u8; 32], psi: [u8; 32], value: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_COMMITMENT");
    hasher.update(&address);
    hasher.update(&psi);
    hasher.update(&value.to_le_bytes());
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

pub fn poseidon_nullifier_hash(secret_key: [u8; 32], commitment: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_NULLIFIER");
    hasher.update(&secret_key);
    hasher.update(&commitment);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

pub fn poseidon_utxo_value_hash(
    commitment: [u8; 32],
    input_value: u64,
    output_value: u64,
    batch_idx: usize,
    txn_idx: usize,
    block_height: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_UTXO_VALUE");
    hasher.update(&commitment);
    hasher.update(&input_value.to_le_bytes());
    hasher.update(&output_value.to_le_bytes());
    hasher.update(&(batch_idx as u64).to_le_bytes());
    hasher.update(&(txn_idx as u64).to_le_bytes());
    hasher.update(&block_height.to_le_bytes());
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

pub fn poseidon_proof_hash(
    instances: &[u64; 12],
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    utxo_values: &[[u8; 32]; 18],
    nullifiers: &[[u8; 32]],
    commitments: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_PROOF_HASH");
    for &instance in instances {
        hasher.update(&instance.to_le_bytes());
    }
    hasher.update(old_root);
    hasher.update(new_root);
    for utxo in utxo_values {
        hasher.update(utxo);
    }
    for n in nullifiers {
        hasher.update(n);
    }
    for c in commitments {
        hasher.update(c);
    }
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

pub fn poseidon_hash_2_elements(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    poseidon_hash_merge(left, right)
}

pub fn poseidon_hash_elements(elements: &[[u8; 32]]) -> [u8; 32] {
    if elements.is_empty() {
        return [0u8; 32];
    }
    
    let mut result = elements[0];
    for element in &elements[1..] {
        result = poseidon_hash_merge(result, *element);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash_merge_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let a = poseidon_hash_merge(left, right);
        let b = poseidon_hash_merge(left, right);
        assert_eq!(a, b);
        assert_ne!(a, left);
        assert_ne!(a, right);
    }

    #[test]
    fn test_poseidon_hash_bytes() {
        let h1 = poseidon_hash_bytes(b"hello world");
        let h2 = poseidon_hash_bytes(b"hello world");
        assert_eq!(h1, h2);
    }
}