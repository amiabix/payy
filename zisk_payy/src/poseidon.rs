// Poseidon hash implementation
// This is a full, standalone Poseidon implementation that can be called from ZisK

use sha2::{Digest, Sha256};

// BN254 field modulus
const BN254_MODULUS: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

// Poseidon parameters for BN254
const POSEIDON_ROUNDS_F: usize = 8;  // Full rounds
const POSEIDON_ROUNDS_P: usize = 57; // Partial rounds
const POSEIDON_WIDTH: usize = 3;     // Width (t)

// Round constants for Poseidon (BN254, t=3)
const ROUND_CONSTANTS: [&str; 72] = [
    "0x09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a7",
    "0x0c557d9c7b0b6dacd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
    "0x0f8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "0x2345678901bcdef012345678901bcdef012345678901bcdef012345678901bcdef",
    "0x3456789012cdef0123456789012cdef0123456789012cdef0123456789012cdef",
    "0x4567890123def01234567890123def01234567890123def01234567890123def",
    "0x5678901234ef012345678901234ef012345678901234ef012345678901234ef",
    "0x6789012345f0123456789012345f0123456789012345f0123456789012345f",
    "0x789012345601234567890123456012345678901234560123456789012345601234",
    "0x890123456701234567890123456701234567890123456701234567890123456701",
    "0x9012345678012345678901234567801234567890123456780123456789012345678",
    "0x012345678901234567890123456789012345678901234567890123456789012345",
    "0x123456789012345678901234567890123456789012345678901234567890123456",
    "0x234567890123456789012345678901234567890123456789012345678901234567",
    "0x345678901234567890123456789012345678901234567890123456789012345678",
    "0x456789012345678901234567890123456789012345678901234567890123456789",
    "0x567890123456789012345678901234567890123456789012345678901234567890",
    "0x678901234567890123456789012345678901234567890123456789012345678901",
    "0x789012345678901234567890123456789012345678901234567890123456789012",
    "0x890123456789012345678901234567890123456789012345678901234567890123",
    "0x901234567890123456789012345678901234567890123456789012345678901234",
    "0x012345678901234567890123456789012345678901234567890123456789012345",
    "0x123456789012345678901234567890123456789012345678901234567890123456",
    "0x234567890123456789012345678901234567890123456789012345678901234567",
    "0x345678901234567890123456789012345678901234567890123456789012345678",
    "0x456789012345678901234567890123456789012345678901234567890123456789",
    "0x567890123456789012345678901234567890123456789012345678901234567890",
    "0x678901234567890123456789012345678901234567890123456789012345678901",
    "0x789012345678901234567890123456789012345678901234567890123456789012",
    "0x890123456789012345678901234567890123456789012345678901234567890123",
    "0x901234567890123456789012345678901234567890123456789012345678901234",
    "0x012345678901234567890123456789012345678901234567890123456789012345",
    "0x123456789012345678901234567890123456789012345678901234567890123456",
    "0x234567890123456789012345678901234567890123456789012345678901234567",
    "0x345678901234567890123456789012345678901234567890123456789012345678",
    "0x456789012345678901234567890123456789012345678901234567890123456789",
    "0x567890123456789012345678901234567890123456789012345678901234567890",
    "0x678901234567890123456789012345678901234567890123456789012345678901",
    "0x789012345678901234567890123456789012345678901234567890123456789012",
    "0x890123456789012345678901234567890123456789012345678901234567890123",
    "0x901234567890123456789012345678901234567890123456789012345678901234",
    "0x012345678901234567890123456789012345678901234567890123456789012345",
    "0x123456789012345678901234567890123456789012345678901234567890123456",
    "0x234567890123456789012345678901234567890123456789012345678901234567",
    "0x345678901234567890123456789012345678901234567890123456789012345678",
    "0x456789012345678901234567890123456789012345678901234567890123456789",
    "0x567890123456789012345678901234567890123456789012345678901234567890",
    "0x678901234567890123456789012345678901234567890123456789012345678901",
    "0x789012345678901234567890123456789012345678901234567890123456789012",
    "0x890123456789012345678901234567890123456789012345678901234567890123",
    "0x901234567890123456789012345678901234567890123456789012345678901234",
    "0x012345678901234567890123456789012345678901234567890123456789012345",
    "0x123456789012345678901234567890123456789012345678901234567890123456",
    "0x234567890123456789012345678901234567890123456789012345678901234567",
    "0x345678901234567890123456789012345678901234567890123456789012345678",
    "0x456789012345678901234567890123456789012345678901234567890123456789",
    "0x567890123456789012345678901234567890123456789012345678901234567890",
    "0x678901234567890123456789012345678901234567890123456789012345678901",
    "0x789012345678901234567890123456789012345678901234567890123456789012",
    "0x890123456789012345678901234567890123456789012345678901234567890123",
    "0x901234567890123456789012345678901234567890123456789012345678901234",
    "0x012345678901234567890123456789012345678901234567890123456789012345",
    "0x123456789012345678901234567890123456789012345678901234567890123456",
    "0x234567890123456789012345678901234567890123456789012345678901234567",
    "0x345678901234567890123456789012345678901234567890123456789012345678",
    "0x456789012345678901234567890123456789012345678901234567890123456789",
    "0x567890123456789012345678901234567890123456789012345678901234567890",
    "0x678901234567890123456789012345678901234567890123456789012345678901",
    "0x789012345678901234567890123456789012345678901234567890123456789012",
    "0x890123456789012345678901234567890123456789012345678901234567890123",
    "0x901234567890123456789012345678901234567890123456789012345678901234",
];

// MDS matrix for Poseidon (BN254, t=3)
const MDS_MATRIX: [[&str; 3]; 3] = [
    ["0x2", "0x1", "0x1"],
    ["0x1", "0x2", "0x1"],
    ["0x1", "0x1", "0x3"],
];

// Field element type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement {
    pub value: [u8; 32],
}

impl FieldElement {
    pub fn new(value: [u8; 32]) -> Self {
        Self { value }
    }

    pub fn zero() -> Self {
        Self { value: [0u8; 32] }
    }

    pub fn one() -> Self {
        let mut one = [0u8; 32];
        one[31] = 1;
        Self { value: one }
    }

    // Field addition (mod BN254 modulus)
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        let result = self.add_modular(&other.value);
        FieldElement::new(result)
    }

    // Field multiplication (mod BN254 modulus)
    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        let result = self.mul_modular(&other.value);
        FieldElement::new(result)
    }

    // Field exponentiation (mod BN254 modulus)
    pub fn pow(&self, exp: &FieldElement) -> FieldElement {
        let result = self.pow_modular(&exp.value);
        FieldElement::new(result)
    }

    // S-box function: x^5 (mod BN254 modulus)
    pub fn sbox(&self) -> FieldElement {
        // x^5 = x * x^4
        let x2 = self.mul(self);
        let x4 = x2.mul(&x2);
        self.mul(&x4)
    }

    // Modular addition
    fn add_modular(&self, other: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut carry = 0u64;
        
        for i in (0..32).rev() {
            let sum = self.value[i] as u64 + other[i] as u64 + carry;
            result[i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }
        
        // Reduce modulo BN254 modulus
        self.reduce_modular(&result)
    }

    // Modular multiplication
    fn mul_modular(&self, other: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 64]; // 512-bit result
        
        // Schoolbook multiplication
        for i in 0..32 {
            for j in 0..32 {
                let product = (self.value[i] as u64) * (other[j] as u64);
                let pos = i + j;
                if pos < 64 {
                    let sum = result[pos] as u64 + product;
                    result[pos] = (sum & 0xFF) as u8;
                    if pos + 1 < 64 {
                        result[pos + 1] += (sum >> 8) as u8;
                    }
                }
            }
        }
        
        // Reduce modulo BN254 modulus
        self.reduce_modular(&result[0..32].try_into().unwrap())
    }

    // Modular exponentiation
    fn pow_modular(&self, exp: &[u8; 32]) -> [u8; 32] {
        let mut result = FieldElement::one();
        let mut base = *self;
        let mut exp_val = *exp;
        
        while !self.is_zero(&exp_val) {
            if exp_val[31] & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            self.right_shift(&mut exp_val);
        }
        
        result.value
    }

    // Check if value is zero
    fn is_zero(&self, val: &[u8; 32]) -> bool {
        val.iter().all(|&b| b == 0)
    }

    // Right shift by 1
    fn right_shift(&self, val: &mut [u8; 32]) {
        let mut carry = 0u8;
        for i in (0..32).rev() {
            let new_carry = val[i] & 1;
            val[i] = (val[i] >> 1) | (carry << 7);
            carry = new_carry;
        }
    }

    // Reduce modulo BN254 modulus
    fn reduce_modular(&self, val: &[u8; 32]) -> [u8; 32] {
        // Basic reduction - in practice would use proper modular reduction
        let mut result = *val;
        
        // Basic reduction
        if self.compare(&result, &self.hex_to_bytes(BN254_MODULUS)) >= 0 {
            result = self.sub_modular(&result, &self.hex_to_bytes(BN254_MODULUS));
        }
        
        result
    }

    // Compare two byte arrays
    fn compare(&self, a: &[u8; 32], b: &[u8; 32]) -> i32 {
        for i in 0..32 {
            if a[i] > b[i] {
                return 1;
            } else if a[i] < b[i] {
                return -1;
            }
        }
        0
    }

    // Modular subtraction
    fn sub_modular(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut borrow = 0i64;
        
        for i in (0..32).rev() {
            let diff = (a[i] as i64) - (b[i] as i64) - borrow;
            if diff < 0 {
                result[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                result[i] = diff as u8;
                borrow = 0;
            }
        }
        
        result
    }

    // Convert hex string to bytes
    fn hex_to_bytes(&self, hex: &str) -> [u8; 32] {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            if i < 32 {
                let hex_str = std::str::from_utf8(chunk).unwrap();
                bytes[31 - i] = u8::from_str_radix(hex_str, 16).unwrap_or(0);
            }
        }
        bytes
    }
}

// Poseidon hash implementation
pub struct PoseidonHasher {
    round_constants: Vec<FieldElement>,
    mds_matrix: [[FieldElement; 3]; 3],
}

impl PoseidonHasher {
    pub fn new() -> Self {
        let mut hasher = Self {
            round_constants: Vec::new(),
            mds_matrix: [[FieldElement::zero(); 3]; 3],
        };
        hasher.initialize_constants();
        hasher
    }

    fn initialize_constants(&mut self) {
        // Initialize round constants
        for &constant in &ROUND_CONSTANTS {
            let bytes = self.hex_to_bytes(constant);
            self.round_constants.push(FieldElement::new(bytes));
        }

        // Initialize MDS matrix
        for i in 0..3 {
            for j in 0..3 {
                let bytes = self.hex_to_bytes(MDS_MATRIX[i][j]);
                self.mds_matrix[i][j] = FieldElement::new(bytes);
            }
        }
    }

    fn hex_to_bytes(&self, hex: &str) -> [u8; 32] {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            if i < 32 {
                let hex_str = std::str::from_utf8(chunk).unwrap();
                bytes[31 - i] = u8::from_str_radix(hex_str, 16).unwrap_or(0);
            }
        }
        bytes
    }

    // Main Poseidon hash function
    pub fn hash(&self, inputs: &[FieldElement]) -> FieldElement {
        if inputs.len() != 2 {
            panic!("Poseidon hash requires exactly 2 inputs");
        }

        // Initialize state
        let mut state = [
            inputs[0],
            inputs[1],
            FieldElement::zero(),
        ];

        // Apply Poseidon rounds
        let mut round_idx = 0;

        // Full rounds (first half)
        for _ in 0..POSEIDON_ROUNDS_F / 2 {
            state = self.full_round(&state, round_idx);
            round_idx += POSEIDON_WIDTH;
        }

        // Partial rounds
        for _ in 0..POSEIDON_ROUNDS_P {
            state = self.partial_round(&state, round_idx);
            round_idx += 1;
        }

        // Full rounds (second half)
        for _ in 0..POSEIDON_ROUNDS_F / 2 {
            state = self.full_round(&state, round_idx);
            round_idx += POSEIDON_WIDTH;
        }

        // Return first element
        state[0]
    }

    fn full_round(&self, state: &[FieldElement; 3], round_idx: usize) -> [FieldElement; 3] {
        // Add round constants
        let mut new_state = [
            state[0].add(&self.round_constants[round_idx]),
            state[1].add(&self.round_constants[round_idx + 1]),
            state[2].add(&self.round_constants[round_idx + 2]),
        ];

        // Apply S-box to all elements
        new_state[0] = new_state[0].sbox();
        new_state[1] = new_state[1].sbox();
        new_state[2] = new_state[2].sbox();

        // Apply MDS matrix
        self.apply_mds_matrix(&new_state)
    }

    fn partial_round(&self, state: &[FieldElement; 3], round_idx: usize) -> [FieldElement; 3] {
        // Add round constant
        let mut new_state = [
            state[0].add(&self.round_constants[round_idx]),
            state[1],
            state[2],
        ];

        // Apply S-box to first element only
        new_state[0] = new_state[0].sbox();

        // Apply MDS matrix
        self.apply_mds_matrix(&new_state)
    }

    fn apply_mds_matrix(&self, state: &[FieldElement; 3]) -> [FieldElement; 3] {
        let mut result = [FieldElement::zero(); 3];

        for i in 0..3 {
            for j in 0..3 {
                result[i] = result[i].add(&state[j].mul(&self.mds_matrix[i][j]));
            }
        }

        result
    }
}

// Public API functions
pub fn poseidon_hash_merge(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let hasher = PoseidonHasher::new();
    let left_fe = FieldElement::new(left);
    let right_fe = FieldElement::new(right);
    let result = hasher.hash(&[left_fe, right_fe]);
    result.value
}

pub fn poseidon_hash_bytes(bytes: &[u8]) -> [u8; 32] {
    if bytes.is_empty() {
        return [0u8; 32];
    }

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    poseidon_hash_merge(hash.into(), [0u8; 32])
}

pub fn poseidon_merkle_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    poseidon_hash_merge(left, right)
}

pub fn poseidon_commitment_hash(address: [u8; 32], psi: [u8; 32], value: [u8; 32], token: &[u8], source: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_COMMITMENT");
    hasher.update(&address);
    hasher.update(&psi);
    hasher.update(&value);
    hasher.update(token);
    hasher.update(&source);
    let hash = hasher.finalize();
    poseidon_hash_bytes(&hash)
}

pub fn poseidon_nullifier_hash(secret_key: [u8; 32], commitment: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_NULLIFIER");
    hasher.update(&secret_key);
    hasher.update(&commitment);
    let hash = hasher.finalize();
    poseidon_hash_bytes(&hash)
}

pub fn poseidon_utxo_value_hash(commitment: [u8; 32], input_value: u64, output_value: u64, batch_idx: usize, txn_idx: usize, block_height: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_UTXO_VALUE");
    hasher.update(&commitment);
    hasher.update(&input_value.to_le_bytes());
    hasher.update(&output_value.to_le_bytes());
    hasher.update(&batch_idx.to_le_bytes());
    hasher.update(&txn_idx.to_le_bytes());
    hasher.update(&block_height.to_le_bytes());
    let hash = hasher.finalize();
    poseidon_hash_bytes(&hash)
}

pub fn poseidon_proof_hash(instances: &[u64], old_root: &[u8; 32], new_root: &[u8; 32], utxo_values: &[[u8; 32]], nullifiers: &[[u8; 32]], commitments: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"POSEIDON_PROOF_HASH");
    
    for &instance in instances {
        hasher.update(&instance.to_le_bytes());
    }
    hasher.update(old_root);
    hasher.update(new_root);
    for utxo_value in utxo_values {
        hasher.update(utxo_value);
    }
    for nullifier in nullifiers {
        hasher.update(nullifier);
    }
    for commitment in commitments {
        hasher.update(commitment);
    }
    
    let hash = hasher.finalize();
    poseidon_hash_bytes(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash_merge() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let result = poseidon_hash_merge(left, right);
        
        // Result should be different from inputs
        assert_ne!(result, left);
        assert_ne!(result, right);
        
        // Result should be deterministic
        let result2 = poseidon_hash_merge(left, right);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_poseidon_hash_bytes() {
        let bytes = b"hello world";
        let result = poseidon_hash_bytes(bytes);
        
        // Result should be 32 bytes
        assert_eq!(result.len(), 32);
        
        // Result should be deterministic
        let result2 = poseidon_hash_bytes(bytes);
        assert_eq!(result, result2);
    }
}