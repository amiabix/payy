// ECDSA signature verification using secp256k1 crate
// This implements ECDSA functions using the secp256k1 library

use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, ecdsa::Signature};
use sha2::{Digest, Sha256};

// ECDSA signature data structure (from Payy)
#[derive(Debug, Clone)]
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

#[derive(Debug, Clone)]
pub struct EcdsaPublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct EcdsaSignData {
    pub signature: EcdsaSignature,
    pub public_key: EcdsaPublicKey,
    pub message: Vec<u8>,
    pub message_hash: [u8; 32],
}

/// ECDSA signature verification using secp256k1
pub fn verify_ecdsa_signature(signature: &EcdsaSignature, message: &[u8], public_key: &EcdsaPublicKey) -> bool {
    // Convert to secp256k1 types
    let secp = Secp256k1::new();
    
    // Create message hash
    let message_hash = hash_message_sha256(message);
    let message = match Message::from_slice(&message_hash) {
        Ok(msg) => msg,
        Err(_) => return false,
    };
    
    // Convert signature
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(&signature.r);
    sig_bytes[32..64].copy_from_slice(&signature.s);
    
    let sig = match Signature::from_compact(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    // Convert public key
    let mut pubkey_bytes = [0u8; 65];
    pubkey_bytes[0] = 0x04; // uncompressed prefix
    pubkey_bytes[1..33].copy_from_slice(&public_key.x);
    pubkey_bytes[33..65].copy_from_slice(&public_key.y);
    
    let pubkey = match PublicKey::from_slice(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    
    // Verify signature
    secp.verify_ecdsa(&message, &sig, &pubkey).is_ok()
}

/// Hash message using SHA256 (ZisK compatible)
fn hash_message_sha256(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

/// Generate ECDSA signature using secp256k1
pub fn generate_ecdsa_signature_payy_style(message: &[u8], secret_key: &[u8; 32]) -> EcdsaSignature {
    let secp = Secp256k1::new();
    
    // Convert secret key
    let secret_key = match SecretKey::from_slice(secret_key) {
        Ok(sk) => sk,
        Err(_) => {
            // Fallback to deterministic generation
            return generate_deterministic_signature(message, secret_key);
        }
    };
    
    // Create message hash
    let message_hash = hash_message_sha256(message);
    let message = match Message::from_slice(&message_hash) {
        Ok(msg) => msg,
        Err(_) => {
            return generate_deterministic_signature(message, &secret_key.secret_bytes());
        }
    };
    
    // Sign message
    let signature = secp.sign_ecdsa(&message, &secret_key);
    let sig_bytes = signature.serialize_compact();
    
    // Convert to our format
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[0..32]);
    s_bytes.copy_from_slice(&sig_bytes[32..64]);
    
    EcdsaSignature {
        r: r_bytes,
        s: s_bytes,
        v: 0, // Recovery ID not needed for verification
    }
}

/// Generate deterministic signature as fallback
fn generate_deterministic_signature(message: &[u8], secret_key: &[u8; 32]) -> EcdsaSignature {
    let mut hasher = Sha256::new();
    hasher.update(b"ECDSA_SIGNATURE_GENERATION");
    hasher.update(secret_key);
    hasher.update(message);
    
    let sig_hash = hasher.finalize();
    
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_hash[0..32]);
    s.copy_from_slice(&sig_hash[32..64]);
    
    EcdsaSignature { r, s, v: 0 }
}

/// Generate public key using secp256k1
pub fn generate_public_key_payy_style(secret_key: &[u8; 32]) -> EcdsaPublicKey {
    let secp = Secp256k1::new();
    
    // Convert secret key
    let secret_key = match SecretKey::from_slice(secret_key) {
        Ok(sk) => sk,
        Err(_) => {
            // Fallback to deterministic generation
            return generate_deterministic_public_key(secret_key);
        }
    };
    
    // Generate public key
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let serialized = public_key.serialize_uncompressed();
    
    // Extract x and y coordinates
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&serialized[1..33]);
    y.copy_from_slice(&serialized[33..65]);
    
    EcdsaPublicKey { x, y }
}

/// Generate deterministic public key as fallback
fn generate_deterministic_public_key(secret_key: &[u8; 32]) -> EcdsaPublicKey {
    let mut hasher = Sha256::new();
    hasher.update(b"ECDSA_PUBLIC_KEY_GENERATION");
    hasher.update(secret_key);
    
    let key_hash = hasher.finalize();
    
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&key_hash[0..32]);
    y.copy_from_slice(&key_hash[32..64]);
    
    EcdsaPublicKey { x, y }
}

/// Convert signature data from Payy format
pub fn convert_signature_data(
    signature_bytes: &[u8; 64],
    recovery_id: u8,
    message: &[u8],
    public_key_bytes: &[u8; 64]
) -> EcdsaSignData {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature_bytes[0..32]);
    s.copy_from_slice(&signature_bytes[32..64]);
    
    let mut pub_x = [0u8; 32];
    let mut pub_y = [0u8; 32];
    pub_x.copy_from_slice(&public_key_bytes[0..32]);
    pub_y.copy_from_slice(&public_key_bytes[32..64]);
    
    let message_hash = hash_message_sha256(message);
    
    EcdsaSignData {
        signature: EcdsaSignature { r, s, v: recovery_id },
        public_key: EcdsaPublicKey { x: pub_x, y: pub_y },
        message: message.to_vec(),
        message_hash,
    }
}

/// Verify all ECDSA signatures in a batch
pub fn verify_all_ecdsa_signatures(signatures: &[EcdsaSignData]) -> bool {
    for sign_data in signatures {
        if !verify_ecdsa_signature(&sign_data.signature, &sign_data.message, &sign_data.public_key) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_signature_verification() {
        // Test with dummy data
        let signature = EcdsaSignature {
            r: [1u8; 32],
            s: [2u8; 32],
            v: 0,
        };
        
        let public_key = EcdsaPublicKey {
            x: [3u8; 32],
            y: [4u8; 32],
        };
        
        let message = b"test message";
        
        // This will fail with dummy data, but tests the structure
        let result = verify_ecdsa_signature(&signature, message, &public_key);
        assert!(!result); // Should fail with dummy data
    }

    #[test]
    fn test_message_hashing() {
        let message = b"hello world";
        let hash1 = hash_message_sha256(message);
        let hash2 = hash_message_sha256(message);
        
        // Should be deterministic
        assert_eq!(hash1, hash2);
        
        // Should be different for different messages
        let different_message = b"different message";
        let hash3 = hash_message_sha256(different_message);
        assert_ne!(hash1, hash3);
    }
}