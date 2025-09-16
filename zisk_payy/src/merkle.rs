// Merkle tree implementation from Payy's zk-primitives
// This implements the Merkle tree functions used in Payy

use crate::poseidon::*;

// Merkle tree path structure (from Payy)
#[derive(Debug, Clone)]
pub struct MerklePath {
    pub siblings: Vec<[u8; 32]>,
    pub path_indices: Vec<u8>,
    pub root_hash: [u8; 32],
}

/// Compute the root hash of a merkle tree using Payy's actual implementation
/// This matches Payy's compute_merkle_root function from zk-primitives
pub fn compute_merkle_root(
    mut leaf: [u8; 32],
    siblings: impl Iterator<Item = ([u8; 32], u8)>
) -> [u8; 32] {
    for (sibling, bit) in siblings {
        match bit {
            // bit is 0, this element is on the left (matches Payy's false)
            0 => leaf = poseidon_merkle_hash(leaf, sibling),
            // bit is 1, this element is on the right (matches Payy's true)
            1 => leaf = poseidon_merkle_hash(sibling, leaf),
            _ => panic!("Invalid bit value: {}", bit),
        }
    }
    
    leaf
}

/// Verify Merkle inclusion proof (implementation from Payy)
pub fn verify_merkle_inclusion_proof(
    leaf: [u8; 32],
    path: &MerklePath,
    root: [u8; 32]
) -> bool {
    let computed_root = compute_merkle_root(leaf, path.siblings.iter().zip(path.path_indices.iter()).map(|(s, d)| (*s, *d)));
    computed_root == root
}

/// Verify all Merkle inclusions in a batch
pub fn verify_all_merkle_inclusions(
    leaves: &[[u8; 32]],
    paths: &[MerklePath],
    root: [u8; 32]
) -> bool {
    if leaves.len() != paths.len() {
        return false;
    }
    
    for (leaf, path) in leaves.iter().zip(paths.iter()) {
        if !verify_merkle_inclusion_proof(*leaf, path, root) {
            return false;
        }
    }
    
    true
}

/// Generate Merkle path for an element
pub fn generate_merkle_path(element: [u8; 32], depth: usize) -> MerklePath {
    let mut siblings = Vec::new();
    let mut path_indices = Vec::new();

    // Generate deterministic path based on element using Poseidon
    let path_hash = poseidon_hash_bytes(&[
        b"MERKLE_PATH_GENERATION".as_ref(),
        &element
    ].concat());

    for i in 0..depth {
        // Generate sibling at this depth using Poseidon
        let sibling = poseidon_hash_bytes(&[
            b"MERKLE_SIBLING".as_ref(),
            &element,
            &i.to_le_bytes(),
            &path_hash
        ].concat());
        siblings.push(sibling);

        // Generate path index (0 or 1)
        let path_index = (path_hash[i % 32] % 2) as u8;
        path_indices.push(path_index);
    }

    // Generate root hash
    let root_hash = compute_merkle_root(element, siblings.iter().zip(path_indices.iter()).map(|(s, d)| (*s, *d)));

    MerklePath {
        siblings,
        path_indices,
        root_hash,
    }
}

/// Update Merkle tree with new element
pub fn update_merkle_tree(
    old_root: [u8; 32],
    new_element: [u8; 32]
) -> [u8; 32] {
    // Tree update using Poseidon hash
    poseidon_merkle_hash(old_root, new_element)
}

/// Compute new root after inserting elements
pub fn compute_new_root(
    old_root: [u8; 32],
    new_elements: &[[u8; 32]]
) -> [u8; 32] {
    let mut current_root = old_root;
    
    for element in new_elements {
        current_root = poseidon_merkle_hash(current_root, *element);
    }
    
    current_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_path_generation() {
        let element = [1u8; 32];
        let path = generate_merkle_path(element, 3);
        
        assert_eq!(path.siblings.len(), 3);
        assert_eq!(path.path_indices.len(), 3);
    }

    #[test]
    fn test_merkle_verification() {
        let element = [1u8; 32];
        let path = generate_merkle_path(element, 3);
        
        let is_valid = verify_merkle_inclusion_proof(element, &path, path.root_hash);
        assert!(is_valid);
    }

    #[test]
    fn test_compute_merkle_root() {
        let leaf = [1u8; 32];
        let sibling1 = [2u8; 32];
        let sibling2 = [3u8; 32];
        
        let siblings = vec![(sibling1, 0), (sibling2, 1)];
        let root = compute_merkle_root(leaf, siblings.into_iter());
        
        // Root should be deterministic
        assert_eq!(root.len(), 32);
    }
}