use crate::params::{HASH_LEN, NUM_LEAVES, TREE_HEIGHT};
use crate::hash::{self, Domain};
use crate::merkle::types::{AuthPath, MerkleTree};

impl MerkleTree {
    /// Extract the authentication path for a given leaf index.
    pub fn auth_path(&self, leaf_index: usize) -> AuthPath {
        assert!(leaf_index < NUM_LEAVES);

        let mut siblings = alloc::vec::Vec::with_capacity(TREE_HEIGHT);
        let mut node_index = NUM_LEAVES + leaf_index;

        for _ in 0..TREE_HEIGHT {
            // Sibling is the other child of the parent
            let sibling_index = node_index ^ 1;
            siblings.push(self.nodes[sibling_index]);
            node_index /= 2; // Move up to parent
        }

        AuthPath { siblings }
    }
}

/// Recompute the Merkle root from a leaf hash and its authentication path.
pub fn recompute_root(
    leaf_hash: &[u8; HASH_LEN],
    leaf_index: usize,
    auth_path: &AuthPath,
) -> [u8; HASH_LEN] {
    assert_eq!(auth_path.siblings.len(), TREE_HEIGHT);
    assert!(leaf_index < NUM_LEAVES);

    let mut current = *leaf_hash;
    let mut index = leaf_index;

    for level in 0..TREE_HEIGHT {
        let sibling = &auth_path.siblings[level];
        if index % 2 == 0 {
            // Current node is left child
            current = hash::hash_with_domain2(Domain::MerkleNode, &current, sibling);
        } else {
            // Current node is right child
            current = hash::hash_with_domain2(Domain::MerkleNode, sibling, &current);
        }
        index /= 2;
    }

    current
}

/// Verify that a leaf is in the tree with the given root.
pub fn verify_auth_path(
    leaf_hash: &[u8; HASH_LEN],
    leaf_index: usize,
    auth_path: &AuthPath,
    root: &[u8; HASH_LEN],
) -> bool {
    let computed = recompute_root(leaf_hash, leaf_index, auth_path);
    use subtle::ConstantTimeEq;
    bool::from(computed.ct_eq(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::tree::build_tree;

    fn make_test_tree() -> (MerkleTree, alloc::vec::Vec<[u8; HASH_LEN]>) {
        let mut leaves = alloc::vec![[0u8; HASH_LEN]; NUM_LEAVES];
        for (i, leaf) in leaves.iter_mut().enumerate() {
            // Give each leaf a unique value
            let bytes = (i as u32).to_be_bytes();
            leaf[0] = bytes[0];
            leaf[1] = bytes[1];
            leaf[2] = bytes[2];
            leaf[3] = bytes[3];
        }
        let tree = build_tree(&leaves);
        (tree, leaves)
    }

    #[test]
    fn test_auth_path_length() {
        let (tree, _) = make_test_tree();
        let path = tree.auth_path(0);
        assert_eq!(path.siblings.len(), TREE_HEIGHT);
    }

    #[test]
    fn test_auth_path_roundtrip_leaf0() {
        let (tree, leaves) = make_test_tree();
        let root = tree.root();
        let path = tree.auth_path(0);
        assert!(verify_auth_path(&leaves[0], 0, &path, &root));
    }

    #[test]
    fn test_auth_path_roundtrip_all_leaves() {
        let (tree, leaves) = make_test_tree();
        let root = tree.root();
        for i in 0..NUM_LEAVES {
            let path = tree.auth_path(i);
            assert!(
                verify_auth_path(&leaves[i], i, &path, &root),
                "auth path failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_auth_path_wrong_leaf_fails() {
        let (tree, _) = make_test_tree();
        let root = tree.root();
        let path = tree.auth_path(0);
        let wrong_leaf = [0xFFu8; HASH_LEN];
        assert!(!verify_auth_path(&wrong_leaf, 0, &path, &root));
    }

    #[test]
    fn test_auth_path_wrong_index_fails() {
        let (tree, leaves) = make_test_tree();
        let root = tree.root();
        let path = tree.auth_path(0);
        // Using leaf 0's path but claiming it's at index 1
        assert!(!verify_auth_path(&leaves[0], 1, &path, &root));
    }

    #[test]
    fn test_recompute_root_matches() {
        let (tree, leaves) = make_test_tree();
        let root = tree.root();
        for i in [0, 1, 42, 511, 512, 1023] {
            let path = tree.auth_path(i);
            let recomputed = recompute_root(&leaves[i], i, &path);
            assert_eq!(recomputed, root, "root mismatch for leaf {}", i);
        }
    }
}
