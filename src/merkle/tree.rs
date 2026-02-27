use crate::params::{HASH_LEN, NUM_LEAVES};
use crate::hash::{self, Domain};
use crate::merkle::types::MerkleTree;

/// Build a Merkle tree from leaf hashes.
/// `leaves` must have exactly NUM_LEAVES elements.
pub fn build_tree(leaves: &[[u8; HASH_LEN]]) -> MerkleTree {
    assert_eq!(leaves.len(), NUM_LEAVES, "expected {} leaves", NUM_LEAVES);

    // Allocate flat array: 2 * NUM_LEAVES nodes
    let mut nodes = alloc::vec![[0u8; HASH_LEN]; 2 * NUM_LEAVES];

    // Copy leaves into the bottom level
    for i in 0..NUM_LEAVES {
        nodes[NUM_LEAVES + i] = leaves[i];
    }

    // Build internal nodes bottom-up
    for i in (1..NUM_LEAVES).rev() {
        nodes[i] = hash::hash_with_domain2(
            Domain::MerkleNode,
            &nodes[2 * i],
            &nodes[2 * i + 1],
        );
    }

    MerkleTree { nodes }
}

impl MerkleTree {
    /// Get the root hash.
    pub fn root(&self) -> [u8; HASH_LEN] {
        self.nodes[1]
    }

    /// Get a leaf hash by leaf index (0-based).
    pub fn leaf(&self, index: usize) -> [u8; HASH_LEN] {
        assert!(index < NUM_LEAVES);
        self.nodes[NUM_LEAVES + index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tree_deterministic() {
        let mut leaves = alloc::vec![[0u8; HASH_LEN]; NUM_LEAVES];
        for (i, leaf) in leaves.iter_mut().enumerate() {
            leaf[0] = i as u8;
            leaf[1] = (i >> 8) as u8;
        }
        let tree1 = build_tree(&leaves);
        let tree2 = build_tree(&leaves);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_leaves_different_root() {
        let leaves1 = alloc::vec![[0u8; HASH_LEN]; NUM_LEAVES];
        let mut leaves2 = alloc::vec![[0u8; HASH_LEN]; NUM_LEAVES];
        leaves2[0][0] = 1; // Change just one leaf
        let tree1 = build_tree(&leaves1);
        let tree2 = build_tree(&leaves2);
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_leaf_retrieval() {
        let mut leaves = alloc::vec![[0u8; HASH_LEN]; NUM_LEAVES];
        for (i, leaf) in leaves.iter_mut().enumerate() {
            leaf[0] = i as u8;
        }
        let tree = build_tree(&leaves);
        for i in 0..NUM_LEAVES {
            assert_eq!(tree.leaf(i), leaves[i]);
        }
    }

    #[test]
    fn test_small_tree_manual() {
        // Verify internal node computation for a known case
        let mut leaves = alloc::vec![[0u8; HASH_LEN]; NUM_LEAVES];
        leaves[0] = [0xAAu8; HASH_LEN];
        leaves[1] = [0xBBu8; HASH_LEN];
        let tree = build_tree(&leaves);

        // Parent of leaves 0 and 1 should be H(leaf0 || leaf1)
        let expected_parent = hash::hash_with_domain2(
            Domain::MerkleNode,
            &leaves[0],
            &leaves[1],
        );
        // Parent of nodes[NUM_LEAVES+0] and nodes[NUM_LEAVES+1] is nodes[(NUM_LEAVES)/2]
        assert_eq!(tree.nodes[NUM_LEAVES / 2], expected_parent);
    }
}
