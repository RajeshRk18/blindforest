use crate::params::HASH_LEN;

/// A Merkle tree root hash.
pub type MerkleRoot = [u8; HASH_LEN];

/// A node in the Merkle tree (32-byte hash).
pub type MerkleNode = [u8; HASH_LEN];

/// Authentication path for a leaf in the Merkle tree.
#[derive(Debug, Clone)]
pub struct AuthPath {
    /// Sibling hashes from leaf to root (length = TREE_HEIGHT).
    pub siblings: alloc::vec::Vec<MerkleNode>,
}

/// The full Merkle tree stored as a flat array.
/// Index 1 = root, indices [NUM_LEAVES..2*NUM_LEAVES) = leaves.
#[derive(Clone)]
pub struct MerkleTree {
    /// Flat array of nodes. Length = 2 * NUM_LEAVES.
    /// nodes[0] is unused, nodes[1] is root.
    pub nodes: alloc::vec::Vec<MerkleNode>,
}
