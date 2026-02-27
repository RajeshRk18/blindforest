use sha2::{Sha256, Digest};
use crate::params::HASH_LEN;

/// Domain separation tags for different hash usages.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Domain {
    /// WOTS chain hash
    WotsChain = 0,
    /// WOTS public key compression (hash all pk elements)
    WotsPkCompress = 1,
    /// Merkle tree internal node
    MerkleNode = 2,
    /// Commitment scheme
    Commitment = 3,
    /// Fiat-Shamir challenge
    FiatShamir = 4,
    /// ZKBoo view commitment
    ViewCommit = 5,
    /// PRF domain
    Prf = 6,
    /// Leaf hash (pk -> leaf)
    LeafHash = 7,
}

/// Hash output type (32 bytes).
pub type HashOutput = [u8; HASH_LEN];

/// Compute SHA-256 with domain separation: H(domain || data).
pub fn hash_with_domain(domain: Domain, data: &[u8]) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update([domain as u8]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA-256 with domain separation over multiple inputs: H(domain || a || b).
pub fn hash_with_domain2(domain: Domain, a: &[u8], b: &[u8]) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update([domain as u8]);
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA-256 with domain separation over three inputs: H(domain || a || b || c).
pub fn hash_with_domain3(domain: Domain, a: &[u8], b: &[u8], c: &[u8]) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update([domain as u8]);
    hasher.update(a);
    hasher.update(b);
    hasher.update(c);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    out
}

/// Compute raw SHA-256 (no domain separation).
pub fn hash_raw(data: &[u8]) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    out
}

/// Incremental hasher with domain separation.
pub struct DomainHasher {
    hasher: Sha256,
}

impl DomainHasher {
    /// Create a new hasher with the given domain tag.
    pub fn new(domain: Domain) -> Self {
        let mut hasher = Sha256::new();
        hasher.update([domain as u8]);
        Self { hasher }
    }

    /// Feed more data.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hash.
    pub fn finalize(self) -> HashOutput {
        let result = self.hasher.finalize();
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&result);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation_differs() {
        let data = b"test data";
        let h1 = hash_with_domain(Domain::WotsChain, data);
        let h2 = hash_with_domain(Domain::MerkleNode, data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_raw_hash_known_vector() {
        // SHA-256("abc") known answer
        let h = hash_raw(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn test_incremental_hasher() {
        let h1 = hash_with_domain2(Domain::Commitment, b"hello", b"world");
        let mut dh = DomainHasher::new(Domain::Commitment);
        dh.update(b"hello");
        dh.update(b"world");
        let h2 = dh.finalize();
        assert_eq!(h1, h2);
    }
}
