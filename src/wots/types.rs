use crate::params::HASH_LEN;

/// A single WOTS secret key element (32 bytes).
pub type WotsElement = [u8; HASH_LEN];

/// WOTS secret key: WOTS_LEN elements, each HASH_LEN bytes.
#[derive(Clone)]
pub struct WotsSecretKey {
    pub elements: alloc::vec::Vec<WotsElement>,
}

impl zeroize::Zeroize for WotsSecretKey {
    fn zeroize(&mut self) {
        for elem in self.elements.iter_mut() {
            elem.zeroize();
        }
    }
}

impl Drop for WotsSecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

/// WOTS public key: WOTS_LEN elements hashed, then compressed into a single hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotsPublicKey {
    pub elements: alloc::vec::Vec<WotsElement>,
}

impl WotsPublicKey {
    /// Compress the public key elements into a single hash.
    pub fn compress(&self) -> [u8; HASH_LEN] {
        use crate::hash::{Domain, DomainHasher};
        let mut hasher = DomainHasher::new(Domain::WotsPkCompress);
        for elem in &self.elements {
            hasher.update(elem);
        }
        hasher.finalize()
    }
}

/// WOTS signature: for each bit, either sk_i (if bit=0) or H(sk_i) (if bit=1).
#[derive(Debug, Clone)]
pub struct WotsSignature {
    pub elements: alloc::vec::Vec<WotsElement>,
}

impl WotsSignature {
    /// Serialized size in bytes.
    pub fn serialized_size(&self) -> usize {
        self.elements.len() * HASH_LEN
    }
}
