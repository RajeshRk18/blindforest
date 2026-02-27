use crate::params::{HASH_LEN, SEED_LEN, WOTS_LEN};
use crate::hash::{self, Domain};
use crate::prf::Prf;
use crate::wots::types::{WotsElement, WotsSecretKey, WotsPublicKey};

/// Hash a WOTS element once (chain length 1) at position `index`.
pub fn chain_hash(element: &WotsElement, index: usize) -> WotsElement {
    hash::hash_with_domain2(Domain::WotsChain, element, &(index as u32).to_be_bytes())
}

/// Generate a WOTS key pair from a seed and leaf index.
pub fn wots_keygen(seed: &[u8; SEED_LEN], leaf_index: u32) -> (WotsSecretKey, WotsPublicKey) {
    let mut sk_elements = alloc::vec::Vec::with_capacity(WOTS_LEN);
    let mut pk_elements = alloc::vec::Vec::with_capacity(WOTS_LEN);

    for i in 0..WOTS_LEN {
        // Generate secret key element from PRF
        let mut prf = Prf::for_wots(seed, leaf_index, i as u32);
        let sk_i = prf.generate_hash();

        // Public key element = H(sk_i) with position binding
        let pk_i = chain_hash(&sk_i, i);

        sk_elements.push(sk_i);
        pk_elements.push(pk_i);
    }

    (
        WotsSecretKey { elements: sk_elements },
        WotsPublicKey { elements: pk_elements },
    )
}

/// Compute the leaf hash from a WOTS public key.
/// This is used as the leaf value in the Merkle tree.
pub fn wots_pk_to_leaf(pk: &WotsPublicKey) -> [u8; HASH_LEN] {
    // First compress the pk, then hash with leaf domain
    let compressed = pk.compress();
    hash::hash_with_domain(Domain::LeafHash, &compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_deterministic() {
        let seed = [0x42u8; SEED_LEN];
        let (sk1, pk1) = wots_keygen(&seed, 0);
        let (sk2, pk2) = wots_keygen(&seed, 0);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1.elements, sk2.elements);
    }

    #[test]
    fn test_keygen_different_leaves() {
        let seed = [0x42u8; SEED_LEN];
        let (_, pk1) = wots_keygen(&seed, 0);
        let (_, pk2) = wots_keygen(&seed, 1);
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_keygen_correct_lengths() {
        let seed = [0x42u8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 0);
        assert_eq!(sk.elements.len(), WOTS_LEN);
        assert_eq!(pk.elements.len(), WOTS_LEN);
    }
}
