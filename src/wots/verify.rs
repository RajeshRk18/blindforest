use crate::params::{HASH_LEN, WOTS_LEN};
use crate::util;
use crate::wots::keygen::chain_hash;
use crate::wots::types::{WotsPublicKey, WotsSignature};

/// Verify a WOTS signature against a public key and message hash.
/// Returns true if the signature is valid.
pub fn wots_verify(pk: &WotsPublicKey, msg_hash: &[u8; HASH_LEN], sig: &WotsSignature) -> bool {
    if sig.elements.len() != WOTS_LEN || pk.elements.len() != WOTS_LEN {
        return false;
    }

    let recovered = wots_recover_pk(msg_hash, sig);
    recovered.elements == pk.elements
}

/// Recover a WOTS public key from a signature and message hash.
/// This is used in the ZKBoo circuit to verify without the original pk.
pub fn wots_recover_pk(msg_hash: &[u8; HASH_LEN], sig: &WotsSignature) -> WotsPublicKey {
    let mut pk_elements = alloc::vec::Vec::with_capacity(WOTS_LEN);

    for i in 0..WOTS_LEN {
        let bit = util::get_doubled_bit(msg_hash, i);
        let pk_i = if bit == 0 {
            // sig[i] = sk[i], so pk[i] = H(sig[i])
            chain_hash(&sig.elements[i], i)
        } else {
            // sig[i] = pk[i] already
            sig.elements[i]
        };
        pk_elements.push(pk_i);
    }

    WotsPublicKey { elements: pk_elements }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SEED_LEN;
    use crate::wots::keygen::wots_keygen;
    use crate::wots::sign::wots_sign;
    use crate::hash;

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [0x42u8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 0);
        let msg_hash = hash::hash_raw(b"hello world");
        let sig = wots_sign(&sk, &msg_hash);
        assert!(wots_verify(&pk, &msg_hash, &sig));
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let seed = [0x42u8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 0);
        let msg_hash = hash::hash_raw(b"hello world");
        let sig = wots_sign(&sk, &msg_hash);
        let wrong_hash = hash::hash_raw(b"wrong message");
        assert!(!wots_verify(&pk, &wrong_hash, &sig));
    }

    #[test]
    fn test_recover_pk_matches() {
        let seed = [0x42u8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 0);
        let msg_hash = hash::hash_raw(b"test recovery");
        let sig = wots_sign(&sk, &msg_hash);
        let recovered = wots_recover_pk(&msg_hash, &sig);
        assert_eq!(recovered, pk);
    }

    #[test]
    fn test_verify_all_zeros_message() {
        let seed = [0xABu8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 5);
        let msg_hash = [0x00u8; HASH_LEN];
        let sig = wots_sign(&sk, &msg_hash);
        assert!(wots_verify(&pk, &msg_hash, &sig));
    }

    #[test]
    fn test_verify_all_ones_message() {
        let seed = [0xCDu8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 3);
        let msg_hash = [0xFFu8; HASH_LEN];
        let sig = wots_sign(&sk, &msg_hash);
        assert!(wots_verify(&pk, &msg_hash, &sig));
    }
}
