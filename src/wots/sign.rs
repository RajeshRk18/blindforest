use crate::params::{HASH_LEN, WOTS_LEN};
use crate::util;
use crate::wots::keygen::chain_hash;
use crate::wots::types::{WotsSecretKey, WotsSignature};

/// Sign a message hash using a WOTS secret key.
/// `msg_hash` must be HASH_LEN bytes (256 bits = WOTS_LEN bits).
pub fn wots_sign(sk: &WotsSecretKey, msg_hash: &[u8; HASH_LEN]) -> WotsSignature {
    assert_eq!(sk.elements.len(), WOTS_LEN);

    let mut sig_elements = alloc::vec::Vec::with_capacity(WOTS_LEN);

    for i in 0..WOTS_LEN {
        let bit = util::get_doubled_bit(msg_hash, i);
        let sig_i = if bit == 0 {
            // Reveal sk[i] directly
            sk.elements[i]
        } else {
            // Reveal H(sk[i]) = pk[i]
            chain_hash(&sk.elements[i], i)
        };
        sig_elements.push(sig_i);
    }

    WotsSignature { elements: sig_elements }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SEED_LEN;
    use crate::wots::keygen::wots_keygen;
    use crate::hash;

    #[test]
    fn test_sign_produces_correct_length() {
        let seed = [0x42u8; SEED_LEN];
        let (sk, _pk) = wots_keygen(&seed, 0);
        let msg_hash = hash::hash_raw(b"test message");
        let sig = wots_sign(&sk, &msg_hash);
        assert_eq!(sig.elements.len(), WOTS_LEN);
    }

    #[test]
    fn test_sign_all_zeros_doubled() {
        let seed = [0x42u8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 0);
        // All-zeros message: first 256 bits are 0 (reveal sk), last 256 bits are 1 (reveal pk)
        let msg_hash = [0x00u8; HASH_LEN];
        let sig = wots_sign(&sk, &msg_hash);
        // First 256: doubled bit = 0, sig[i] = sk[i]
        for i in 0..256 {
            assert_eq!(sig.elements[i], sk.elements[i]);
        }
        // Last 256: doubled bit = 1 (complement), sig[i] = pk[i]
        for i in 256..512 {
            assert_eq!(sig.elements[i], pk.elements[i]);
        }
    }

    #[test]
    fn test_sign_all_ones_doubled() {
        let seed = [0x42u8; SEED_LEN];
        let (sk, pk) = wots_keygen(&seed, 0);
        // All-ones message: first 256 bits are 1 (reveal pk), last 256 bits are 0 (reveal sk)
        let msg_hash = [0xFFu8; HASH_LEN];
        let sig = wots_sign(&sk, &msg_hash);
        // First 256: doubled bit = 1, sig[i] = pk[i]
        for i in 0..256 {
            assert_eq!(sig.elements[i], pk.elements[i]);
        }
        // Last 256: doubled bit = 0 (complement), sig[i] = sk[i]
        for i in 256..512 {
            assert_eq!(sig.elements[i], sk.elements[i]);
        }
    }
}
