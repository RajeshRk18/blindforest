use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use zeroize::Zeroize;

use crate::params::{AES_NONCE_LEN, HASH_LEN, SEED_LEN};

/// AES-256-CTR based PRF.
///
/// Expands a seed (used as AES key) with a nonce into a pseudorandom stream.
pub struct Prf {
    cipher: Ctr128BE<Aes256>,
}

impl Prf {
    /// Create a new PRF instance from a 32-byte seed (AES key) and 16-byte nonce.
    pub fn new(seed: &[u8; SEED_LEN], nonce: &[u8; AES_NONCE_LEN]) -> Self {
        let cipher = Ctr128BE::<Aes256>::new(seed.into(), nonce.into());
        Self { cipher }
    }

    /// Create a PRF for WOTS key generation.
    /// Nonce encodes: leaf_index (4 bytes) || chain_index (4 bytes) || zeros (8 bytes).
    pub fn for_wots(seed: &[u8; SEED_LEN], leaf_index: u32, chain_index: u32) -> Self {
        let mut nonce = [0u8; AES_NONCE_LEN];
        nonce[0..4].copy_from_slice(&leaf_index.to_be_bytes());
        nonce[4..8].copy_from_slice(&chain_index.to_be_bytes());
        Self::new(seed, &nonce)
    }

    /// Create a PRF for MPC random tape generation.
    /// Nonce encodes: round (4 bytes) || party (1 byte) || zeros (11 bytes).
    pub fn for_tape(seed: &[u8; SEED_LEN], round: u32, party: u8) -> Self {
        let mut nonce = [0u8; AES_NONCE_LEN];
        nonce[0..4].copy_from_slice(&round.to_be_bytes());
        nonce[4] = party;
        Self::new(seed, &nonce)
    }

    /// Generate `len` pseudorandom bytes.
    pub fn generate(&mut self, len: usize) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; len];
        self.fill(&mut buf);
        buf
    }

    /// Fill a buffer with pseudorandom bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        // CTR mode: encrypting zeros gives us the keystream
        self.cipher.apply_keystream(buf);
    }

    /// Generate a single 32-byte hash-sized output.
    pub fn generate_hash(&mut self) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        self.fill(&mut out);
        out
    }

    /// Generate a single u32 from the PRF stream.
    pub fn generate_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        u32::from_le_bytes(buf)
    }
}

/// A seed that can be zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PrfSeed(pub [u8; SEED_LEN]);

impl PrfSeed {
    /// Generate a random seed.
    pub fn random(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let mut seed = [0u8; SEED_LEN];
        rng.fill_bytes(&mut seed);
        Self(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_deterministic() {
        let seed = [0x42u8; SEED_LEN];
        let nonce = [0u8; AES_NONCE_LEN];

        let mut prf1 = Prf::new(&seed, &nonce);
        let mut prf2 = Prf::new(&seed, &nonce);

        let out1 = prf1.generate(64);
        let out2 = prf2.generate(64);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_prf_different_nonces_differ() {
        let seed = [0x42u8; SEED_LEN];
        let nonce1 = [0u8; AES_NONCE_LEN];
        let mut nonce2 = [0u8; AES_NONCE_LEN];
        nonce2[0] = 1;

        let mut prf1 = Prf::new(&seed, &nonce1);
        let mut prf2 = Prf::new(&seed, &nonce2);

        let out1 = prf1.generate(32);
        let out2 = prf2.generate(32);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_prf_streaming_consistency() {
        let seed = [0xABu8; SEED_LEN];
        let nonce = [0u8; AES_NONCE_LEN];

        // Generate 64 bytes at once
        let mut prf1 = Prf::new(&seed, &nonce);
        let all_at_once = prf1.generate(64);

        // Generate 64 bytes in two chunks
        let mut prf2 = Prf::new(&seed, &nonce);
        let chunk1 = prf2.generate(32);
        let chunk2 = prf2.generate(32);

        assert_eq!(&all_at_once[..32], &chunk1[..]);
        assert_eq!(&all_at_once[32..], &chunk2[..]);
    }
}
