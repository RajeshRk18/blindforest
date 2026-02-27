//! Key generation for the blind signature scheme.
//!
//! Produces a [`BlindSigKeyPair`] by:
//! 1. Sampling (or accepting) a master seed.
//! 2. Deriving [`NUM_LEAVES`] WOTS keypairs from the seed via the PRF.
//! 3. Hashing each WOTS public key into a Merkle leaf.
//! 4. Building the full Merkle tree and extracting its root as the public key.
//!
//! [`NUM_LEAVES`]: crate::params::NUM_LEAVES

use core::sync::atomic::AtomicU32;

use crate::blind::types::{BlindSigKeyPair, BlindSigPublicKey, BlindSigSecretKey};
use crate::merkle::tree::build_tree;
use crate::params::{NUM_LEAVES, SEED_LEN};
use crate::wots::keygen::{wots_keygen, wots_pk_to_leaf};

/// Generate a blind signature keypair from a cryptographic RNG.
///
/// Fills a fresh [`SEED_LEN`]-byte seed from `rng`, then delegates to
/// [`generate_keypair_from_seed`] for deterministic tree construction.
///
/// # Examples
///
/// ```
/// use blindforest::blind::keygen::generate_keypair;
/// let mut rng = rand_core::OsRng;
/// let kp = generate_keypair(&mut rng);
/// assert_eq!(kp.public_key.root.len(), 32);
/// ```
pub fn generate_keypair(rng: &mut impl rand_core::CryptoRngCore) -> BlindSigKeyPair {
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);
    generate_keypair_from_seed(&seed)
}

/// Generate a keypair deterministically from a given seed.
///
/// This is useful for testing and for schemes where the seed is derived
/// from a higher-level key hierarchy.
///
/// # Arguments
///
/// * `seed` -- A [`SEED_LEN`]-byte master seed. All WOTS keypairs are
///   derived from this seed via the crate PRF.
///
/// # Examples
///
/// ```
/// use blindforest::blind::keygen::generate_keypair_from_seed;
/// use blindforest::params::SEED_LEN;
///
/// let seed = [0x42u8; SEED_LEN];
/// let kp = generate_keypair_from_seed(&seed);
/// // Deterministic: same seed always yields the same root.
/// let kp2 = generate_keypair_from_seed(&seed);
/// assert_eq!(kp.public_key.root, kp2.public_key.root);
/// ```
pub fn generate_keypair_from_seed(seed: &[u8; SEED_LEN]) -> BlindSigKeyPair {
    // Derive all WOTS leaf hashes from the master seed.
    let mut leaves = alloc::vec::Vec::with_capacity(NUM_LEAVES);
    for i in 0..NUM_LEAVES {
        let (_sk, pk) = wots_keygen(seed, i as u32);
        leaves.push(wots_pk_to_leaf(&pk));
    }

    // Build the Merkle tree over the leaf hashes.
    let tree = build_tree(&leaves);
    let root = tree.root();

    BlindSigKeyPair {
        secret_key: BlindSigSecretKey {
            seed: *seed,
            tree,
            next_leaf: AtomicU32::new(0),
        },
        public_key: BlindSigPublicKey { root },
    }
}

impl BlindSigKeyPair {
    /// Generate a blind signature keypair.
    ///
    /// Convenience wrapper around [`generate_keypair`].
    pub fn generate(rng: &mut impl rand_core::CryptoRngCore) -> BlindSigKeyPair {
        generate_keypair(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_deterministic() {
        let seed = [0x42u8; SEED_LEN];
        let kp1 = generate_keypair_from_seed(&seed);
        let kp2 = generate_keypair_from_seed(&seed);
        assert_eq!(
            kp1.public_key.root, kp2.public_key.root,
            "same seed must produce the same Merkle root"
        );
    }

    #[test]
    fn test_keygen_different_seeds() {
        let seed_a = [0x01u8; SEED_LEN];
        let seed_b = [0x02u8; SEED_LEN];
        let kp_a = generate_keypair_from_seed(&seed_a);
        let kp_b = generate_keypair_from_seed(&seed_b);
        assert_ne!(
            kp_a.public_key.root, kp_b.public_key.root,
            "different seeds must produce different Merkle roots"
        );
    }

    #[test]
    fn test_keygen_leaf_counter_starts_at_zero() {
        let seed = [0xFFu8; SEED_LEN];
        let kp = generate_keypair_from_seed(&seed);
        let counter = kp
            .secret_key
            .next_leaf
            .load(core::sync::atomic::Ordering::Relaxed);
        assert_eq!(counter, 0, "next_leaf must start at 0");
    }
}
