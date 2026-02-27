//! Types for the blind signature protocol (Herranz & Louiso construction).
//!
//! This module defines the key types, intermediate protocol messages, and final
//! blind signature that flow through the four phases of the protocol:
//!
//! 1. **Keygen** -- [`BlindSigKeyPair`] containing [`BlindSigSecretKey`] and [`BlindSigPublicKey`].
//! 2. **BS.Sig1 (commit)** -- User produces [`CommittedMessage`] and retains [`UserState`].
//! 3. **BS.Sig2 (sign)** -- Signer produces [`SignerResponse`] from the committed message.
//! 4. **BS.Sig3 (unblind/prove)** -- User produces the final [`BlindSignature`].

use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::AtomicU32;

use crate::commitment::{Commitment, CommitmentRandomness};
use crate::merkle::types::{AuthPath, MerkleTree};
use crate::params::{HASH_LEN, SEED_LEN};
use crate::wots::types::WotsSignature;
use crate::zkboo::types::Proof;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Blind signature secret key.
///
/// Contains the master seed for WOTS key derivation, the full Merkle tree
/// (needed for authentication path extraction), and a counter tracking the
/// next unused leaf. Each leaf can only be used once -- attempting to sign
/// after all leaves are exhausted returns [`Error::KeyExhausted`].
///
/// # Security
///
/// The seed is zeroized on drop. This type intentionally does **not**
/// implement `Debug` to avoid accidentally leaking secret material in logs.
///
/// [`Error::KeyExhausted`]: crate::error::Error::KeyExhausted
pub struct BlindSigSecretKey {
    /// Master seed for deriving WOTS keypairs via the PRF.
    pub(crate) seed: [u8; SEED_LEN],
    /// The full Merkle tree (needed for auth path extraction).
    pub(crate) tree: MerkleTree,
    /// Atomic counter tracking the next leaf index to use.
    /// Monotonically increasing; returns [`Error::KeyExhausted`] when it
    /// reaches [`NUM_LEAVES`].
    ///
    /// [`Error::KeyExhausted`]: crate::error::Error::KeyExhausted
    /// [`NUM_LEAVES`]: crate::params::NUM_LEAVES
    pub(crate) next_leaf: AtomicU32,
}

impl Drop for BlindSigSecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
    }
}

/// Blind signature public key.
///
/// This is simply the Merkle tree root hash. It is safe to share publicly
/// and is used by both the signer (to issue commitments) and the verifier
/// (to check blind signatures).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSigPublicKey {
    /// The Merkle root hash.
    pub root: [u8; HASH_LEN],
}

/// A blind signature keypair (secret key + public key).
///
/// Produced by [`generate_keypair`] or [`BlindSigKeyPair::generate`].
///
/// [`generate_keypair`]: crate::blind::keygen::generate_keypair
/// [`BlindSigKeyPair::generate`]: BlindSigKeyPair::generate
pub struct BlindSigKeyPair {
    /// The secret key (contains the seed and Merkle tree).
    pub secret_key: BlindSigSecretKey,
    /// The public key (Merkle root).
    pub public_key: BlindSigPublicKey,
}

// ---------------------------------------------------------------------------
// Protocol messages
// ---------------------------------------------------------------------------

/// The committed message sent from user to signer (BS.Sig1 output).
///
/// The user computes `Com(m; r)` and sends only this commitment to the
/// signer, keeping the message `m` and randomness `r` private.
#[derive(Debug, Clone)]
pub struct CommittedMessage {
    /// The commitment value `Com(m; r)`.
    pub commitment: Commitment,
}

/// The signer's response to a committed message (BS.Sig2 output).
///
/// Contains a WOTS one-time signature on the commitment hash, the Merkle
/// authentication path for the leaf that was used, and the leaf index.
/// This is sent back to the user who will use it to construct a ZKBoo
/// proof during the unblinding step.
#[derive(Debug, Clone)]
pub struct SignerResponse {
    /// WOTS signature on the commitment hash.
    pub wots_sig: WotsSignature,
    /// Merkle authentication path for the used leaf.
    pub auth_path: AuthPath,
    /// The leaf index used for signing.
    pub leaf_index: u32,
}

impl SignerResponse {
    /// Serialized size in bytes.
    pub fn serialized_size(&self) -> usize {
        use crate::params::HASH_LEN;
        // WOTS signature elements + auth path siblings + leaf index
        self.wots_sig.elements.len() * HASH_LEN
            + self.auth_path.siblings.len() * HASH_LEN
            + 4 // leaf_index u32
    }
}

/// User-side state retained between BS.Sig1 (commit) and BS.Sig3 (unblind/prove).
///
/// This holds the original message, commitment randomness, and the commitment
/// itself. It is consumed during the unblinding step and should not be
/// persisted beyond that.
///
/// # Security
///
/// Contains the commitment randomness which is secret until the blind
/// signature is produced. This type does not implement `Debug` to avoid
/// leaking the randomness.
pub struct UserState {
    /// The original message the user wants signed.
    pub(crate) message: Vec<u8>,
    /// Commitment randomness used in BS.Sig1.
    pub(crate) randomness: CommitmentRandomness,
    /// The commitment value `Com(m; r)`.
    pub(crate) commitment: Commitment,
}

// ---------------------------------------------------------------------------
// Final blind signature
// ---------------------------------------------------------------------------

/// A complete blind signature.
///
/// Contains the commitment randomness (revealed so the verifier can
/// recompute the commitment), the ZKBoo proof demonstrating knowledge of
/// a valid WOTS signature and Merkle authentication path, and the leaf
/// index used as public circuit input.
///
/// # Verification
///
/// The verifier recomputes `Com(m; r)` from the message and randomness,
/// then checks the ZKBoo proof against the public key root and commitment
/// hash as circuit public input.
#[derive(Debug, Clone)]
pub struct BlindSignature {
    /// The commitment randomness (revealed to allow recomputation of the commitment).
    pub randomness: CommitmentRandomness,
    /// The ZKBoo proof of valid WOTS signature + Merkle authentication path.
    pub proof: Proof,
    /// Leaf index (public, needed for the circuit public input).
    pub leaf_index: u32,
}

impl BlindSignature {
    /// Serialized size in bytes.
    pub fn serialized_size(&self) -> usize {
        use crate::params::COMMITMENT_RAND_LEN;
        COMMITMENT_RAND_LEN // randomness
            + self.proof.serialized_size() // ZKBoo proof
            + 4 // leaf_index u32
    }
}

// ---------------------------------------------------------------------------
// Debug impls for types that hold secrets
// ---------------------------------------------------------------------------

impl fmt::Debug for BlindSigSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindSigSecretKey")
            .field("seed", &"[REDACTED]")
            .field("next_leaf", &self.next_leaf)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for UserState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserState")
            .field("message_len", &self.message.len())
            .field("randomness", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for BlindSigKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindSigKeyPair")
            .field("secret_key", &self.secret_key)
            .field("public_key", &self.public_key)
            .finish()
    }
}
