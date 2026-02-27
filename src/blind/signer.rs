//! Signer-side protocol operations for the blind signature scheme.
//!
//! The signer participates in one protocol phase:
//!
//! **BS.Sig2 (sign)** -- [`BlindSigSecretKey::sign_committed`] receives a
//! committed message from the user, allocates the next one-time leaf,
//! WOTS-signs the commitment value, and returns the signature together with
//! the Merkle authentication path.
//!
//! The signer never sees the original message -- only its commitment -- so
//! the resulting signature is *blind*.

use core::sync::atomic::Ordering;

use crate::blind::types::{BlindSigSecretKey, CommittedMessage, SignerResponse};
use crate::error::{Error, Result};
use crate::params::NUM_LEAVES;
use crate::wots::keygen::wots_keygen;
use crate::wots::sign::wots_sign;

impl BlindSigSecretKey {
    /// BS.Sig2: Sign a committed message.
    ///
    /// Atomically claims the next available Merkle leaf, derives the
    /// corresponding WOTS keypair, signs the commitment hash, and extracts
    /// the Merkle authentication path for the used leaf.
    ///
    /// # Arguments
    ///
    /// * `committed` -- The committed message received from the user in
    ///   BS.Sig1.
    ///
    /// # Returns
    ///
    /// A [`SignerResponse`] containing the WOTS signature on the commitment,
    /// the Merkle authentication path, and the leaf index. This is sent back
    /// to the user for BS.Sig3.
    ///
    /// # Errors
    ///
    /// * [`Error::KeyExhausted`] if all [`NUM_LEAVES`] one-time keys have
    ///   already been used. Each leaf can only be used once; reuse would
    ///   compromise security.
    ///
    /// # Thread Safety
    ///
    /// The leaf counter is updated atomically, so this method is safe to call
    /// concurrently from multiple threads. However, the Merkle tree and seed
    /// are read-only after construction, so no additional synchronization is
    /// needed.
    ///
    /// [`NUM_LEAVES`]: crate::params::NUM_LEAVES
    pub fn sign_committed(&self, committed: &CommittedMessage) -> Result<SignerResponse> {
        // Atomically claim the next leaf index.
        let leaf_index = self.next_leaf.fetch_add(1, Ordering::SeqCst);

        if leaf_index >= NUM_LEAVES as u32 {
            // Revert the counter (best-effort; concurrent callers may also
            // observe KeyExhausted, which is correct behavior).
            self.next_leaf.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::KeyExhausted);
        }

        // Derive the WOTS keypair for this leaf from the master seed.
        let (sk, _pk) = wots_keygen(&self.seed, leaf_index);

        // Sign the commitment value with WOTS.
        // The commitment value is already a [u8; HASH_LEN] hash, which is
        // exactly what wots_sign expects as its message hash.
        let wots_sig = wots_sign(&sk, &committed.commitment.value);

        // Extract the Merkle authentication path for the claimed leaf.
        let auth_path = self.tree.auth_path(leaf_index as usize);

        Ok(SignerResponse {
            wots_sig,
            auth_path,
            leaf_index,
        })
    }
}
