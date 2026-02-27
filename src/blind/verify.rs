//! Blind signature verification.
//!
//! **BS.Vfy** -- [`BlindSigPublicKey::verify`] checks a blind signature
//! against a message and the signer's public key. The verifier:
//!
//! 1. Recomputes the commitment `Com(m; r)` from the message and the
//!    revealed randomness in the signature.
//! 2. Sets the commitment hash as the circuit's `msg_hash` and the public
//!    key root as `expected_root`.
//! 3. Verifies the ZKBoo proof, which demonstrates that the signer
//!    WOTS-signed the commitment and that the signing leaf is part of
//!    the Merkle tree with the claimed root.

use crate::blind::types::{BlindSigPublicKey, BlindSignature};
use crate::commitment;
use crate::error::Result;
use crate::mpc::circuit::CircuitPublicInput;
use crate::zkboo::verifier;

impl BlindSigPublicKey {
    /// Verify a blind signature on a message.
    ///
    /// Recomputes the commitment from the message and the randomness
    /// embedded in the signature, then verifies the ZKBoo proof against
    /// the public key root.
    ///
    /// This function expects a full-security proof with [`NUM_ROUNDS`]
    /// repetitions. For testing with reduced-round proofs, use
    /// [`verify_with_rounds`](Self::verify_with_rounds) instead.
    ///
    /// # Arguments
    ///
    /// * `message` -- The message that was blindly signed.
    /// * `signature` -- The blind signature to verify.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid.
    ///
    /// # Errors
    ///
    /// * [`Error::VerificationFailed`] if the ZKBoo proof does not verify
    ///   (wrong message, tampered signature, or invalid proof).
    /// * [`Error::ProofFormat`] if the proof has an unexpected structure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use blindforest::blind::keygen::generate_keypair;
    /// use blindforest::blind::user::{user_commit, user_unblind};
    ///
    /// let mut rng = rand_core::OsRng;
    /// let kp = generate_keypair(&mut rng);
    ///
    /// let msg = b"hello blind world";
    /// let (state, committed) = user_commit(msg, &mut rng);
    /// let response = kp.secret_key.sign_committed(&committed).unwrap();
    /// let sig = user_unblind(&state, &kp.public_key, &response, &mut rng).unwrap();
    ///
    /// kp.public_key.verify(msg, &sig).unwrap();
    /// ```
    ///
    /// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
    /// [`Error::VerificationFailed`]: crate::error::Error::VerificationFailed
    /// [`Error::ProofFormat`]: crate::error::Error::ProofFormat
    pub fn verify(&self, message: &[u8], signature: &BlindSignature) -> Result<()> {
        let com = commitment::commit(message, &signature.randomness);

        let public_input = CircuitPublicInput {
            msg_hash: com.value,
            expected_root: self.root,
            leaf_index: signature.leaf_index,
        };

        verifier::verify(&signature.proof, &public_input)
    }

    /// Verify a blind signature, auto-detecting the round count from the proof.
    ///
    /// This is useful for verifying proofs generated with a reduced round
    /// count during testing. The round count is inferred from the proof
    /// structure rather than requiring the full [`NUM_ROUNDS`].
    ///
    /// # Arguments
    ///
    /// * `message` -- The message that was blindly signed.
    /// * `signature` -- The blind signature to verify.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid.
    ///
    /// # Errors
    ///
    /// Same as [`verify`](Self::verify).
    ///
    /// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
    pub fn verify_with_rounds(&self, message: &[u8], signature: &BlindSignature) -> Result<()> {
        let com = commitment::commit(message, &signature.randomness);

        let public_input = CircuitPublicInput {
            msg_hash: com.value,
            expected_root: self.root,
            leaf_index: signature.leaf_index,
        };

        verifier::verify_with_rounds(&signature.proof, &public_input)
    }
}

#[cfg(test)]
mod tests {
    use crate::blind::keygen::generate_keypair_from_seed;
    use crate::blind::user::{user_commit, user_unblind_with_rounds};
    use crate::error::Error;
    use crate::params::SEED_LEN;

    /// Full end-to-end blind signature test with 1 ZKBoo round.
    ///
    /// Even a single round exercises the full MPC circuit (approximately
    /// 267 SHA-256 evaluations in 3-party MPC), so this test is slow
    /// (~1-2 minutes).
    #[test]
    fn test_blind_sig_e2e_1_round() {
        let seed = [0x42u8; SEED_LEN];
        let keypair = generate_keypair_from_seed(&seed);
        let mut rng = rand_core::OsRng;

        let message = b"hello blind world";

        // BS.Sig1: User commits to the message.
        let (user_state, committed) = user_commit(message, &mut rng);

        // BS.Sig2: Signer signs the commitment.
        let response = keypair.secret_key.sign_committed(&committed).unwrap();

        // BS.Sig3: User unblinds with 1 round for speed.
        let blind_sig = user_unblind_with_rounds(
            &user_state,
            &keypair.public_key,
            &response,
            1,
            &mut rng,
        )
        .unwrap();

        // BS.Vfy: Verify the blind signature.
        keypair
            .public_key
            .verify_with_rounds(message, &blind_sig)
            .unwrap();
    }

    /// Verifying with the wrong message must fail.
    #[test]
    fn test_blind_sig_wrong_message_fails() {
        let seed = [0x42u8; SEED_LEN];
        let keypair = generate_keypair_from_seed(&seed);
        let mut rng = rand_core::OsRng;

        let message = b"hello blind world";
        let (user_state, committed) = user_commit(message, &mut rng);
        let response = keypair.secret_key.sign_committed(&committed).unwrap();
        let blind_sig = user_unblind_with_rounds(
            &user_state,
            &keypair.public_key,
            &response,
            1,
            &mut rng,
        )
        .unwrap();

        // Verification with a different message must fail.
        let result = keypair
            .public_key
            .verify_with_rounds(b"wrong message", &blind_sig);
        assert!(result.is_err(), "verify must fail with wrong message");
    }

    /// The signer must return `KeyExhausted` when all leaves have been used.
    #[test]
    fn test_signer_key_exhaustion() {
        let seed = [0x42u8; SEED_LEN];
        let keypair = generate_keypair_from_seed(&seed);
        let mut rng = rand_core::OsRng;

        // Set the counter near the limit.
        use core::sync::atomic::Ordering;
        keypair
            .secret_key
            .next_leaf
            .store(1023, Ordering::SeqCst);

        let (_, committed) = user_commit(b"msg", &mut rng);

        // Leaf 1023 (the last one) should succeed.
        assert!(
            keypair.secret_key.sign_committed(&committed).is_ok(),
            "signing with the last leaf must succeed"
        );

        // Leaf 1024 (past the end) should fail.
        assert!(
            matches!(
                keypair.secret_key.sign_committed(&committed),
                Err(Error::KeyExhausted)
            ),
            "signing after all leaves are used must return KeyExhausted"
        );
    }

    /// Verifying against a different public key must fail.
    #[test]
    fn test_blind_sig_wrong_key_fails() {
        let seed1 = [0x42u8; SEED_LEN];
        let seed2 = [0x43u8; SEED_LEN];
        let keypair1 = generate_keypair_from_seed(&seed1);
        let keypair2 = generate_keypair_from_seed(&seed2);
        let mut rng = rand_core::OsRng;

        let message = b"hello blind world";
        let (user_state, committed) = user_commit(message, &mut rng);
        let response = keypair1.secret_key.sign_committed(&committed).unwrap();
        let blind_sig = user_unblind_with_rounds(
            &user_state,
            &keypair1.public_key,
            &response,
            1,
            &mut rng,
        )
        .unwrap();

        // Verification against a different public key must fail.
        let result = keypair2
            .public_key
            .verify_with_rounds(message, &blind_sig);
        assert!(
            result.is_err(),
            "verify must fail against a different public key"
        );
    }

    /// Multiple signatures from the same key use different leaves.
    #[test]
    fn test_signer_increments_leaf() {
        let seed = [0x42u8; SEED_LEN];
        let keypair = generate_keypair_from_seed(&seed);
        let mut rng = rand_core::OsRng;

        let (_, committed1) = user_commit(b"msg1", &mut rng);
        let (_, committed2) = user_commit(b"msg2", &mut rng);

        let resp1 = keypair.secret_key.sign_committed(&committed1).unwrap();
        let resp2 = keypair.secret_key.sign_committed(&committed2).unwrap();

        assert_eq!(resp1.leaf_index, 0, "first signature should use leaf 0");
        assert_eq!(resp2.leaf_index, 1, "second signature should use leaf 1");
    }
}
