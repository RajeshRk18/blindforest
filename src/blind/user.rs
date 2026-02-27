//! User-side protocol operations for the blind signature scheme.
//!
//! The user participates in two of the three protocol phases:
//!
//! 1. **BS.Sig1 (commit)** -- [`user_commit`] generates a commitment to the
//!    message and produces a [`UserState`] that must be retained for the
//!    unblinding step.
//!
//! 2. **BS.Sig3 (unblind/prove)** -- [`user_unblind`] consumes the signer's
//!    response and the saved user state to produce a [`BlindSignature`]
//!    containing a ZKBoo proof of knowledge of a valid WOTS signature and
//!    Merkle authentication path.

use crate::blind::types::{
    BlindSigPublicKey, BlindSignature, CommittedMessage, SignerResponse, UserState,
};
use crate::commitment::{self, CommitmentRandomness};
use crate::error::Result;
use crate::mpc::circuit::{CircuitInput, CircuitPublicInput};
use crate::wots::keygen::wots_pk_to_leaf;
use crate::wots::verify::wots_recover_pk;
use crate::merkle::auth::verify_auth_path;
use crate::zkboo::prover;

/// BS.Sig1: User commits to a message.
///
/// Generates fresh commitment randomness, computes `Com(m; r)`, and returns
/// both the [`UserState`] (to be retained for BS.Sig3) and the
/// [`CommittedMessage`] to send to the signer.
///
/// # Arguments
///
/// * `message` -- The message the user wants blindly signed.
/// * `rng` -- A cryptographically secure random number generator.
///
/// # Returns
///
/// A tuple of `(UserState, CommittedMessage)`. The committed message is sent
/// to the signer; the user state is kept secret until unblinding.
///
/// # Examples
///
/// ```no_run
/// use blindforest::blind::user::user_commit;
///
/// let mut rng = rand_core::OsRng;
/// let (state, committed) = user_commit(b"my secret message", &mut rng);
/// // Send `committed` to the signer, keep `state` for later.
/// ```
pub fn user_commit(
    message: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
) -> (UserState, CommittedMessage) {
    let randomness = CommitmentRandomness::random(rng);
    let com = commitment::commit(message, &randomness);

    let committed = CommittedMessage {
        commitment: com.clone(),
    };

    let state = UserState {
        message: message.to_vec(),
        randomness,
        commitment: com,
    };

    (state, committed)
}

/// BS.Sig3: User processes the signer's response to produce a blind signature.
///
/// The user:
/// 1. Verifies that the signer's WOTS signature on the commitment is valid
///    with respect to the claimed leaf in the signer's Merkle tree.
/// 2. Constructs the ZKBoo circuit witness (WOTS signature + auth path).
/// 3. Generates a ZKBoo proof demonstrating knowledge of the witness.
///
/// The resulting [`BlindSignature`] contains the commitment randomness
/// (so the verifier can recompute the commitment) and the zero-knowledge
/// proof, but does **not** reveal the WOTS signature or auth path.
///
/// # Arguments
///
/// * `state` -- The user state from [`user_commit`].
/// * `pk` -- The signer's public key (Merkle root).
/// * `response` -- The signer's response containing the WOTS signature,
///   authentication path, and leaf index.
/// * `rng` -- A cryptographically secure RNG for proof generation.
///
/// # Errors
///
/// * [`Error::VerificationFailed`] if the signer's WOTS signature or Merkle
///   auth path does not verify against the public key, or if the ZKBoo proof
///   generation fails.
///
/// [`Error::VerificationFailed`]: crate::error::Error::VerificationFailed
pub fn user_unblind(
    state: &UserState,
    pk: &BlindSigPublicKey,
    response: &SignerResponse,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<BlindSignature> {
    user_unblind_inner(state, pk, response, None, rng)
}

/// BS.Sig3 variant with a configurable number of ZKBoo rounds.
///
/// Identical to [`user_unblind`] but allows specifying a reduced round count,
/// which is useful for testing without the extreme cost of the full 219-round
/// proof.
///
/// # Arguments
///
/// * `state` -- The user state from [`user_commit`].
/// * `pk` -- The signer's public key.
/// * `response` -- The signer's response.
/// * `num_rounds` -- Number of ZKBoo rounds (use [`NUM_ROUNDS`] for full
///   security).
/// * `rng` -- A cryptographically secure RNG.
///
/// # Errors
///
/// Same as [`user_unblind`].
///
/// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
pub fn user_unblind_with_rounds(
    state: &UserState,
    pk: &BlindSigPublicKey,
    response: &SignerResponse,
    num_rounds: usize,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<BlindSignature> {
    user_unblind_inner(state, pk, response, Some(num_rounds), rng)
}

/// Shared implementation for both full and reduced-round unblinding.
fn user_unblind_inner(
    state: &UserState,
    pk: &BlindSigPublicKey,
    response: &SignerResponse,
    num_rounds: Option<usize>,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<BlindSignature> {
    // ---------------------------------------------------------------
    // Step 1: Verify the signer's WOTS signature on the commitment.
    // ---------------------------------------------------------------
    // The signer signed the commitment value (a [u8; HASH_LEN] hash).
    // We derive the expected WOTS public key from the signer's seed-derived
    // leaf, then verify the signature. This catches signer misbehavior early
    // with a clear error rather than letting it surface as a ZKBoo proof
    // failure.

    // Recover the WOTS public key from the signature and verify.
    // We need the WOTS pk to compute the leaf hash for auth path verification.
    let recovered_pk = wots_recover_pk(
        &state.commitment.value,
        &response.wots_sig,
    );

    // Compute the leaf hash from the recovered pk.
    let leaf_hash = wots_pk_to_leaf(&recovered_pk);

    // Verify the Merkle authentication path.
    if !verify_auth_path(
        &leaf_hash,
        response.leaf_index as usize,
        &response.auth_path,
        &pk.root,
    ) {
        return Err(crate::error::Error::VerificationFailed);
    }

    // ---------------------------------------------------------------
    // Step 2: Build the ZKBoo circuit input (secret witness).
    // ---------------------------------------------------------------
    let circuit_input = CircuitInput {
        wots_sig: response.wots_sig.elements.clone(),
        auth_path: response.auth_path.siblings.clone(),
    };

    // ---------------------------------------------------------------
    // Step 3: Build the circuit public input.
    // ---------------------------------------------------------------
    // The circuit's msg_hash is the commitment value -- the hash that the
    // WOTS signature was computed over.
    let public_input = CircuitPublicInput {
        msg_hash: state.commitment.value,
        expected_root: pk.root,
        leaf_index: response.leaf_index,
    };

    // ---------------------------------------------------------------
    // Step 4: Generate the ZKBoo proof.
    // ---------------------------------------------------------------
    let proof = match num_rounds {
        Some(rounds) => prover::prove_with_rounds(&circuit_input, &public_input, rounds, rng)?,
        None => prover::prove(&circuit_input, &public_input, rng)?,
    };

    // ---------------------------------------------------------------
    // Step 5: Assemble the blind signature.
    // ---------------------------------------------------------------
    Ok(BlindSignature {
        randomness: CommitmentRandomness(state.randomness.0),
        proof,
        leaf_index: response.leaf_index,
    })
}
