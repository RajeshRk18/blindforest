//! ZKBoo NIZK verifier.
//!
//! Verifies a non-interactive zero-knowledge proof that the prover knows a
//! valid WOTS+ signature and Merkle authentication path without learning any
//! information about the secret witness.
//!
//! For each round the verifier:
//!
//! 1. Checks that the commitment for party `e` matches the prover's claimed
//!    seed and view.
//! 2. Reconstructs the random tapes for parties `e` and `(e+1) % 3` from
//!    their seeds.
//! 3. Re-evaluates the circuit in 2-party mode, reading party `e`'s view and
//!    recomputing party `(e+1) % 3`'s view.
//! 4. Checks that the recomputed view for party `(e+1) % 3` commits to the
//!    same hash as in the proof.
//! 5. Reconstructs the full circuit output using all three parties' output
//!    shares and checks it against the expected Merkle root.
//!
//! Finally, the Fiat-Shamir challenges are re-derived and checked for
//! consistency.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::mpc::circuit::{
    evaluate_circuit_verify, CircuitPublicInput, SharedCircuitInputPair,
};
use crate::mpc::tape::LazyTape;
use crate::mpc::view::View;
use crate::params::{
    HASH_LEN, NUM_PARTIES, NUM_ROUNDS, SHA256_STATE_WORDS, TREE_HEIGHT, WOTS_LEN,
};
use crate::zkboo::challenge::compute_challenges;
use crate::zkboo::prover::commit_party;
use crate::zkboo::types::Proof;

// =========================================================================
// Input-share reconstruction
// =========================================================================

/// Rebuild a [`SharedCircuitInputPair`] from two flat vectors of `u32` shares.
///
/// The flat layout is: WOTS signature words (`WOTS_LEN * SHA256_STATE_WORDS`),
/// followed by auth-path words (`TREE_HEIGHT * SHA256_STATE_WORDS`).
///
/// # Arguments
///
/// * `share_e` - Flat shares for party `e`.
/// * `share_next` - Flat shares for party `(e+1) % 3`.
///
/// # Returns
///
/// The structured 2-party shared circuit input.
fn rebuild_shared_input_pair(
    share_e: &[u32],
    share_next: &[u32],
) -> SharedCircuitInputPair {
    let wots_words = WOTS_LEN * SHA256_STATE_WORDS;

    let mut wots_sig = Vec::with_capacity(WOTS_LEN);
    for i in 0..WOTS_LEN {
        let mut elem = [[0u32; 2]; SHA256_STATE_WORDS];
        for j in 0..SHA256_STATE_WORDS {
            let idx = i * SHA256_STATE_WORDS + j;
            elem[j] = [share_e[idx], share_next[idx]];
        }
        wots_sig.push(elem);
    }

    let mut auth_path = Vec::with_capacity(TREE_HEIGHT);
    for i in 0..TREE_HEIGHT {
        let mut elem = [[0u32; 2]; SHA256_STATE_WORDS];
        for j in 0..SHA256_STATE_WORDS {
            let idx = wots_words + i * SHA256_STATE_WORDS + j;
            elem[j] = [share_e[idx], share_next[idx]];
        }
        auth_path.push(elem);
    }

    SharedCircuitInputPair { wots_sig, auth_path }
}

// =========================================================================
// Public API
// =========================================================================

/// Verify a ZKBoo non-interactive zero-knowledge proof.
///
/// Checks that the proof demonstrates valid knowledge of a WOTS+ signature
/// and Merkle authentication path that verify against the public inputs,
/// without revealing the secret witness.
///
/// # Arguments
///
/// * `proof` - The proof to verify, containing round commitments and opened
///   round proofs.
/// * `public_input` - The public inputs: message hash, expected Merkle root,
///   and leaf index.
///
/// # Returns
///
/// `Ok(())` if the proof is valid.
///
/// # Errors
///
/// * [`Error::ProofFormat`] if the proof has the wrong number of rounds or
///   inconsistent structure.
/// * [`Error::VerificationFailed`] if any verification check fails:
///   commitment mismatch, output reconstruction mismatch, or Fiat-Shamir
///   challenge mismatch.
pub fn verify(
    proof: &Proof,
    public_input: &CircuitPublicInput,
) -> Result<()> {
    verify_impl(proof, public_input, NUM_ROUNDS)
}

/// Verify a ZKBoo proof, auto-detecting the number of rounds from the proof.
///
/// This is useful for verifying proofs generated with a reduced round count
/// (e.g., during testing). The round count is inferred from the proof
/// structure rather than requiring [`NUM_ROUNDS`].
///
/// # Arguments
///
/// * `proof` - The proof to verify.
/// * `public_input` - The public inputs.
///
/// # Returns
///
/// `Ok(())` if the proof is valid.
///
/// # Errors
///
/// Same as [`verify`].
///
/// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
pub fn verify_with_rounds(
    proof: &Proof,
    public_input: &CircuitPublicInput,
) -> Result<()> {
    let num_rounds = proof.num_rounds();
    if num_rounds == 0 {
        return Err(Error::ProofFormat);
    }
    verify_impl(proof, public_input, num_rounds)
}

/// Internal verification implementation parameterized by round count.
fn verify_impl(
    proof: &Proof,
    public_input: &CircuitPublicInput,
    num_rounds: usize,
) -> Result<()> {
    // ------------------------------------------------------------------
    // Step 1: Structural checks
    // ------------------------------------------------------------------
    if proof.num_rounds() != num_rounds {
        return Err(Error::ProofFormat);
    }
    if proof.commitments.len() != num_rounds {
        return Err(Error::ProofFormat);
    }

    // ------------------------------------------------------------------
    // Step 2: Re-derive Fiat-Shamir challenges
    // ------------------------------------------------------------------
    let challenges = compute_challenges(
        &public_input.msg_hash,
        &public_input.expected_root,
        &proof.commitments,
    );

    // ------------------------------------------------------------------
    // Step 3: Verify each round
    // ------------------------------------------------------------------
    // Number of u32 words consumed from tapes[0] and tapes[1] during input
    // sharing. tapes[2] is not read by share_circuit_input.
    let sharing_words = (WOTS_LEN + TREE_HEIGHT) * SHA256_STATE_WORDS;

    for r in 0..num_rounds {
        let round_proof = &proof.round_proofs[r];
        let e = round_proof.e as usize;

        // (a) Challenge consistency: the round's challenge must match.
        if round_proof.e != challenges[r] {
            return Err(Error::VerificationFailed);
        }
        if e >= NUM_PARTIES {
            return Err(Error::ProofFormat);
        }

        let next = (e + 1) % NUM_PARTIES;

        // (b) Verify commitment for party e: recompute and compare.
        let expected_commit_e = commit_party(&round_proof.seed_e, &round_proof.view_e);
        if expected_commit_e != proof.commitments[r].commitments[e] {
            return Err(Error::VerificationFailed);
        }

        // (c) Recreate tapes for parties e and (e+1)%3 from their seeds.
        let mut tape_e = LazyTape::new(&round_proof.seed_e, r as u32, e as u8);
        let mut tape_next = LazyTape::new(&round_proof.seed_next, r as u32, next as u8);

        // (d) Advance tapes past the input-sharing phase.
        //
        //     During input sharing, share_circuit_input calls share_hash for
        //     each element, which reads one u32 from tapes[0] and one from
        //     tapes[1] per word (tapes[2] is never read). So:
        //
        //     - Party 0's tape: consumed `sharing_words` u32 values
        //     - Party 1's tape: consumed `sharing_words` u32 values
        //     - Party 2's tape: consumed 0 u32 values
        //
        //     We advance each tape by the correct amount based on which party
        //     index it corresponds to in the original 3-party array.
        let tape_e_advance = if e < 2 { sharing_words } else { 0 };
        let tape_next_advance = if next < 2 { sharing_words } else { 0 };

        for _ in 0..tape_e_advance {
            tape_e.next_u32();
        }
        for _ in 0..tape_next_advance {
            tape_next.next_u32();
        }

        // (e) Rebuild the 2-party shared input from the flat share vectors.
        let shared_input = rebuild_shared_input_pair(
            &round_proof.input_share_e,
            &round_proof.input_share_next,
        );

        // (f) Set up views for circuit replay.
        //     - view_e: clone from the prover's view, reset read position
        //       so the verifier reads gate outputs from the beginning.
        //     - view_next: fresh empty view that will be filled during replay.
        let mut view_e = round_proof.view_e.clone();
        view_e.reset_read();
        let mut view_next = View::new();

        // (g) Evaluate circuit in 2-party verification mode.
        let output = evaluate_circuit_verify(
            &shared_input,
            public_input,
            e,
            &mut tape_e,
            &mut tape_next,
            &mut view_e,
            &mut view_next,
        );

        // (h) Verify commitment for party (e+1)%3: the recomputed view must
        //     commit to the same value the prover committed to.
        let expected_commit_next = commit_party(&round_proof.seed_next, &view_next);
        if expected_commit_next != proof.commitments[r].commitments[next] {
            return Err(Error::VerificationFailed);
        }

        // (i) Verify output: reconstruct the full root from all 3 parties'
        //     output shares and compare against the expected root.
        //
        //     output[i][0] = party e's share
        //     output[i][1] = party (e+1)%3's share
        //     output_share_third[i] = party (e+2)%3's share
        let mut reconstructed_root = [0u8; HASH_LEN];
        for i in 0..SHA256_STATE_WORDS {
            let word = output[i][0] ^ output[i][1] ^ round_proof.output_share_third[i];
            reconstructed_root[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        if reconstructed_root != public_input.expected_root {
            return Err(Error::VerificationFailed);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use crate::merkle::tree::build_tree;
    use crate::mpc::circuit::{CircuitInput, CircuitPublicInput};
    use crate::params::{NUM_LEAVES, SEED_LEN};
    use crate::wots::keygen::{wots_keygen, wots_pk_to_leaf};
    use crate::wots::sign::wots_sign;
    use crate::zkboo::prover::prove_with_rounds;

    /// Build a complete test fixture: WOTS keypair, signature, Merkle tree,
    /// auth path, and all inputs needed for the circuit.
    struct TestFixture {
        circuit_input: CircuitInput,
        public_input: CircuitPublicInput,
    }

    fn make_fixture(leaf_index: u32) -> TestFixture {
        let key_seed = [0x42u8; SEED_LEN];
        let msg = b"test message for zkboo prover/verifier roundtrip";
        let msg_hash = hash::hash_raw(msg);

        // Generate WOTS keypairs for all leaves to build the Merkle tree.
        let mut leaves = Vec::with_capacity(NUM_LEAVES);
        for i in 0..NUM_LEAVES {
            let (_, pk) = wots_keygen(&key_seed, i as u32);
            leaves.push(wots_pk_to_leaf(&pk));
        }
        let tree = build_tree(&leaves);
        let root = tree.root();

        // Sign with the chosen leaf.
        let (sk, _pk) = wots_keygen(&key_seed, leaf_index);
        let sig = wots_sign(&sk, &msg_hash);
        let auth_path = tree.auth_path(leaf_index as usize);

        TestFixture {
            circuit_input: CircuitInput {
                wots_sig: sig.elements,
                auth_path: auth_path.siblings,
            },
            public_input: CircuitPublicInput {
                msg_hash,
                expected_root: root,
                leaf_index,
            },
        }
    }

    /// Prove-then-verify round-trip with a small number of rounds.
    ///
    /// Even 1 round exercises the full MPC circuit (approximately 267
    /// SHA-256 evaluations), so this test takes several seconds.
    #[test]
    fn test_zkboo_prove_verify_roundtrip() {
        let fixture = make_fixture(0);
        let mut rng = rand::thread_rng();

        let proof = prove_with_rounds(
            &fixture.circuit_input,
            &fixture.public_input,
            1,
            &mut rng,
        )
        .expect("prove should succeed with a valid witness");

        assert_eq!(proof.num_rounds(), 1);
        assert_eq!(proof.commitments.len(), 1);

        let result = verify_with_rounds(&proof, &fixture.public_input);
        assert!(result.is_ok(), "verify should succeed: {:?}", result.err());
    }

    /// Verify that a proof fails when checked against the wrong expected root.
    #[test]
    fn test_zkboo_verify_wrong_root_fails() {
        let fixture = make_fixture(0);
        let mut rng = rand::thread_rng();

        let proof = prove_with_rounds(
            &fixture.circuit_input,
            &fixture.public_input,
            1,
            &mut rng,
        )
        .expect("prove should succeed");

        // Construct a public input with a different expected root.
        let wrong_public_input = CircuitPublicInput {
            msg_hash: fixture.public_input.msg_hash,
            expected_root: [0xFFu8; HASH_LEN],
            leaf_index: fixture.public_input.leaf_index,
        };

        let result = verify_with_rounds(&proof, &wrong_public_input);
        assert!(
            result.is_err(),
            "verify must fail when the expected root is wrong"
        );
    }

    /// Verify that tampering with a commitment causes verification failure.
    #[test]
    fn test_zkboo_verify_tampered_commitment_fails() {
        let fixture = make_fixture(0);
        let mut rng = rand::thread_rng();

        let mut proof = prove_with_rounds(
            &fixture.circuit_input,
            &fixture.public_input,
            1,
            &mut rng,
        )
        .expect("prove should succeed");

        // Tamper with the opened party e's commitment so the verifier is
        // guaranteed to detect it (party e's commitment is always checked).
        let e = proof.round_proofs[0].e as usize;
        proof.commitments[0].commitments[e][0] ^= 0xFF;

        let result = verify_with_rounds(&proof, &fixture.public_input);
        assert!(
            result.is_err(),
            "verify must fail when a commitment is tampered with"
        );
    }

    /// Verify with 2 rounds to exercise multi-round challenge derivation.
    #[test]
    #[ignore] // Slow: ~2 circuit evaluations
    fn test_zkboo_prove_verify_two_rounds() {
        let fixture = make_fixture(7);
        let mut rng = rand::thread_rng();

        let proof = prove_with_rounds(
            &fixture.circuit_input,
            &fixture.public_input,
            2,
            &mut rng,
        )
        .expect("prove should succeed");

        assert_eq!(proof.num_rounds(), 2);

        let result = verify_with_rounds(&proof, &fixture.public_input);
        assert!(result.is_ok(), "verify should succeed: {:?}", result.err());
    }

    /// Verify that tampering with the output_share_third causes failure.
    #[test]
    fn test_zkboo_verify_tampered_output_share_fails() {
        let fixture = make_fixture(0);
        let mut rng = rand::thread_rng();

        let mut proof = prove_with_rounds(
            &fixture.circuit_input,
            &fixture.public_input,
            1,
            &mut rng,
        )
        .expect("prove should succeed");

        // Tamper with the third party's output share.
        proof.round_proofs[0].output_share_third[0] ^= 1;

        let result = verify_with_rounds(&proof, &fixture.public_input);
        assert!(
            result.is_err(),
            "verify must fail when output_share_third is tampered with"
        );
    }

    /// Verify that tampering with an input share causes failure.
    #[test]
    fn test_zkboo_verify_tampered_input_share_fails() {
        let fixture = make_fixture(0);
        let mut rng = rand::thread_rng();

        let mut proof = prove_with_rounds(
            &fixture.circuit_input,
            &fixture.public_input,
            1,
            &mut rng,
        )
        .expect("prove should succeed");

        // Tamper with the first word of party e's input share.
        if !proof.round_proofs[0].input_share_e.is_empty() {
            proof.round_proofs[0].input_share_e[0] ^= 1;
        }

        let result = verify_with_rounds(&proof, &fixture.public_input);
        assert!(
            result.is_err(),
            "verify must fail when an input share is tampered with"
        );
    }

    #[test]
    fn test_rebuild_shared_input_pair_dimensions() {
        let share_len = (WOTS_LEN + TREE_HEIGHT) * SHA256_STATE_WORDS;
        let share_e = alloc::vec![0u32; share_len];
        let share_next = alloc::vec![0u32; share_len];

        let pair = rebuild_shared_input_pair(&share_e, &share_next);
        assert_eq!(pair.wots_sig.len(), WOTS_LEN);
        assert_eq!(pair.auth_path.len(), TREE_HEIGHT);
    }

    #[test]
    fn test_rebuild_shared_input_pair_values() {
        let share_len = (WOTS_LEN + TREE_HEIGHT) * SHA256_STATE_WORDS;
        let mut share_e = alloc::vec![0u32; share_len];
        let mut share_next = alloc::vec![0u32; share_len];

        // Fill with known values.
        for i in 0..share_len {
            share_e[i] = i as u32;
            share_next[i] = (i as u32).wrapping_add(0x10000);
        }

        let pair = rebuild_shared_input_pair(&share_e, &share_next);

        // Check first WOTS element.
        for j in 0..SHA256_STATE_WORDS {
            assert_eq!(pair.wots_sig[0][j][0], j as u32);
            assert_eq!(pair.wots_sig[0][j][1], (j as u32).wrapping_add(0x10000));
        }

        // Check first auth-path element.
        let wots_words = WOTS_LEN * SHA256_STATE_WORDS;
        for j in 0..SHA256_STATE_WORDS {
            assert_eq!(pair.auth_path[0][j][0], (wots_words + j) as u32);
            assert_eq!(
                pair.auth_path[0][j][1],
                ((wots_words + j) as u32).wrapping_add(0x10000)
            );
        }
    }
}
