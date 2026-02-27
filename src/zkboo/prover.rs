//! ZKBoo NIZK prover.
//!
//! Generates a non-interactive zero-knowledge proof that the prover knows a
//! valid WOTS+ signature and Merkle authentication path that verify against a
//! public Merkle root, without revealing any secret witness data.
//!
//! The proof is produced by running [`NUM_ROUNDS`] independent MPC-in-the-head
//! evaluations of the blind-signature verification circuit, committing to all
//! parties' views, deriving Fiat-Shamir challenges, and opening two of the
//! three parties per round.
//!
//! [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::hash::{Domain, DomainHasher};
use crate::mpc::circuit::{
    evaluate_circuit, share_circuit_input, CircuitInput, CircuitPublicInput, SharedCircuitInput,
};
use crate::mpc::shares::reconstruct_u32;
use crate::mpc::tape::LazyTape;
use crate::mpc::view::View;
use crate::params::{
    HASH_LEN, NUM_PARTIES, NUM_ROUNDS, SEED_LEN, SHA256_STATE_WORDS, TREE_HEIGHT, WOTS_LEN,
};
use crate::zkboo::challenge::compute_challenges;
use crate::zkboo::types::{Proof, RoundCommitment, RoundProof};

// =========================================================================
// Commitment helper
// =========================================================================

/// Compute the commitment for one MPC party: `H(ViewCommit || seed || view_outputs)`.
///
/// This binds the party's seed (which determines its random tape) and the
/// recorded view outputs together. Both prover and verifier use the same
/// commitment scheme to ensure consistency.
///
/// # Arguments
///
/// * `seed` - The 32-byte seed that generates this party's random tape.
/// * `view` - The view containing all recorded gate outputs for this party.
///
/// # Returns
///
/// A 32-byte commitment hash.
pub(crate) fn commit_party(seed: &[u8; SEED_LEN], view: &View) -> [u8; HASH_LEN] {
    let mut hasher = DomainHasher::new(Domain::ViewCommit);
    hasher.update(seed);
    for &val in &view.outputs {
        hasher.update(&val.to_le_bytes());
    }
    hasher.finalize()
}

// =========================================================================
// Input-share extraction
// =========================================================================

/// Extract one party's input shares from a 3-party [`SharedCircuitInput`] as
/// a flat `Vec<u32>`.
///
/// The layout is: WOTS signature words (WOTS_LEN * SHA256_STATE_WORDS),
/// followed by auth-path words (TREE_HEIGHT * SHA256_STATE_WORDS).
///
/// # Arguments
///
/// * `shared` - The 3-party shared circuit input.
/// * `party` - The party index (0, 1, or 2) to extract.
///
/// # Returns
///
/// A flat vector of `u32` shares for the specified party.
fn extract_input_shares(shared: &SharedCircuitInput, party: usize) -> Vec<u32> {
    let total_words = (WOTS_LEN + TREE_HEIGHT) * SHA256_STATE_WORDS;
    let mut shares = Vec::with_capacity(total_words);
    for elem in &shared.wots_sig {
        for word in elem {
            shares.push(word[party]);
        }
    }
    for elem in &shared.auth_path {
        for word in elem {
            shares.push(word[party]);
        }
    }
    shares
}

// =========================================================================
// Public API
// =========================================================================

/// Generate a ZKBoo non-interactive zero-knowledge proof.
///
/// Proves knowledge of a valid WOTS+ signature and Merkle authentication path
/// (the secret witness) that satisfy the blind-signature verification circuit
/// with respect to the given public inputs.
///
/// The proof consists of [`NUM_ROUNDS`] independent MPC-in-the-head
/// evaluations. Each round:
///
/// 1. Generates 3 random seeds and creates per-party random tapes.
/// 2. Shares the secret witness among 3 parties using the tapes.
/// 3. Evaluates the verification circuit in 3-party MPC, producing views.
/// 4. Commits to each party's (seed, view) pair.
///
/// After all rounds, a Fiat-Shamir challenge selects which two parties to open
/// in each round, producing the final proof.
///
/// # Arguments
///
/// * `circuit_input` - The secret witness: WOTS signature elements and Merkle
///   auth-path siblings.
/// * `public_input` - Public inputs: message hash, expected Merkle root, and
///   leaf index.
/// * `rng` - A cryptographically secure random number generator for seed
///   generation.
///
/// # Returns
///
/// A [`Proof`] containing all round commitments and opened round proofs, or
/// an error if the witness does not satisfy the circuit (i.e., the
/// reconstructed root does not match `expected_root`).
///
/// # Errors
///
/// Returns [`Error::VerificationFailed`] if the circuit output does not match
/// the expected Merkle root, which indicates an invalid witness.
///
/// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
pub fn prove(
    circuit_input: &CircuitInput,
    public_input: &CircuitPublicInput,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Proof> {
    prove_with_rounds(circuit_input, public_input, NUM_ROUNDS, rng)
}

/// Generate a ZKBoo proof with a configurable number of rounds.
///
/// This is identical to [`prove`] but allows specifying a custom round count,
/// which is useful for testing with a reduced number of rounds to avoid the
/// extreme cost of the full 219-round proof.
///
/// # Arguments
///
/// * `circuit_input` - The secret witness.
/// * `public_input` - Public inputs.
/// * `num_rounds` - Number of ZKBoo rounds to execute (use [`NUM_ROUNDS`] for
///   full security).
/// * `rng` - A cryptographically secure RNG.
///
/// # Returns
///
/// A [`Proof`] with `num_rounds` round commitments and round proofs.
///
/// # Errors
///
/// Returns [`Error::VerificationFailed`] if the circuit output does not match
/// the expected Merkle root in any round.
///
/// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
pub fn prove_with_rounds(
    circuit_input: &CircuitInput,
    public_input: &CircuitPublicInput,
    num_rounds: usize,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Proof> {
    // Per-round state collected during the commit phase.
    let mut all_seeds: Vec<[[u8; SEED_LEN]; NUM_PARTIES]> = Vec::with_capacity(num_rounds);
    let mut all_shared_inputs: Vec<SharedCircuitInput> = Vec::with_capacity(num_rounds);
    let mut all_views: Vec<[View; 3]> = Vec::with_capacity(num_rounds);
    let mut all_commitments: Vec<RoundCommitment> = Vec::with_capacity(num_rounds);
    let mut all_outputs: Vec<[[u32; 3]; SHA256_STATE_WORDS]> = Vec::with_capacity(num_rounds);

    // Phase 1: Commit -- run the MPC circuit for each round.
    for r in 0..num_rounds {
        // (a) Generate 3 random seeds for this round.
        let mut seeds = [[0u8; SEED_LEN]; NUM_PARTIES];
        for seed in &mut seeds {
            rng.fill_bytes(seed);
        }

        // (b) Create tapes from seeds. A single tape per party is used for
        //     both input sharing and circuit evaluation (the tape state
        //     carries over).
        let mut tapes = [
            LazyTape::new(&seeds[0], r as u32, 0),
            LazyTape::new(&seeds[1], r as u32, 1),
            LazyTape::new(&seeds[2], r as u32, 2),
        ];

        // (c) Share the circuit input among 3 parties.
        let shared_input = share_circuit_input(circuit_input, &mut tapes);

        // (d) Create 3 fresh views and evaluate the circuit.
        let mut views = [View::new(), View::new(), View::new()];
        let output = evaluate_circuit(&shared_input, public_input, &mut tapes, &mut views);

        // (e) Verify that the reconstructed output matches the expected root.
        //     If the witness is invalid, the roots will not match.
        let mut reconstructed_root = [0u8; HASH_LEN];
        for i in 0..SHA256_STATE_WORDS {
            let word = reconstruct_u32(&output[i]);
            reconstructed_root[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        if reconstructed_root != public_input.expected_root {
            return Err(Error::VerificationFailed);
        }

        // (f) Commit to each party's (seed, view).
        let mut commitments = [[0u8; HASH_LEN]; NUM_PARTIES];
        for j in 0..NUM_PARTIES {
            commitments[j] = commit_party(&seeds[j], &views[j]);
        }

        all_seeds.push(seeds);
        all_shared_inputs.push(shared_input);
        all_views.push(views);
        all_commitments.push(RoundCommitment { commitments });
        all_outputs.push(output);
    }

    // Phase 2: Fiat-Shamir challenge derivation.
    let challenges = compute_challenges(
        &public_input.msg_hash,
        &public_input.expected_root,
        &all_commitments,
    );

    // Phase 3: Open -- for each round, reveal the challenged pair.
    let mut round_proofs = Vec::with_capacity(num_rounds);

    for r in 0..num_rounds {
        let e = challenges[r] as usize;
        let next = (e + 1) % NUM_PARTIES;
        let third = (e + 2) % NUM_PARTIES;

        // Extract the output share for the unopened third party.
        let mut output_share_third = [0u32; SHA256_STATE_WORDS];
        for i in 0..SHA256_STATE_WORDS {
            output_share_third[i] = all_outputs[r][i][third];
        }

        round_proofs.push(RoundProof {
            e: e as u8,
            seed_e: all_seeds[r][e],
            seed_next: all_seeds[r][next],
            view_e: all_views[r][e].clone(),
            input_share_e: extract_input_shares(&all_shared_inputs[r], e),
            input_share_next: extract_input_shares(&all_shared_inputs[r], next),
            output_share_third,
        });
    }

    Ok(Proof {
        commitments: all_commitments,
        round_proofs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_party_deterministic() {
        let seed = [0xAAu8; SEED_LEN];
        let mut view = View::new();
        view.record(42);
        view.record(0xDEADBEEF);

        let c1 = commit_party(&seed, &view);
        let c2 = commit_party(&seed, &view);
        assert_eq!(c1, c2, "Same seed and view must produce identical commitments");
    }

    #[test]
    fn test_commit_party_differs_on_seed() {
        let seed1 = [0xAAu8; SEED_LEN];
        let seed2 = [0xBBu8; SEED_LEN];
        let mut view = View::new();
        view.record(42);

        let c1 = commit_party(&seed1, &view);
        let c2 = commit_party(&seed2, &view);
        assert_ne!(c1, c2, "Different seeds must produce different commitments");
    }

    #[test]
    fn test_commit_party_differs_on_view() {
        let seed = [0xAAu8; SEED_LEN];
        let mut view1 = View::new();
        view1.record(42);
        let mut view2 = View::new();
        view2.record(43);

        let c1 = commit_party(&seed, &view1);
        let c2 = commit_party(&seed, &view2);
        assert_ne!(c1, c2, "Different views must produce different commitments");
    }

    #[test]
    fn test_extract_input_shares_length() {
        // Build a minimal SharedCircuitInput with known dimensions.
        let wots_sig = vec![[[0u32; 3]; SHA256_STATE_WORDS]; WOTS_LEN];
        let auth_path = vec![[[0u32; 3]; SHA256_STATE_WORDS]; TREE_HEIGHT];
        let shared = SharedCircuitInput { wots_sig, auth_path };

        let expected_len = (WOTS_LEN + TREE_HEIGHT) * SHA256_STATE_WORDS;
        for party in 0..NUM_PARTIES {
            let shares = extract_input_shares(&shared, party);
            assert_eq!(
                shares.len(),
                expected_len,
                "Party {} input share length mismatch",
                party
            );
        }
    }

    #[test]
    fn test_extract_input_shares_reconstruction() {
        // Verify that XOR-ing all 3 parties' shares reconstructs the original.
        let mut wots_sig = Vec::with_capacity(WOTS_LEN);
        for i in 0..WOTS_LEN {
            let mut elem = [[0u32; 3]; SHA256_STATE_WORDS];
            for j in 0..SHA256_STATE_WORDS {
                // share_u32(value, r0, r1) = [r0, r1, value ^ r0 ^ r1]
                let value = (i * SHA256_STATE_WORDS + j) as u32;
                elem[j] = crate::mpc::shares::share_u32(value, 0x11111111, 0x22222222);
            }
            wots_sig.push(elem);
        }

        let mut auth_path = Vec::with_capacity(TREE_HEIGHT);
        for i in 0..TREE_HEIGHT {
            let mut elem = [[0u32; 3]; SHA256_STATE_WORDS];
            for j in 0..SHA256_STATE_WORDS {
                let value = (0x10000 + i * SHA256_STATE_WORDS + j) as u32;
                elem[j] = crate::mpc::shares::share_u32(value, 0x33333333, 0x44444444);
            }
            auth_path.push(elem);
        }

        let shared = SharedCircuitInput { wots_sig, auth_path };

        let s0 = extract_input_shares(&shared, 0);
        let s1 = extract_input_shares(&shared, 1);
        let s2 = extract_input_shares(&shared, 2);

        for i in 0..s0.len() {
            let reconstructed = s0[i] ^ s1[i] ^ s2[i];
            // Verify against the original value we used.
            let expected = if i < WOTS_LEN * SHA256_STATE_WORDS {
                i as u32
            } else {
                (0x10000 + (i - WOTS_LEN * SHA256_STATE_WORDS)) as u32
            };
            assert_eq!(
                reconstructed, expected,
                "Reconstruction mismatch at index {}",
                i
            );
        }
    }
}
