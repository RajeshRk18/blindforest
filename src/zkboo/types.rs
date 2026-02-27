use alloc::vec::Vec;
use crate::mpc::view::View;
use crate::params::{HASH_LEN, NUM_PARTIES, SEED_LEN, SHA256_STATE_WORDS};

/// Commitment for one round of ZKBoo.
///
/// Contains commitments to each party's seed and view. In the ZKBoo protocol,
/// the prover commits to each of the three MPC parties' states before the
/// Fiat-Shamir challenge selects which two parties to open.
///
/// Each commitment is computed as `H(ViewCommit || seed_i || view_i_data)`
/// for `i` in `0..NUM_PARTIES`.
#[derive(Debug, Clone)]
pub struct RoundCommitment {
    /// Commitment to party `i`'s `(seed, view)`: `H(ViewCommit || seed_i || view_i_data)`
    /// for `i` in `0..3`.
    pub commitments: [[u8; HASH_LEN]; NUM_PARTIES],
}

impl RoundCommitment {
    /// Serialized size in bytes: 3 commitments of HASH_LEN each.
    pub fn serialized_size(&self) -> usize {
        NUM_PARTIES * HASH_LEN
    }
}

/// Proof data for a single ZKBoo round after the challenge selects party `e`.
///
/// In the ZKBoo protocol, after the verifier (or Fiat-Shamir oracle) chooses a
/// challenge `e` in `{0, 1, 2}`, the prover opens parties `e` and `(e+1) % 3`,
/// providing their seeds, views, and input shares. The verifier can then replay
/// the MPC computation for these two parties and check consistency.
#[derive(Debug, Clone)]
pub struct RoundProof {
    /// The challenge value for this round (0, 1, or 2).
    pub e: u8,
    /// Seed for party `e`.
    pub seed_e: [u8; SEED_LEN],
    /// Seed for party `(e+1) % 3`.
    pub seed_next: [u8; SEED_LEN],
    /// View (gate outputs) for party `e` -- needed for verification replay.
    pub view_e: View,
    /// Input shares for party `e` (the witness shares assigned to party `e`).
    ///
    /// These are the shared circuit input words for party `e`.
    pub input_share_e: Vec<u32>,
    /// Input shares for party `(e+1) % 3`.
    pub input_share_next: Vec<u32>,
    /// Output share for the third (unopened) party `(e+2) % 3`.
    ///
    /// The verifier needs this to reconstruct the full circuit output (Merkle
    /// root) from all three parties' shares and compare against the expected
    /// public root.
    pub output_share_third: [u32; SHA256_STATE_WORDS],
}

impl RoundProof {
    /// Serialized size in bytes.
    pub fn serialized_size(&self) -> usize {
        1 // e
        + SEED_LEN // seed_e
        + SEED_LEN // seed_next
        + self.view_e.serialized_size() // view_e
        + self.input_share_e.len() * 4 // input_share_e
        + self.input_share_next.len() * 4 // input_share_next
        + SHA256_STATE_WORDS * 4 // output_share_third
    }
}

/// A complete ZKBoo proof consisting of [`NUM_ROUNDS`] round proofs
/// plus the round commitments.
///
/// The proof binds a statement (public input) to a witness via an MPC-in-the-head
/// approach. It contains `NUM_ROUNDS` independent repetitions to achieve
/// the desired soundness level (each round has soundness error 2/3).
///
/// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
#[derive(Debug, Clone)]
pub struct Proof {
    /// Per-round commitments (all 3 parties' commitments for each round).
    pub commitments: Vec<RoundCommitment>,
    /// Per-round proofs (opened party data after challenge).
    pub round_proofs: Vec<RoundProof>,
}

impl Proof {
    /// Number of rounds in this proof.
    #[must_use]
    pub fn num_rounds(&self) -> usize {
        self.round_proofs.len()
    }

    /// Serialized size in bytes.
    pub fn serialized_size(&self) -> usize {
        let commitments_size: usize = self.commitments.iter().map(|c| c.serialized_size()).sum();
        let proofs_size: usize = self.round_proofs.iter().map(|p| p.serialized_size()).sum();
        commitments_size + proofs_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_commitment_default_zeros() {
        let rc = RoundCommitment {
            commitments: [[0u8; HASH_LEN]; NUM_PARTIES],
        };
        for c in &rc.commitments {
            assert_eq!(c, &[0u8; HASH_LEN]);
        }
    }

    #[test]
    fn test_proof_num_rounds() {
        let proof = Proof {
            commitments: Vec::new(),
            round_proofs: Vec::new(),
        };
        assert_eq!(proof.num_rounds(), 0);

        let proof = Proof {
            commitments: alloc::vec![
                RoundCommitment { commitments: [[0u8; HASH_LEN]; NUM_PARTIES] };
                5
            ],
            round_proofs: alloc::vec![
                RoundProof {
                    e: 0,
                    seed_e: [0u8; SEED_LEN],
                    seed_next: [0u8; SEED_LEN],
                    view_e: View::new(),
                    input_share_e: Vec::new(),
                    input_share_next: Vec::new(),
                    output_share_third: [0u32; SHA256_STATE_WORDS],
                };
                5
            ],
        };
        assert_eq!(proof.num_rounds(), 5);
    }

    #[test]
    fn test_round_proof_clone() {
        let mut view = View::new();
        view.record(42);
        view.record(0xDEADBEEF);

        let rp = RoundProof {
            e: 1,
            seed_e: [0xAA; SEED_LEN],
            seed_next: [0xBB; SEED_LEN],
            view_e: view,
            input_share_e: alloc::vec![1, 2, 3],
            input_share_next: alloc::vec![4, 5, 6],
            output_share_third: [0u32; SHA256_STATE_WORDS],
        };
        let rp2 = rp.clone();
        assert_eq!(rp2.e, 1);
        assert_eq!(rp2.seed_e, [0xAA; SEED_LEN]);
        assert_eq!(rp2.seed_next, [0xBB; SEED_LEN]);
        assert_eq!(rp2.view_e.len(), 2);
        assert_eq!(rp2.input_share_e, alloc::vec![1, 2, 3]);
        assert_eq!(rp2.input_share_next, alloc::vec![4, 5, 6]);
    }
}
