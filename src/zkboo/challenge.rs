use alloc::vec::Vec;
use crate::hash::{Domain, DomainHasher};
use crate::params::{AES_NONCE_LEN, HASH_LEN, NUM_ROUNDS, SEED_LEN};
use crate::prf::Prf;
use crate::zkboo::types::RoundCommitment;

/// Derive the Fiat-Shamir challenges from the transcript.
///
/// The challenge is computed in two phases:
///
/// 1. **Transcript hash**: Compute a master seed via
///    `H_FS = SHA-256(FiatShamir || msg_hash || pk || commitment_0 || ... || commitment_{t-1})`,
///    where each `commitment_i` is the concatenation of the 3 party commitments.
///
/// 2. **Challenge expansion**: Use the 32-byte master seed to generate a PRF stream
///    (AES-256-CTR with a zero nonce). Extract individual bytes and apply rejection
///    sampling: accept `byte % 3` when `byte < 252` (the largest multiple of 3 that
///    fits in a `u8`), otherwise skip and take the next byte. This avoids modular bias
///    in the `{0, 1, 2}` distribution.
///
/// # Arguments
///
/// * `msg_hash`   - The 32-byte hash of the message being signed.
/// * `public_key` - The 32-byte Merkle root (public key).
/// * `commitments`- Slice of round commitments (one per ZKBoo round).
///
/// # Returns
///
/// A `Vec<u8>` of length [`NUM_ROUNDS`] where each element is in `{0, 1, 2}`.
///
/// # Panics
///
/// This function does not panic under normal operation.
///
/// [`NUM_ROUNDS`]: crate::params::NUM_ROUNDS
pub fn compute_challenges(
    msg_hash: &[u8; HASH_LEN],
    public_key: &[u8; HASH_LEN],
    commitments: &[RoundCommitment],
) -> Vec<u8> {
    // Phase 1: Hash the full transcript to produce a master seed.
    let master_seed = {
        let mut hasher = DomainHasher::new(Domain::FiatShamir);
        hasher.update(msg_hash);
        hasher.update(public_key);
        for rc in commitments {
            for commitment in &rc.commitments {
                hasher.update(commitment);
            }
        }
        hasher.finalize()
    };

    // Phase 2: Expand the master seed into NUM_ROUNDS challenge values using
    // AES-256-CTR as a PRF with a zero nonce.
    let nonce = [0u8; AES_NONCE_LEN];
    let mut prf = Prf::new(
        <&[u8; SEED_LEN]>::try_from(master_seed.as_slice()).unwrap(),
        &nonce,
    );

    let mut challenges = Vec::with_capacity(NUM_ROUNDS);

    while challenges.len() < NUM_ROUNDS {
        // Draw a batch of PRF bytes. We need at least NUM_ROUNDS bytes, but
        // rejection sampling may discard some, so over-allocate slightly.
        // On average ~1.6% of bytes are rejected (4/256), so we need roughly
        // NUM_ROUNDS * 256/252 bytes. We draw in chunks to keep it simple.
        let mut byte_buf = [0u8; 1];
        prf.fill(&mut byte_buf);
        let b = byte_buf[0];

        // Rejection sampling: 252 is the largest multiple of 3 <= 255.
        // Values 252..=255 would introduce bias, so we reject them.
        if b < 252 {
            challenges.push(b % 3);
        }
    }

    challenges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::NUM_PARTIES;

    /// Helper: build a deterministic `RoundCommitment` from a seed byte.
    fn make_commitments(seed: u8, count: usize) -> Vec<RoundCommitment> {
        (0..count)
            .map(|i| {
                let mut commitments = [[0u8; HASH_LEN]; NUM_PARTIES];
                for (party, commitment) in commitments.iter_mut().enumerate() {
                    // Fill with a pattern derived from seed, round index, and party index
                    for (j, byte) in commitment.iter_mut().enumerate() {
                        *byte = seed
                            .wrapping_add(i as u8)
                            .wrapping_add(party as u8)
                            .wrapping_add(j as u8);
                    }
                }
                RoundCommitment { commitments }
            })
            .collect()
    }

    #[test]
    fn test_challenge_deterministic() {
        let msg_hash = [0x11u8; HASH_LEN];
        let pk = [0x22u8; HASH_LEN];
        let commitments = make_commitments(0xAA, NUM_ROUNDS);

        let c1 = compute_challenges(&msg_hash, &pk, &commitments);
        let c2 = compute_challenges(&msg_hash, &pk, &commitments);

        assert_eq!(c1.len(), NUM_ROUNDS);
        assert_eq!(c1, c2, "Same inputs must produce identical challenges");
    }

    #[test]
    fn test_challenge_differs_on_commitment() {
        let msg_hash = [0x11u8; HASH_LEN];
        let pk = [0x22u8; HASH_LEN];

        let commitments_a = make_commitments(0xAA, NUM_ROUNDS);
        let commitments_b = make_commitments(0xBB, NUM_ROUNDS);

        let c_a = compute_challenges(&msg_hash, &pk, &commitments_a);
        let c_b = compute_challenges(&msg_hash, &pk, &commitments_b);

        assert_ne!(
            c_a, c_b,
            "Different commitments must produce different challenges"
        );
    }

    #[test]
    fn test_challenge_values_in_range() {
        let msg_hash = [0x33u8; HASH_LEN];
        let pk = [0x44u8; HASH_LEN];
        let commitments = make_commitments(0xCC, NUM_ROUNDS);

        let challenges = compute_challenges(&msg_hash, &pk, &commitments);

        assert_eq!(challenges.len(), NUM_ROUNDS);
        for (i, &c) in challenges.iter().enumerate() {
            assert!(
                c < 3,
                "Challenge at round {} is {} but must be in {{0, 1, 2}}",
                i,
                c
            );
        }
    }

    #[test]
    fn test_challenge_distribution() {
        let msg_hash = [0x55u8; HASH_LEN];
        let pk = [0x66u8; HASH_LEN];
        let commitments = make_commitments(0xDD, NUM_ROUNDS);

        let challenges = compute_challenges(&msg_hash, &pk, &commitments);

        let mut counts = [0usize; 3];
        for &c in &challenges {
            counts[c as usize] += 1;
        }

        // With NUM_ROUNDS = 219 and uniform distribution, expected count per
        // value is 73. We check each value appears at least 50 times, which is
        // well within statistical bounds (probability of failure is negligible).
        for (val, &count) in counts.iter().enumerate() {
            assert!(
                count >= 50,
                "Challenge value {} appeared only {} times (expected ~73)",
                val,
                count
            );
        }
    }
}
