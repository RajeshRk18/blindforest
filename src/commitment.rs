use crate::hash::{self, Domain, HashOutput};
use crate::params::COMMITMENT_RAND_LEN;

/// A commitment to a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The commitment value.
    pub value: HashOutput,
}

/// Commitment randomness.
///
/// The inner bytes are intentionally hidden from `Debug` output to prevent
/// accidental secret leakage in logs.
#[derive(Clone)]
pub struct CommitmentRandomness(pub [u8; COMMITMENT_RAND_LEN]);

impl core::fmt::Debug for CommitmentRandomness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("CommitmentRandomness")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl CommitmentRandomness {
    /// Generate random commitment randomness.
    pub fn random(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let mut r = [0u8; COMMITMENT_RAND_LEN];
        rng.fill_bytes(&mut r);
        Self(r)
    }
}

impl zeroize::Zeroize for CommitmentRandomness {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for CommitmentRandomness {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Compute Com(m; r) = H_c(m ∥ r) with domain separation.
/// Paper Section A.2, page 18: single-layer hash of message concatenated with randomness.
pub fn commit(message: &[u8], randomness: &CommitmentRandomness) -> Commitment {
    let value = hash::hash_with_domain2(Domain::Commitment, message, &randomness.0);
    Commitment { value }
}

/// Verify that a commitment matches a message and randomness.
pub fn verify_commitment(
    commitment: &Commitment,
    message: &[u8],
    randomness: &CommitmentRandomness,
) -> bool {
    let recomputed = commit(message, randomness);
    use subtle::ConstantTimeEq;
    bool::from(recomputed.value.ct_eq(&commitment.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_roundtrip() {
        let mut rng = rand_core::OsRng;
        let msg = b"hello world";
        let r = CommitmentRandomness::random(&mut rng);
        let com = commit(msg, &r);
        assert!(verify_commitment(&com, msg, &r));
    }

    #[test]
    fn test_commitment_wrong_message() {
        let mut rng = rand_core::OsRng;
        let msg = b"hello world";
        let r = CommitmentRandomness::random(&mut rng);
        let com = commit(msg, &r);
        assert!(!verify_commitment(&com, b"wrong message", &r));
    }

    #[test]
    fn test_commitment_wrong_randomness() {
        let mut rng = rand_core::OsRng;
        let msg = b"hello world";
        let r1 = CommitmentRandomness::random(&mut rng);
        let r2 = CommitmentRandomness::random(&mut rng);
        let com = commit(msg, &r1);
        assert!(!verify_commitment(&com, msg, &r2));
    }

    #[test]
    fn test_commitment_deterministic() {
        let r = CommitmentRandomness([0x42u8; COMMITMENT_RAND_LEN]);
        let com1 = commit(b"test", &r);
        let r = CommitmentRandomness([0x42u8; COMMITMENT_RAND_LEN]);
        let com2 = commit(b"test", &r);
        assert_eq!(com1, com2);
    }
}
