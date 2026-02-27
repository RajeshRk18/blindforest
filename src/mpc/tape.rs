use crate::params::SEED_LEN;
use crate::prf::Prf;

/// Streaming random tape for one party in one round.
/// Uses AES-256-CTR under the hood, generating bytes on demand.
pub struct LazyTape {
    prf: Prf,
}

impl LazyTape {
    /// Create a new tape for the given seed, round, and party index.
    pub fn new(seed: &[u8; SEED_LEN], round: u32, party: u8) -> Self {
        let prf = Prf::for_tape(seed, round, party);
        Self { prf }
    }

    /// Get the next u32 from the tape.
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        self.prf.generate_u32()
    }

    /// Get the next n bytes from the tape.
    pub fn next_bytes(&mut self, n: usize) -> alloc::vec::Vec<u8> {
        self.prf.generate(n)
    }

    /// Fill a buffer with bytes from the tape.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.prf.fill(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tape_deterministic() {
        let seed = [0x42u8; SEED_LEN];
        let mut tape1 = LazyTape::new(&seed, 0, 0);
        let mut tape2 = LazyTape::new(&seed, 0, 0);
        assert_eq!(tape1.next_u32(), tape2.next_u32());
        assert_eq!(tape1.next_u32(), tape2.next_u32());
    }

    #[test]
    fn test_different_parties_differ() {
        let seed = [0x42u8; SEED_LEN];
        let mut tape0 = LazyTape::new(&seed, 0, 0);
        let mut tape1 = LazyTape::new(&seed, 0, 1);
        // Very unlikely to be equal
        assert_ne!(tape0.next_u32(), tape1.next_u32());
    }

    #[test]
    fn test_different_rounds_differ() {
        let seed = [0x42u8; SEED_LEN];
        let mut tape_r0 = LazyTape::new(&seed, 0, 0);
        let mut tape_r1 = LazyTape::new(&seed, 1, 0);
        assert_ne!(tape_r0.next_u32(), tape_r1.next_u32());
    }

    #[test]
    fn test_tape_streaming_consistency() {
        let seed = [0xABu8; SEED_LEN];
        let mut tape1 = LazyTape::new(&seed, 5, 2);
        let v1 = tape1.next_u32();
        let v2 = tape1.next_u32();

        // Second tape, consume 8 bytes as a block
        let mut tape2 = LazyTape::new(&seed, 5, 2);
        let bytes = tape2.next_bytes(8);
        let r1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let r2 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(v1, r1);
        assert_eq!(v2, r2);
    }
}
