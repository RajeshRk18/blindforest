use crate::params::NUM_PARTIES;

/// A 3-party additive share of a u32 value.
/// Reconstruction: value = shares[0] ^ shares[1] ^ shares[2]
pub type Share = [u32; NUM_PARTIES];

/// Create shares of a value. shares[0] and shares[1] are random,
/// shares[2] = value ^ shares[0] ^ shares[1].
#[inline]
pub fn share_u32(value: u32, rand0: u32, rand1: u32) -> Share {
    [rand0, rand1, value ^ rand0 ^ rand1]
}

/// Reconstruct a value from its shares.
#[inline]
pub fn reconstruct_u32(shares: &Share) -> u32 {
    shares[0] ^ shares[1] ^ shares[2]
}

/// Share a byte slice into 3 party slices. Each output has the same length as input.
/// rand0 and rand1 must have the same length as value.
pub fn share_bytes(value: &[u8], rand0: &[u8], rand1: &[u8]) -> [alloc::vec::Vec<u8>; NUM_PARTIES] {
    assert_eq!(value.len(), rand0.len());
    assert_eq!(value.len(), rand1.len());
    let len = value.len();
    let mut s2 = alloc::vec![0u8; len];
    for i in 0..len {
        s2[i] = value[i] ^ rand0[i] ^ rand1[i];
    }
    [rand0.to_vec(), rand1.to_vec(), s2]
}

/// Reconstruct bytes from 3 party shares.
pub fn reconstruct_bytes(shares: &[alloc::vec::Vec<u8>; NUM_PARTIES]) -> alloc::vec::Vec<u8> {
    let len = shares[0].len();
    assert_eq!(shares[1].len(), len);
    assert_eq!(shares[2].len(), len);
    let mut result = alloc::vec![0u8; len];
    for i in 0..len {
        result[i] = shares[0][i] ^ shares[1][i] ^ shares[2][i];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_reconstruct_u32() {
        let value = 0xDEADBEEF_u32;
        let shares = share_u32(value, 0x12345678, 0x9ABCDEF0);
        assert_eq!(reconstruct_u32(&shares), value);
    }

    #[test]
    fn test_share_reconstruct_zero() {
        let shares = share_u32(0, 0x11111111, 0x22222222);
        assert_eq!(reconstruct_u32(&shares), 0);
    }

    #[test]
    fn test_share_reconstruct_bytes() {
        let value = b"hello world 1234";
        let rand0 = vec![0x42u8; value.len()];
        let rand1 = vec![0xABu8; value.len()];
        let shares = share_bytes(value, &rand0, &rand1);
        let reconstructed = reconstruct_bytes(&shares);
        assert_eq!(&reconstructed, value);
    }
}
