use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Extract the `i`-th bit (0-indexed from MSB) of byte slice `data`.
/// Returns 0 or 1.
#[inline]
pub fn get_bit(data: &[u8], i: usize) -> u8 {
    let byte_idx = i / 8;
    let bit_idx = 7 - (i % 8);
    (data[byte_idx] >> bit_idx) & 1
}

/// Extract the `i`-th bit of the doubled message m̂ = (M || M̄).
/// For i < 256: returns `get_bit(data, i)` (original message bit).
/// For i >= 256: returns `1 - get_bit(data, i - 256)` (complement bit).
/// This ensures exactly 256 chain hashes always happen (constant work).
#[inline]
pub fn get_doubled_bit(data: &[u8], i: usize) -> u8 {
    let n = data.len() * 8;
    if i < n {
        get_bit(data, i)
    } else {
        1 - get_bit(data, i - n)
    }
}

/// Convert a byte slice to a vector of bits (MSB first).
pub fn bytes_to_bits(data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut bits = alloc::vec::Vec::with_capacity(data.len() * 8);
    for byte in data {
        for j in (0..8).rev() {
            bits.push((byte >> j) & 1);
        }
    }
    bits
}

/// Convert a slice of bits (0 or 1, MSB first) back to bytes.
/// Panics if bits.len() is not a multiple of 8.
pub fn bits_to_bytes(bits: &[u8]) -> alloc::vec::Vec<u8> {
    assert!(bits.len() % 8 == 0, "bits length must be multiple of 8");
    let mut bytes = alloc::vec![0u8; bits.len() / 8];
    for (i, &bit) in bits.iter().enumerate() {
        bytes[i / 8] |= bit << (7 - (i % 8));
    }
    bytes
}

/// Constant-time comparison of two byte slices.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    a.ct_eq(b)
}

/// Zeroize a mutable byte slice.
#[inline]
pub fn zeroize_slice(data: &mut [u8]) {
    data.zeroize();
}

/// Encode a u32 as big-endian bytes.
#[inline]
pub fn u32_to_be_bytes(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

/// Decode a u32 from big-endian bytes.
#[inline]
pub fn u32_from_be_bytes(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[..4]);
    u32::from_be_bytes(buf)
}

/// Encode a u64 as big-endian bytes.
#[inline]
pub fn u64_to_be_bytes(val: u64) -> [u8; 8] {
    val.to_be_bytes()
}

/// XOR two equal-length byte slices into a new Vec.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> alloc::vec::Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// XOR `src` into `dst` in-place.
pub fn xor_bytes_into(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}
