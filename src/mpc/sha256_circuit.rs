//! SHA-256 compression function implemented as an MPC circuit.
//!
//! Provides both 3-party (prover) and 2-party (verifier) variants of the
//! SHA-256 compression function, message schedule expansion, and full
//! SHA-256 hash computation over shared inputs.
//!
//! The circuit decomposes SHA-256 into operations on XOR-additive shares:
//! - **Free gates**: XOR, NOT, ROTR, SHR (no tape/view interaction)
//! - **Interactive gates**: AND, ADD, Ch, Maj (consume randomness from tapes
//!   and record outputs to views)

use alloc::vec::Vec;

use crate::mpc::gates;
use crate::mpc::gates_verify;
use crate::mpc::tape::LazyTape;
use crate::mpc::view::View;
use crate::params::{SHA256_ROUNDS, SHA256_SCHEDULE_LEN, SHA256_STATE_WORDS};

// ---------------------------------------------------------------------------
// SHA-256 constants
// ---------------------------------------------------------------------------

/// Standard SHA-256 initial hash values H0..H7.
const SHA256_IV: [u32; SHA256_STATE_WORDS] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Standard SHA-256 round constants K[0..63].
const SHA256_K: [u32; SHA256_ROUNDS] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ---------------------------------------------------------------------------
// Free helper functions (3-party, no tape/view)
// ---------------------------------------------------------------------------

/// Lower-case sigma0: sigma0(x) = ROTR(7,x) ^ ROTR(18,x) ^ SHR(3,x)
#[inline]
fn small_sigma0(x: [u32; 3]) -> [u32; 3] {
    let r7 = gates::rightrotate(x, 7);
    let r18 = gates::rightrotate(x, 18);
    let s3 = gates::rightshift(x, 3);
    gates::xor(gates::xor(r7, r18), s3)
}

/// Lower-case sigma1: sigma1(x) = ROTR(17,x) ^ ROTR(19,x) ^ SHR(10,x)
#[inline]
fn small_sigma1(x: [u32; 3]) -> [u32; 3] {
    let r17 = gates::rightrotate(x, 17);
    let r19 = gates::rightrotate(x, 19);
    let s10 = gates::rightshift(x, 10);
    gates::xor(gates::xor(r17, r19), s10)
}

/// Upper-case Sigma0: Sigma0(a) = ROTR(2,a) ^ ROTR(13,a) ^ ROTR(22,a)
#[inline]
fn big_sigma0(a: [u32; 3]) -> [u32; 3] {
    let r2 = gates::rightrotate(a, 2);
    let r13 = gates::rightrotate(a, 13);
    let r22 = gates::rightrotate(a, 22);
    gates::xor(gates::xor(r2, r13), r22)
}

/// Upper-case Sigma1: Sigma1(e) = ROTR(6,e) ^ ROTR(11,e) ^ ROTR(25,e)
#[inline]
fn big_sigma1(e: [u32; 3]) -> [u32; 3] {
    let r6 = gates::rightrotate(e, 6);
    let r11 = gates::rightrotate(e, 11);
    let r25 = gates::rightrotate(e, 25);
    gates::xor(gates::xor(r6, r11), r25)
}

// ---------------------------------------------------------------------------
// Free helper functions (2-party verify, no tape/view)
// ---------------------------------------------------------------------------

/// Lower-case sigma0 (2-party verify variant).
#[inline]
fn small_sigma0_verify(x: [u32; 2]) -> [u32; 2] {
    let r7 = gates_verify::rightrotate_verify(x, 7);
    let r18 = gates_verify::rightrotate_verify(x, 18);
    let s3 = gates_verify::rightshift_verify(x, 3);
    gates_verify::xor_verify(gates_verify::xor_verify(r7, r18), s3)
}

/// Lower-case sigma1 (2-party verify variant).
#[inline]
fn small_sigma1_verify(x: [u32; 2]) -> [u32; 2] {
    let r17 = gates_verify::rightrotate_verify(x, 17);
    let r19 = gates_verify::rightrotate_verify(x, 19);
    let s10 = gates_verify::rightshift_verify(x, 10);
    gates_verify::xor_verify(gates_verify::xor_verify(r17, r19), s10)
}

/// Upper-case Sigma0 (2-party verify variant).
#[inline]
fn big_sigma0_verify(a: [u32; 2]) -> [u32; 2] {
    let r2 = gates_verify::rightrotate_verify(a, 2);
    let r13 = gates_verify::rightrotate_verify(a, 13);
    let r22 = gates_verify::rightrotate_verify(a, 22);
    gates_verify::xor_verify(gates_verify::xor_verify(r2, r13), r22)
}

/// Upper-case Sigma1 (2-party verify variant).
#[inline]
fn big_sigma1_verify(e: [u32; 2]) -> [u32; 2] {
    let r6 = gates_verify::rightrotate_verify(e, 6);
    let r11 = gates_verify::rightrotate_verify(e, 11);
    let r25 = gates_verify::rightrotate_verify(e, 25);
    gates_verify::xor_verify(gates_verify::xor_verify(r6, r11), r25)
}

// ---------------------------------------------------------------------------
// Shared constant encoding helpers
// ---------------------------------------------------------------------------

/// Encode a public constant as a 3-party XOR share: party 0 holds the value,
/// parties 1 and 2 hold zero.
#[inline]
fn const_share_3(val: u32) -> [u32; 3] {
    [val, 0, 0]
}

/// Encode a public constant as a 2-party XOR share for the opened pair
/// `(e, (e+1) mod 3)`. The full 3-party encoding is `[val, 0, 0]`, so the
/// two visible shares depend on which parties are opened.
#[inline]
fn const_share_2(val: u32, e: usize) -> [u32; 2] {
    match e {
        0 => [val, 0], // parties 0, 1
        1 => [0, 0],   // parties 1, 2
        2 => [0, val],  // parties 2, 0
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// 3-party SHA-256 compression (prover)
// ---------------------------------------------------------------------------

/// SHA-256 compression function over 3-party XOR-additive shares.
///
/// Computes the standard SHA-256 compression on shared `state` and `block`:
/// 1. Expands the 16-word message block into a 64-word schedule.
/// 2. Runs 64 compression rounds with working variables `a..h`.
/// 3. Adds the original state to the final working variables.
///
/// # Arguments
///
/// * `state` - Shared initial hash state (8 words, H0..H7).
/// * `block` - Shared message block (16 big-endian u32 words).
/// * `tapes` - Random tapes for each of the 3 parties.
/// * `views` - Output views for each of the 3 parties.
///
/// # Returns
///
/// The updated shared hash state after compression.
pub fn sha256_compress(
    state: &[[u32; 3]; SHA256_STATE_WORDS],
    block: &[[u32; 3]; 16],
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [[u32; 3]; SHA256_STATE_WORDS] {
    // -- Message schedule expansion --
    let mut w = [[0u32; 3]; SHA256_SCHEDULE_LEN];
    for i in 0..16 {
        w[i] = block[i];
    }
    for i in 16..SHA256_SCHEDULE_LEN {
        // w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16]
        let s1 = small_sigma1(w[i - 2]);
        let s0 = small_sigma0(w[i - 15]);
        let tmp = gates::add(s1, w[i - 7], tapes, views);
        let tmp = gates::add(tmp, s0, tapes, views);
        w[i] = gates::add(tmp, w[i - 16], tapes, views);
    }

    // -- Initialize working variables --
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // -- 64 compression rounds --
    for i in 0..SHA256_ROUNDS {
        let sigma1_e = big_sigma1(e);
        let ch_efg = gates::ch(e, f, g, tapes, views);
        let k_share = const_share_3(SHA256_K[i]);

        // T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + w[i]
        let t1 = gates::add(h, sigma1_e, tapes, views);
        let t1 = gates::add(t1, ch_efg, tapes, views);
        let t1 = gates::add(t1, k_share, tapes, views);
        let t1 = gates::add(t1, w[i], tapes, views);

        let sigma0_a = big_sigma0(a);
        let maj_abc = gates::maj(a, b, c, tapes, views);

        // T2 = Sigma0(a) + Maj(a,b,c)
        let t2 = gates::add(sigma0_a, maj_abc, tapes, views);

        // Rotate working variables
        h = g;
        g = f;
        f = e;
        e = gates::add(d, t1, tapes, views);
        d = c;
        c = b;
        b = a;
        a = gates::add(t1, t2, tapes, views);
    }

    // -- Add original state --
    let vars = [a, b, c, d, e, f, g, h];
    let mut output = [[0u32; 3]; SHA256_STATE_WORDS];
    for i in 0..SHA256_STATE_WORDS {
        output[i] = gates::add(state[i], vars[i], tapes, views);
    }
    output
}

// ---------------------------------------------------------------------------
// 2-party SHA-256 compression (verifier)
// ---------------------------------------------------------------------------

/// SHA-256 compression function over 2-party XOR-additive shares (verifier).
///
/// Mirrors [`sha256_compress`] but uses 2-party verification gates. The
/// verifier opens parties `e` and `(e+1) mod 3`; party `e`'s view provides
/// previously recorded gate outputs, while party `(e+1) mod 3`'s outputs
/// are recomputed and recorded into `view_next`.
///
/// # Arguments
///
/// * `state` - Shared initial hash state for the opened pair.
/// * `block` - Shared message block for the opened pair (16 words).
/// * `e` - Index of the first opened party (0, 1, or 2).
/// * `tape_e` - Random tape for party `e`.
/// * `tape_next` - Random tape for party `(e+1) mod 3`.
/// * `view_e` - Recorded view of party `e` (read mode).
/// * `view_next` - Fresh view for party `(e+1) mod 3` (write mode).
///
/// # Returns
///
/// The updated shared hash state for the opened pair.
pub fn sha256_compress_verify(
    state: &[[u32; 2]; SHA256_STATE_WORDS],
    block: &[[u32; 2]; 16],
    e: usize,
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [[u32; 2]; SHA256_STATE_WORDS] {
    // -- Message schedule expansion --
    let mut w = [[0u32; 2]; SHA256_SCHEDULE_LEN];
    for i in 0..16 {
        w[i] = block[i];
    }
    for i in 16..SHA256_SCHEDULE_LEN {
        let s1 = small_sigma1_verify(w[i - 2]);
        let s0 = small_sigma0_verify(w[i - 15]);
        let tmp = gates_verify::add_verify(s1, w[i - 7], tape_e, tape_next, view_e, view_next);
        let tmp = gates_verify::add_verify(tmp, s0, tape_e, tape_next, view_e, view_next);
        w[i] = gates_verify::add_verify(tmp, w[i - 16], tape_e, tape_next, view_e, view_next);
    }

    // -- Initialize working variables --
    let mut va = state[0];
    let mut vb = state[1];
    let mut vc = state[2];
    let mut vd = state[3];
    let mut ve = state[4];
    let mut vf = state[5];
    let mut vg = state[6];
    let mut vh = state[7];

    // -- 64 compression rounds --
    for i in 0..SHA256_ROUNDS {
        let sigma1_e = big_sigma1_verify(ve);
        let ch_efg = gates_verify::ch_verify(ve, vf, vg, e, tape_e, tape_next, view_e, view_next);
        let k_share = const_share_2(SHA256_K[i], e);

        // T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + w[i]
        let t1 = gates_verify::add_verify(vh, sigma1_e, tape_e, tape_next, view_e, view_next);
        let t1 = gates_verify::add_verify(t1, ch_efg, tape_e, tape_next, view_e, view_next);
        let t1 = gates_verify::add_verify(t1, k_share, tape_e, tape_next, view_e, view_next);
        let t1 = gates_verify::add_verify(t1, w[i], tape_e, tape_next, view_e, view_next);

        let sigma0_a = big_sigma0_verify(va);
        let maj_abc = gates_verify::maj_verify(va, vb, vc, tape_e, tape_next, view_e, view_next);

        // T2 = Sigma0(a) + Maj(a,b,c)
        let t2 = gates_verify::add_verify(sigma0_a, maj_abc, tape_e, tape_next, view_e, view_next);

        // Rotate working variables
        vh = vg;
        vg = vf;
        vf = ve;
        ve = gates_verify::add_verify(vd, t1, tape_e, tape_next, view_e, view_next);
        vd = vc;
        vc = vb;
        vb = va;
        va = gates_verify::add_verify(t1, t2, tape_e, tape_next, view_e, view_next);
    }

    // -- Add original state --
    let vars = [va, vb, vc, vd, ve, vf, vg, vh];
    let mut output = [[0u32; 2]; SHA256_STATE_WORDS];
    for i in 0..SHA256_STATE_WORDS {
        output[i] = gates_verify::add_verify(state[i], vars[i], tape_e, tape_next, view_e, view_next);
    }
    output
}

// ---------------------------------------------------------------------------
// Full SHA-256 hash (multi-block, 3-party prover)
// ---------------------------------------------------------------------------

/// Compute full SHA-256 over an already-padded shared message (3-party prover).
///
/// The caller must supply a message that has already been padded to a multiple
/// of 16 u32 words (512 bits) according to the SHA-256 padding rule.
///
/// # Arguments
///
/// * `message` - Shared padded message as a slice of u32-word shares. Its
///   length must be a multiple of 16.
/// * `tapes` - Random tapes for each of the 3 parties.
/// * `views` - Output views for each of the 3 parties.
///
/// # Panics
///
/// Panics if `message.len()` is not a multiple of 16.
pub fn sha256_mpc(
    message: &[[u32; 3]],
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [[u32; 3]; SHA256_STATE_WORDS] {
    assert!(
        message.len() % 16 == 0,
        "message length must be a multiple of 16 words"
    );

    // Initialize state with standard IV, shared as [H_i, 0, 0].
    let mut state = [[0u32; 3]; SHA256_STATE_WORDS];
    for i in 0..SHA256_STATE_WORDS {
        state[i] = const_share_3(SHA256_IV[i]);
    }

    // Process each 16-word (512-bit) block.
    for chunk in message.chunks_exact(16) {
        let mut block = [[0u32; 3]; 16];
        block.copy_from_slice(chunk);
        state = sha256_compress(&state, &block, tapes, views);
    }

    state
}

// ---------------------------------------------------------------------------
// Full SHA-256 hash (multi-block, 2-party verifier)
// ---------------------------------------------------------------------------

/// Compute full SHA-256 over an already-padded shared message (2-party verifier).
///
/// The caller must supply a message that has already been padded to a multiple
/// of 16 u32 words (512 bits) according to the SHA-256 padding rule.
///
/// # Arguments
///
/// * `message` - Shared padded message for the opened pair. Its length must
///   be a multiple of 16.
/// * `e` - Index of the first opened party (0, 1, or 2).
/// * `tape_e` - Random tape for party `e`.
/// * `tape_next` - Random tape for party `(e+1) mod 3`.
/// * `view_e` - Recorded view of party `e` (read mode).
/// * `view_next` - Fresh view for party `(e+1) mod 3` (write mode).
///
/// # Panics
///
/// Panics if `message.len()` is not a multiple of 16.
pub fn sha256_mpc_verify(
    message: &[[u32; 2]],
    e: usize,
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [[u32; 2]; SHA256_STATE_WORDS] {
    assert!(
        message.len() % 16 == 0,
        "message length must be a multiple of 16 words"
    );

    let mut state = [[0u32; 2]; SHA256_STATE_WORDS];
    for i in 0..SHA256_STATE_WORDS {
        state[i] = const_share_2(SHA256_IV[i], e);
    }

    for chunk in message.chunks_exact(16) {
        let mut block = [[0u32; 2]; 16];
        block.copy_from_slice(chunk);
        state = sha256_compress_verify(&state, &block, e, tape_e, tape_next, view_e, view_next);
    }

    state
}

// ---------------------------------------------------------------------------
// SHA-256 padding utility
// ---------------------------------------------------------------------------

/// Pad a byte-slice message according to SHA-256 padding rules and return
/// the result as a vector of big-endian u32 words.
///
/// The padding appends a `0x80` byte, then zero bytes, then a 64-bit
/// big-endian bit-length, such that the total length is a multiple of 64
/// bytes (16 u32 words).
pub fn sha256_pad(msg: &[u8]) -> Vec<u32> {
    let msg_len_bits = (msg.len() as u64) * 8;

    // Total padded length in bytes must be a multiple of 64.
    // We need: msg.len() + 1 (0x80) + padding_zeros + 8 (length) = multiple of 64
    let mut padded_len = msg.len() + 1 + 8; // minimum: message + 0x80 + 8-byte length
    if padded_len % 64 != 0 {
        padded_len += 64 - (padded_len % 64);
    }

    let mut buf = Vec::with_capacity(padded_len);
    buf.extend_from_slice(msg);
    buf.push(0x80);
    // Zero-pad until 8 bytes remain for the length
    while buf.len() < padded_len - 8 {
        buf.push(0);
    }
    // Append 64-bit big-endian bit length
    buf.extend_from_slice(&msg_len_bits.to_be_bytes());

    debug_assert_eq!(buf.len() % 64, 0);

    // Convert to big-endian u32 words
    let num_words = buf.len() / 4;
    let mut words = Vec::with_capacity(num_words);
    for i in 0..num_words {
        let offset = i * 4;
        let word = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        words.push(word);
    }
    words
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::shares::{reconstruct_u32, share_u32};
    use crate::params::SEED_LEN;
    use sha2::{Digest, Sha256};

    /// Create 3 deterministic tapes for testing.
    fn make_tapes(seeds: &[[u8; SEED_LEN]; 3]) -> [LazyTape; 3] {
        [
            LazyTape::new(&seeds[0], 0, 0),
            LazyTape::new(&seeds[1], 0, 1),
            LazyTape::new(&seeds[2], 0, 2),
        ]
    }

    fn make_views() -> [View; 3] {
        [View::new(), View::new(), View::new()]
    }

    /// Share each u32 word of a padded message into 3-party shares.
    fn share_words(words: &[u32], tapes: &mut [LazyTape; 3]) -> Vec<[u32; 3]> {
        words
            .iter()
            .map(|&w| share_u32(w, tapes[0].next_u32(), tapes[1].next_u32()))
            .collect()
    }

    /// Reconstruct the hash output bytes from 3-party shared state words.
    fn reconstruct_hash(state: &[[u32; 3]; SHA256_STATE_WORDS]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..SHA256_STATE_WORDS {
            let word = reconstruct_u32(&state[i]);
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Compute reference SHA-256 digest using the `sha2` crate.
    fn reference_sha256(msg: &[u8]) -> [u8; 32] {
        let result = Sha256::digest(msg);
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Run the MPC SHA-256 on the given message bytes and return the
    /// reconstructed hash, the 3-party views, and the shared message words.
    fn run_mpc_sha256(
        msg: &[u8],
    ) -> (
        [u8; 32],
        [View; 3],
        Vec<[u32; 3]>,
    ) {
        let seeds = [
            [0x11u8; SEED_LEN],
            [0x22u8; SEED_LEN],
            [0x33u8; SEED_LEN],
        ];

        // Use separate tapes for sharing randomness and for the circuit itself.
        let mut share_tapes = make_tapes(&seeds);
        let padded = sha256_pad(msg);
        let shared_msg = share_words(&padded, &mut share_tapes);

        // Fresh tapes for the circuit evaluation.
        let mut circuit_tapes = [
            LazyTape::new(&seeds[0], 1, 0),
            LazyTape::new(&seeds[1], 1, 1),
            LazyTape::new(&seeds[2], 1, 2),
        ];
        let mut views = make_views();

        let state = sha256_mpc(&shared_msg, &mut circuit_tapes, &mut views);
        let hash = reconstruct_hash(&state);
        (hash, views, shared_msg)
    }

    // -- Test 1: MPC SHA-256 matches reference implementation --

    #[test]
    fn test_sha256_mpc_matches_real() {
        let msg = b"hello world";
        let (mpc_hash, _views, _shared) = run_mpc_sha256(msg);
        let expected = reference_sha256(msg);
        assert_eq!(
            mpc_hash, expected,
            "MPC SHA-256 output does not match sha2::Sha256"
        );
    }

    // -- Test 2: Compress verify consistency --

    #[test]
    fn test_sha256_compress_verify_consistency() {
        let seeds = [
            [0xAAu8; SEED_LEN],
            [0xBBu8; SEED_LEN],
            [0xCCu8; SEED_LEN],
        ];

        // Create a simple one-block message.
        let msg = b"test compress verify";
        let padded = sha256_pad(msg);

        // Share the padded message.
        let mut share_tapes = make_tapes(&seeds);
        let shared_msg = share_words(&padded, &mut share_tapes);

        // Build shared IV.
        let state_3: [[u32; 3]; SHA256_STATE_WORDS] = core::array::from_fn(|i| const_share_3(SHA256_IV[i]));

        // Build the shared block.
        let mut block_3 = [[0u32; 3]; 16];
        block_3.copy_from_slice(&shared_msg[..16]);

        // Run 3-party prover.
        let mut prover_tapes = [
            LazyTape::new(&seeds[0], 1, 0),
            LazyTape::new(&seeds[1], 1, 1),
            LazyTape::new(&seeds[2], 1, 2),
        ];
        let mut prover_views = make_views();
        let result_3 = sha256_compress(&state_3, &block_3, &mut prover_tapes, &mut prover_views);

        // For each party pair (e, e+1 mod 3), run 2-party verifier and check.
        for e in 0..3 {
            let next = (e + 1) % 3;

            // Extract the 2-party shares for state and block.
            let state_2: [[u32; 2]; SHA256_STATE_WORDS] =
                core::array::from_fn(|i| [state_3[i][e], state_3[i][next]]);
            let block_2: [[u32; 2]; 16] =
                core::array::from_fn(|i| [block_3[i][e], block_3[i][next]]);

            // Clone party e's view and reset its read pointer.
            let mut view_e = prover_views[e].clone();
            view_e.reset_read();
            let mut view_next = View::new();

            let mut tape_e = LazyTape::new(&seeds[e], 1, e as u8);
            let mut tape_next = LazyTape::new(&seeds[next], 1, next as u8);

            let result_2 = sha256_compress_verify(
                &state_2,
                &block_2,
                e,
                &mut tape_e,
                &mut tape_next,
                &mut view_e,
                &mut view_next,
            );

            // Check that the opened pair matches the prover's output.
            for i in 0..SHA256_STATE_WORDS {
                assert_eq!(
                    result_2[i][0], result_3[i][e],
                    "party e={} word {}: share e mismatch",
                    e, i
                );
                assert_eq!(
                    result_2[i][1], result_3[i][next],
                    "party e={} word {}: share next mismatch",
                    e, i
                );
            }

            // Verify that the recomputed view for party (e+1) matches the prover's view.
            assert_eq!(
                view_next.outputs, prover_views[next].outputs,
                "party e={}: recomputed view_next does not match prover view for party {}",
                e, next
            );
        }
    }

    // -- Test 3: Empty message --

    #[test]
    fn test_sha256_mpc_empty_message() {
        let msg = b"";
        let (mpc_hash, _views, _shared) = run_mpc_sha256(msg);
        let expected = reference_sha256(msg);
        assert_eq!(
            mpc_hash, expected,
            "MPC SHA-256 of empty string does not match reference"
        );
    }

    // -- Test 4: Various message lengths (fuzz) --

    #[test]
    fn test_sha256_mpc_fuzz() {
        // Test several lengths including edge cases around block boundaries.
        // A SHA-256 block is 64 bytes. Padding requires at least 9 extra bytes
        // (1 byte 0x80 + 8 bytes length), so messages of length 55, 56, 63, 64
        // trigger different padding scenarios.
        let test_lengths: &[usize] = &[0, 1, 2, 15, 32, 55, 56, 63, 64, 65, 100, 128, 200];

        for &len in test_lengths {
            // Build a deterministic message of the given length.
            let msg: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
            let (mpc_hash, _views, _shared) = run_mpc_sha256(&msg);
            let expected = reference_sha256(&msg);
            assert_eq!(
                mpc_hash, expected,
                "MPC SHA-256 mismatch for message length {}",
                len
            );
        }
    }

    // -- Supplementary: padding sanity checks --

    #[test]
    fn test_sha256_pad_empty() {
        let words = sha256_pad(b"");
        // Empty message: 0 bytes + 0x80 + 55 zero bytes + 8-byte length = 64 bytes = 16 words.
        assert_eq!(words.len(), 16);
        assert_eq!(words[0], 0x80000000); // 0x80 in the first byte (big-endian)
        assert_eq!(words[15], 0);          // bit length = 0
    }

    #[test]
    fn test_sha256_pad_abc() {
        let words = sha256_pad(b"abc");
        assert_eq!(words.len(), 16);
        // "abc" = 0x61626380... then zeros, then bit length 24 in last word.
        assert_eq!(words[0], 0x61626380);
        assert_eq!(words[15], 24); // 3 bytes = 24 bits
    }

    #[test]
    fn test_sha256_pad_56_bytes() {
        // 56 bytes needs two blocks because 56 + 1 + 8 = 65 > 64.
        let msg = [0x41u8; 56];
        let words = sha256_pad(&msg);
        assert_eq!(words.len(), 32); // 2 blocks = 128 bytes = 32 words
    }

    #[test]
    fn test_sha256_pad_64_bytes() {
        // 64 bytes needs two blocks.
        let msg = [0x42u8; 64];
        let words = sha256_pad(&msg);
        assert_eq!(words.len(), 32);
    }
}
