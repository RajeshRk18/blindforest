//! Blind-signature verification circuit evaluated as a 3-party MPC computation.
//!
//! This is the heart of the ZKBoo-based blind signature scheme. The prover
//! demonstrates knowledge of a valid WOTS+ signature and Merkle authentication
//! path that verifies against a public Merkle root, without revealing the
//! signature itself.
//!
//! # Circuit structure
//!
//! The verification circuit performs:
//!
//! 1. **WOTS public-key recovery** -- For each of the 512 doubled message bits
//!    (m̂ = M || M̄):
//!    - bit = 0: `pk[i] = SHA-256(WotsChain || sig[i] || i)` (one chain hash)
//!    - bit = 1: `pk[i] = sig[i]` (signature element is already the pk element)
//!    Since the message hash is *public* input, the branch is a plain `if`
//!    rather than an MPC conditional.
//!
//! 2. **Public-key compression** --
//!    `compressed_pk = SHA-256(WotsPkCompress || pk[0] || ... || pk[511])`
//!
//! 3. **Leaf hash** -- `leaf = SHA-256(LeafHash || compressed_pk)`
//!
//! 4. **Merkle path recomputation** -- For each of the 10 tree levels, with
//!    the direction bit taken from the *public* leaf index:
//!    - bit = 0: `node = SHA-256(MerkleNode || current || sibling)`
//!    - bit = 1: `node = SHA-256(MerkleNode || sibling || current)`
//!
//! 5. The resulting shared root is returned; the caller (prover / verifier)
//!    checks it against the expected public root.
//!
//! # Complexity
//!
//! The circuit evaluates approximately 523 SHA-256 invocations in MPC:
//! - 512 WOTS chain hashes (exactly 256 always happen due to doubling)
//! - 1 pk-compression hash (over 512 * 32 = 16384 bytes, multi-block)
//! - 1 leaf hash
//! - 10 Merkle-node hashes
//!
//! Each SHA-256 invocation is extremely expensive in the MPC setting due to the
//! AND-gate cost of the SHA-256 compression function.

use alloc::vec::Vec;

use crate::hash::Domain;
use crate::mpc::sha256_circuit::{sha256_mpc, sha256_mpc_verify, sha256_pad};
use crate::mpc::shares;
use crate::mpc::tape::LazyTape;
use crate::mpc::view::View;
use crate::params::{HASH_LEN, SHA256_STATE_WORDS, TREE_HEIGHT, WOTS_LEN};
use crate::util;

// =========================================================================
// Public types
// =========================================================================

/// Secret witness for the blind-signature verification circuit.
///
/// These values are shared among the three MPC parties; the verifier never
/// sees the plain values.
pub struct CircuitInput {
    /// WOTS signature elements (512 elements, each 32 bytes).
    pub wots_sig: Vec<[u8; HASH_LEN]>,
    /// Merkle authentication-path siblings (10 hashes, each 32 bytes).
    pub auth_path: Vec<[u8; HASH_LEN]>,
}

/// Public inputs to the verification circuit.
///
/// These are known to both prover and verifier and are embedded directly into
/// the MPC shares (only party 0 holds public constants; the other shares are
/// zero).
pub struct CircuitPublicInput {
    /// The committed message hash (what was signed).
    pub msg_hash: [u8; HASH_LEN],
    /// The expected Merkle root (public key).
    pub expected_root: [u8; HASH_LEN],
    /// Leaf index in the Merkle tree (public, part of the signature).
    pub leaf_index: u32,
}

/// The secret witness after it has been split into 3-party XOR shares.
///
/// Each 32-byte hash element is represented as 8 big-endian `u32` words, each
/// word stored as `[u32; 3]` (one share per party).
pub struct SharedCircuitInput {
    /// Shared WOTS signature: `WOTS_LEN` elements, each 8 words.
    pub wots_sig: Vec<[[u32; 3]; SHA256_STATE_WORDS]>,
    /// Shared Merkle auth-path siblings: `TREE_HEIGHT` elements, each 8 words.
    pub auth_path: Vec<[[u32; 3]; SHA256_STATE_WORDS]>,
}

/// The 2-party projection of [`SharedCircuitInput`], used during verification.
///
/// Contains only the shares for the opened pair of parties `(e, (e+1)%3)`.
pub struct SharedCircuitInputPair {
    /// Shared WOTS signature: `WOTS_LEN` elements, each 8 words.
    pub wots_sig: Vec<[[u32; 2]; SHA256_STATE_WORDS]>,
    /// Shared Merkle auth-path siblings: `TREE_HEIGHT` elements, each 8 words.
    pub auth_path: Vec<[[u32; 2]; SHA256_STATE_WORDS]>,
}

// =========================================================================
// Sharing / projection helpers
// =========================================================================

/// Split a 32-byte value into 8 big-endian `u32` words and XOR-share each
/// word among 3 parties, drawing randomness from the tapes.
fn share_hash(bytes: &[u8; HASH_LEN], tapes: &mut [LazyTape; 3]) -> [[u32; 3]; SHA256_STATE_WORDS] {
    let mut out = [[0u32; 3]; SHA256_STATE_WORDS];
    for i in 0..SHA256_STATE_WORDS {
        let word = u32::from_be_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
        out[i] = shares::share_u32(word, tapes[0].next_u32(), tapes[1].next_u32());
    }
    out
}

/// Share all elements of a [`CircuitInput`] using the given tapes.
pub fn share_circuit_input(
    input: &CircuitInput,
    tapes: &mut [LazyTape; 3],
) -> SharedCircuitInput {
    assert_eq!(input.wots_sig.len(), WOTS_LEN);
    assert_eq!(input.auth_path.len(), TREE_HEIGHT);

    let wots_sig = input
        .wots_sig
        .iter()
        .map(|elem| share_hash(elem, tapes))
        .collect();

    let auth_path = input
        .auth_path
        .iter()
        .map(|sibling| share_hash(sibling, tapes))
        .collect();

    SharedCircuitInput { wots_sig, auth_path }
}

/// Project a 3-party [`SharedCircuitInput`] down to the 2-party pair
/// `(e, (e+1)%3)`.
pub fn project_shared_input(
    shared: &SharedCircuitInput,
    e: usize,
) -> SharedCircuitInputPair {
    let next = (e + 1) % 3;

    let wots_sig = shared
        .wots_sig
        .iter()
        .map(|elem| {
            let mut pair = [[0u32; 2]; SHA256_STATE_WORDS];
            for j in 0..SHA256_STATE_WORDS {
                pair[j] = [elem[j][e], elem[j][next]];
            }
            pair
        })
        .collect();

    let auth_path = shared
        .auth_path
        .iter()
        .map(|elem| {
            let mut pair = [[0u32; 2]; SHA256_STATE_WORDS];
            for j in 0..SHA256_STATE_WORDS {
                pair[j] = [elem[j][e], elem[j][next]];
            }
            pair
        })
        .collect();

    SharedCircuitInputPair { wots_sig, auth_path }
}

// =========================================================================
// Internal: domain-separated MPC hash helpers
// =========================================================================

/// Encode a public constant as a 3-party XOR share (`[val, 0, 0]`).
#[inline]
fn pub3(val: u32) -> [u32; 3] {
    [val, 0, 0]
}

/// Encode a public constant as a 2-party XOR share for opened pair `(e, e+1)`.
#[inline]
fn pub2(val: u32, e: usize) -> [u32; 2] {
    match e {
        0 => [val, 0],
        2 => [0, val],
        _ => [0, 0],
    }
}

/// Convert a byte slice to big-endian `u32` words (padding the last partial
/// word with zeros if necessary).
#[cfg(test)]
fn bytes_to_words(data: &[u8]) -> Vec<u32> {
    let mut words = Vec::with_capacity((data.len() + 3) / 4);
    let mut i = 0;
    while i + 4 <= data.len() {
        words.push(u32::from_be_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
        ]));
        i += 4;
    }
    if i < data.len() {
        let mut buf = [0u8; 4];
        buf[..data.len() - i].copy_from_slice(&data[i..]);
        words.push(u32::from_be_bytes(buf));
    }
    words
}

/// Build shared, padded message words for a domain-separated hash over
/// shared data (3-party).
///
/// Constructs `SHA-256(domain_byte || data_words)` by:
/// 1. Prepending the domain byte as a public constant.
/// 2. Applying SHA-256 padding to the known total length.
/// 3. Lifting each padding/domain word into shares.
///
/// `data_words` are already-shared `u32` words (big-endian encoding of the
/// secret data). `data_byte_len` is the number of meaningful *bytes* in the
/// data (important for correct SHA-256 padding).
fn build_domain_message_3(
    domain: Domain,
    data_words: &[[u32; 3]],
    data_byte_len: usize,
) -> Vec<[u32; 3]> {
    // The plaintext message is: [domain_byte] ++ data_bytes.
    // Total message length in bytes is 1 + data_byte_len.
    let total_msg_len = 1 + data_byte_len;

    // Compute padding for a message of `total_msg_len` bytes.
    // We build a dummy plaintext of that length, pad it, then overlay
    // the shared data words at the correct positions.
    let mut plain = Vec::with_capacity(total_msg_len);
    plain.push(domain as u8);
    plain.resize(total_msg_len, 0);
    let padded_words = sha256_pad(&plain);

    // Now build the shared version.
    // The first byte is the domain tag; this occupies the high byte of word 0.
    // The data bytes start at offset 1 in the byte stream, i.e., at bit
    // position 8 within word 0.
    //
    // Strategy: start from the fully-public padded words, then XOR in the
    // shared data at the correct positions.
    //
    // The domain byte and padding bytes are public -> [val, 0, 0].
    // The data bytes are secret -> carried in data_words.
    //
    // Because the data starts at byte offset 1 and each u32 word is 4 bytes,
    // the alignment is tricky. We handle this by constructing the shared
    // padded message word-by-word.

    // First, figure out where the data words sit inside the padded buffer.
    // Data bytes occupy [1 .. 1+data_byte_len) in the byte stream.
    // In the padded_words (big-endian u32), byte offset `b` maps to:
    //   word index  = b / 4
    //   byte within word = b % 4  (0 = MSB, 3 = LSB)
    //
    // Since data_byte_len is always a multiple of 32 (we hash 32-byte elements),
    // and 1 + data_byte_len is typically NOT aligned, we need to handle the
    // first partial word specially.

    // Actually, the simplest correct approach: build the full plaintext as
    // public bytes, pad it, get padded_words. Then for each data word, XOR
    // the public plaintext contribution out and XOR the shared data in.
    //
    // But that requires knowing the plaintext data, which we don't have
    // (it's shared). Instead, let's take a different approach:
    //
    // Observation: the domain byte + data is:
    //   byte 0:     domain_tag
    //   bytes 1..1+data_byte_len: the secret data
    //   remaining:  padding (0x80, zeros, length)
    //
    // All padding bytes are public. The domain byte is public.
    // The secret data occupies bytes 1 through data_byte_len (inclusive).
    //
    // We'll construct each padded word as:
    //   shared_word = public_component XOR secret_component
    // where public_component = [padded_words[i], 0, 0] and
    //       secret_component has the shared data bytes at the correct position.
    //
    // Since the data starts at byte 1 (not word-aligned), we need to
    // shift/merge. However, for the vast majority of our use cases, the data
    // is either:
    //   a) 32 bytes (a single hash element) -> total = 33 bytes
    //   b) 36 bytes (hash element + 4-byte index) -> total = 37 bytes
    //   c) 64 bytes (two hash elements for Merkle node) -> total = 65 bytes
    //   d) 8192 bytes (256 hash elements for pk compression) -> total = 8193 bytes
    //
    // For all cases the data is a whole number of u32 words (8, 9, 16, or 2048
    // words), and the 1-byte domain offset means the shared data straddles word
    // boundaries.
    //
    // The cleanest approach: serialize the domain byte + data as a flat byte
    // sequence, with the data bytes represented as 3-party shares at the byte
    // level, then convert to word-level shares. Since we're in MPC land and
    // the byte-to-word conversion is just packing (no AND gates needed), this
    // is fine.

    // Step 1: Build the flat byte-level shared message.
    //   For public bytes: [byte, 0, 0]
    //   For secret bytes: extract from data_words
    //
    // Step 2: Pad the shared byte message according to SHA-256 (padding bytes
    //   are all public).
    //
    // Step 3: Pack the padded bytes into big-endian u32 word shares.

    // Extract the shared data as individual byte shares.
    // data_words has `data_byte_len / 4` entries (assuming exact alignment),
    // each [u32;3]. We need to unpack these into bytes.
    let data_word_count = (data_byte_len + 3) / 4;
    debug_assert!(data_words.len() >= data_word_count);

    // Build flat shared bytes: domain_byte + data_bytes + padding
    let padded_byte_len = padded_words.len() * 4;
    let mut shared_bytes: Vec<[u8; 3]> = Vec::with_capacity(padded_byte_len);

    // Byte 0: domain tag (public)
    shared_bytes.push([domain as u8, 0, 0]);

    // Bytes 1..1+data_byte_len: secret data, extracted from data_words
    let mut data_byte_idx = 0;
    for word_idx in 0..data_word_count {
        let w = data_words[word_idx];
        let b0 = w.map(|s| (s >> 24) as u8);
        let b1 = w.map(|s| (s >> 16) as u8);
        let b2 = w.map(|s| (s >> 8) as u8);
        let b3 = w.map(|s| s as u8);
        for b in [b0, b1, b2, b3] {
            if data_byte_idx < data_byte_len {
                shared_bytes.push([b[0], b[1], b[2]]);
                data_byte_idx += 1;
            }
        }
    }

    // Remaining bytes: padding (public).
    // The padding starts at byte `total_msg_len` in the padded buffer.
    // We already have `1 + data_byte_len` bytes pushed.
    let plain_padded = {
        let mut p = Vec::with_capacity(total_msg_len);
        p.push(domain as u8);
        p.resize(total_msg_len, 0);
        sha256_pad(&p)
    };
    // Convert padded words back to bytes to extract padding bytes.
    let padded_bytes_ref: Vec<u8> = plain_padded
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();
    for i in total_msg_len..padded_byte_len {
        shared_bytes.push([padded_bytes_ref[i], 0, 0]);
    }

    debug_assert_eq!(shared_bytes.len(), padded_byte_len);

    // Pack into big-endian u32 word shares.
    let num_words = padded_byte_len / 4;
    let mut result = Vec::with_capacity(num_words);
    for wi in 0..num_words {
        let b0 = shared_bytes[wi * 4];
        let b1 = shared_bytes[wi * 4 + 1];
        let b2 = shared_bytes[wi * 4 + 2];
        let b3 = shared_bytes[wi * 4 + 3];
        let mut word = [0u32; 3];
        for p in 0..3 {
            word[p] = (b0[p] as u32) << 24
                | (b1[p] as u32) << 16
                | (b2[p] as u32) << 8
                | (b3[p] as u32);
        }
        result.push(word);
    }

    result
}

/// Build shared, padded message words for a domain-separated hash (2-party).
///
/// Same logic as [`build_domain_message_3`] but for the opened pair `(e, e+1)`.
fn build_domain_message_2(
    domain: Domain,
    data_words: &[[u32; 2]],
    data_byte_len: usize,
    e: usize,
) -> Vec<[u32; 2]> {
    let total_msg_len = 1 + data_byte_len;

    let data_word_count = (data_byte_len + 3) / 4;
    debug_assert!(data_words.len() >= data_word_count);

    // Build the plain padding reference.
    let mut plain = Vec::with_capacity(total_msg_len);
    plain.push(domain as u8);
    plain.resize(total_msg_len, 0);
    let plain_padded = sha256_pad(&plain);
    let padded_byte_len = plain_padded.len() * 4;
    let padded_bytes_ref: Vec<u8> = plain_padded
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();

    // Build flat shared bytes as [u8; 2].
    let mut shared_bytes: Vec<[u8; 2]> = Vec::with_capacity(padded_byte_len);

    // Domain byte: public
    let domain_byte = domain as u8;
    let pub_byte = |b: u8| -> [u8; 2] {
        match e {
            0 => [b, 0],
            2 => [0, b],
            _ => [0, 0],
        }
    };
    shared_bytes.push(pub_byte(domain_byte));

    // Data bytes
    let mut data_byte_idx = 0;
    for word_idx in 0..data_word_count {
        let w = data_words[word_idx];
        let b0 = [(w[0] >> 24) as u8, (w[1] >> 24) as u8];
        let b1 = [(w[0] >> 16) as u8, (w[1] >> 16) as u8];
        let b2 = [(w[0] >> 8) as u8, (w[1] >> 8) as u8];
        let b3 = [w[0] as u8, w[1] as u8];
        for b in [b0, b1, b2, b3] {
            if data_byte_idx < data_byte_len {
                shared_bytes.push(b);
                data_byte_idx += 1;
            }
        }
    }

    // Padding bytes (public)
    for i in total_msg_len..padded_byte_len {
        shared_bytes.push(pub_byte(padded_bytes_ref[i]));
    }

    debug_assert_eq!(shared_bytes.len(), padded_byte_len);

    // Pack to u32 words
    let num_words = padded_byte_len / 4;
    let mut result = Vec::with_capacity(num_words);
    for wi in 0..num_words {
        let b0 = shared_bytes[wi * 4];
        let b1 = shared_bytes[wi * 4 + 1];
        let b2 = shared_bytes[wi * 4 + 2];
        let b3 = shared_bytes[wi * 4 + 3];
        let mut word = [0u32; 2];
        for p in 0..2 {
            word[p] = (b0[p] as u32) << 24
                | (b1[p] as u32) << 16
                | (b2[p] as u32) << 8
                | (b3[p] as u32);
        }
        result.push(word);
    }

    result
}

/// Compute `SHA-256(domain || data)` in 3-party MPC.
///
/// `data_words` are the shared u32 words of the data (big-endian), and
/// `data_byte_len` is the exact number of meaningful data bytes.
fn hash_in_mpc(
    domain: Domain,
    data_words: &[[u32; 3]],
    data_byte_len: usize,
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [[u32; 3]; SHA256_STATE_WORDS] {
    let msg = build_domain_message_3(domain, data_words, data_byte_len);
    sha256_mpc(&msg, tapes, views)
}

/// Compute `SHA-256(domain || data)` in 2-party MPC (verification).
fn hash_in_mpc_verify(
    domain: Domain,
    data_words: &[[u32; 2]],
    data_byte_len: usize,
    e: usize,
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [[u32; 2]; SHA256_STATE_WORDS] {
    let msg = build_domain_message_2(domain, data_words, data_byte_len, e);
    sha256_mpc_verify(&msg, e, tape_e, tape_next, view_e, view_next)
}

// =========================================================================
// Shared-word manipulation helpers
// =========================================================================

/// Flatten an array of 8-word shared hashes into a flat `Vec` of shared words.
fn flatten_words_3(elements: &[[[u32; 3]; SHA256_STATE_WORDS]]) -> Vec<[u32; 3]> {
    let mut out = Vec::with_capacity(elements.len() * SHA256_STATE_WORDS);
    for elem in elements {
        out.extend_from_slice(elem);
    }
    out
}

/// Flatten an array of 8-word shared hashes into a flat `Vec` of shared words (2-party).
fn flatten_words_2(elements: &[[[u32; 2]; SHA256_STATE_WORDS]]) -> Vec<[u32; 2]> {
    let mut out = Vec::with_capacity(elements.len() * SHA256_STATE_WORDS);
    for elem in elements {
        out.extend_from_slice(elem);
    }
    out
}

/// Concatenate two 8-word shared hashes into a 16-word flat slice (3-party).
fn concat_two_hashes_3(
    a: &[[u32; 3]; SHA256_STATE_WORDS],
    b: &[[u32; 3]; SHA256_STATE_WORDS],
) -> Vec<[u32; 3]> {
    let mut out = Vec::with_capacity(2 * SHA256_STATE_WORDS);
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// Concatenate two 8-word shared hashes into a 16-word flat slice (2-party).
fn concat_two_hashes_2(
    a: &[[u32; 2]; SHA256_STATE_WORDS],
    b: &[[u32; 2]; SHA256_STATE_WORDS],
) -> Vec<[u32; 2]> {
    let mut out = Vec::with_capacity(2 * SHA256_STATE_WORDS);
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// Lift a public 32-byte hash into 3-party shares (only party 0 holds it).
#[allow(dead_code)]
pub(crate) fn public_hash_to_shares_3(bytes: &[u8; HASH_LEN]) -> [[u32; 3]; SHA256_STATE_WORDS] {
    let mut out = [[0u32; 3]; SHA256_STATE_WORDS];
    for i in 0..SHA256_STATE_WORDS {
        let word = u32::from_be_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
        out[i] = pub3(word);
    }
    out
}

/// Lift a public 32-byte hash into 2-party shares.
#[allow(dead_code)]
pub(crate) fn public_hash_to_shares_2(
    bytes: &[u8; HASH_LEN],
    e: usize,
) -> [[u32; 2]; SHA256_STATE_WORDS] {
    let mut out = [[0u32; 2]; SHA256_STATE_WORDS];
    for i in 0..SHA256_STATE_WORDS {
        let word = u32::from_be_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
        out[i] = pub2(word, e);
    }
    out
}

/// Build the shared word representation of `sig_element || index_be_bytes`
/// (36 bytes total) from the 8-word shared sig element and the public index.
fn sig_element_with_index_3(
    sig_words: &[[u32; 3]; SHA256_STATE_WORDS],
    index: u32,
) -> (Vec<[u32; 3]>, usize) {
    // 32 bytes of sig element + 4 bytes of index = 36 bytes = 9 words
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(sig_words);
    out.push(pub3(index));
    (out, 36)
}

/// Build the shared word representation of `sig_element || index_be_bytes`
/// (2-party).
fn sig_element_with_index_2(
    sig_words: &[[u32; 2]; SHA256_STATE_WORDS],
    index: u32,
    e: usize,
) -> (Vec<[u32; 2]>, usize) {
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(sig_words);
    out.push(pub2(index, e));
    (out, 36)
}

// =========================================================================
// 3-party circuit evaluation (prover)
// =========================================================================

/// Evaluate the full blind-signature verification circuit with 3-party MPC.
///
/// # Arguments
///
/// * `shared_input` -- The secret witness (WOTS signature + auth path) split
///   into 3-party XOR shares.
/// * `public_input` -- Public inputs (message hash, expected root, leaf index).
/// * `tapes` -- Random tapes for the three parties.
/// * `views` -- Output views for the three parties.
///
/// # Returns
///
/// The shared computed Merkle root as 8 `[u32; 3]` words. The caller should
/// reconstruct each word via XOR and compare against `public_input.expected_root`.
pub fn evaluate_circuit(
    shared_input: &SharedCircuitInput,
    public_input: &CircuitPublicInput,
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [[u32; 3]; SHA256_STATE_WORDS] {
    assert_eq!(shared_input.wots_sig.len(), WOTS_LEN);
    assert_eq!(shared_input.auth_path.len(), TREE_HEIGHT);

    // -----------------------------------------------------------------
    // Step 1: WOTS public-key recovery
    // -----------------------------------------------------------------
    // For each bit i of the message hash:
    //   bit=0 -> pk[i] = SHA-256(WotsChain || sig[i] || i.to_be_bytes())
    //   bit=1 -> pk[i] = sig[i]
    // The message hash is public, so we can branch directly.
    let mut pk_elements: Vec<[[u32; 3]; SHA256_STATE_WORDS]> = Vec::with_capacity(WOTS_LEN);

    for i in 0..WOTS_LEN {
        let bit = util::get_doubled_bit(&public_input.msg_hash, i);
        let pk_i = if bit == 0 {
            // pk[i] = H(WotsChain || sig[i] || i)
            let (data_words, data_len) =
                sig_element_with_index_3(&shared_input.wots_sig[i], i as u32);
            hash_in_mpc(Domain::WotsChain, &data_words, data_len, tapes, views)
        } else {
            // pk[i] = sig[i] (already the public key element)
            shared_input.wots_sig[i]
        };
        pk_elements.push(pk_i);
    }

    // -----------------------------------------------------------------
    // Step 2: Public-key compression
    // -----------------------------------------------------------------
    // compressed_pk = SHA-256(WotsPkCompress || pk[0] || pk[1] || ... || pk[511])
    // Data is 512 * 32 = 16384 bytes.
    let pk_flat = flatten_words_3(&pk_elements);
    let compressed_pk = hash_in_mpc(
        Domain::WotsPkCompress,
        &pk_flat,
        WOTS_LEN * HASH_LEN,
        tapes,
        views,
    );

    // -----------------------------------------------------------------
    // Step 3: Leaf hash
    // -----------------------------------------------------------------
    // leaf = SHA-256(LeafHash || compressed_pk)
    // Data is 32 bytes.
    let leaf = hash_in_mpc(
        Domain::LeafHash,
        &compressed_pk[..],
        HASH_LEN,
        tapes,
        views,
    );

    // -----------------------------------------------------------------
    // Step 4: Merkle path recomputation
    // -----------------------------------------------------------------
    let mut current = leaf;
    let mut index = public_input.leaf_index as usize;

    for level in 0..TREE_HEIGHT {
        let sibling = &shared_input.auth_path[level];
        // Data for MerkleNode hash: left || right (64 bytes total)
        let data_words = if index % 2 == 0 {
            // current is left child
            concat_two_hashes_3(&current, sibling)
        } else {
            // current is right child
            concat_two_hashes_3(sibling, &current)
        };
        current = hash_in_mpc(
            Domain::MerkleNode,
            &data_words,
            2 * HASH_LEN,
            tapes,
            views,
        );
        index /= 2;
    }

    current
}

// =========================================================================
// 2-party circuit evaluation (verifier)
// =========================================================================

/// Evaluate the full blind-signature verification circuit with 2-party MPC
/// (verification variant).
///
/// # Arguments
///
/// * `shared_input` -- The 2-party projection of the secret witness.
/// * `public_input` -- Public inputs (message hash, expected root, leaf index).
/// * `e` -- The challenged party index (0, 1, or 2).
/// * `tape_e` -- Random tape for party `e`.
/// * `tape_next` -- Random tape for party `(e+1)%3`.
/// * `view_e` -- The prover-supplied view for party `e` (read mode).
/// * `view_next` -- The view being recomputed for party `(e+1)%3`.
///
/// # Returns
///
/// The shared computed Merkle root as 8 `[u32; 2]` words.
pub fn evaluate_circuit_verify(
    shared_input: &SharedCircuitInputPair,
    public_input: &CircuitPublicInput,
    e: usize,
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [[u32; 2]; SHA256_STATE_WORDS] {
    assert_eq!(shared_input.wots_sig.len(), WOTS_LEN);
    assert_eq!(shared_input.auth_path.len(), TREE_HEIGHT);

    // Step 1: WOTS public-key recovery
    let mut pk_elements: Vec<[[u32; 2]; SHA256_STATE_WORDS]> = Vec::with_capacity(WOTS_LEN);

    for i in 0..WOTS_LEN {
        let bit = util::get_doubled_bit(&public_input.msg_hash, i);
        let pk_i = if bit == 0 {
            let (data_words, data_len) =
                sig_element_with_index_2(&shared_input.wots_sig[i], i as u32, e);
            hash_in_mpc_verify(
                Domain::WotsChain,
                &data_words,
                data_len,
                e,
                tape_e,
                tape_next,
                view_e,
                view_next,
            )
        } else {
            shared_input.wots_sig[i]
        };
        pk_elements.push(pk_i);
    }

    // Step 2: Public-key compression
    let pk_flat = flatten_words_2(&pk_elements);
    let compressed_pk = hash_in_mpc_verify(
        Domain::WotsPkCompress,
        &pk_flat,
        WOTS_LEN * HASH_LEN,
        e,
        tape_e,
        tape_next,
        view_e,
        view_next,
    );

    // Step 3: Leaf hash
    let leaf = hash_in_mpc_verify(
        Domain::LeafHash,
        &compressed_pk[..],
        HASH_LEN,
        e,
        tape_e,
        tape_next,
        view_e,
        view_next,
    );

    // Step 4: Merkle path recomputation
    let mut current = leaf;
    let mut index = public_input.leaf_index as usize;

    for level in 0..TREE_HEIGHT {
        let sibling = &shared_input.auth_path[level];
        let data_words = if index % 2 == 0 {
            concat_two_hashes_2(&current, sibling)
        } else {
            concat_two_hashes_2(sibling, &current)
        };
        current = hash_in_mpc_verify(
            Domain::MerkleNode,
            &data_words,
            2 * HASH_LEN,
            e,
            tape_e,
            tape_next,
            view_e,
            view_next,
        );
        index /= 2;
    }

    current
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use crate::merkle::tree::build_tree;
    use crate::mpc::shares::reconstruct_u32;
    use crate::params::{NUM_LEAVES, SEED_LEN};
    use crate::wots::keygen::{wots_keygen, wots_pk_to_leaf};
    use crate::wots::sign::wots_sign;

    /// Reconstruct a 32-byte hash from 8 shared u32 words (3-party).
    fn reconstruct_hash_3(words: &[[u32; 3]; SHA256_STATE_WORDS]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        for i in 0..SHA256_STATE_WORDS {
            let val = reconstruct_u32(&words[i]);
            out[4 * i..4 * i + 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    /// Reconstruct a 32-byte hash from 8 shared u32 words (2-party).
    /// Note: only valid for checking partial shares; full reconstruction needs
    /// all 3 parties.
    #[allow(dead_code)]
    fn reconstruct_hash_2(words: &[[u32; 2]; SHA256_STATE_WORDS]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        for i in 0..SHA256_STATE_WORDS {
            let val = words[i][0] ^ words[i][1];
            out[4 * i..4 * i + 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    /// Build a complete test fixture: WOTS keypair, signature, Merkle tree,
    /// auth path, and all inputs needed for the circuit.
    struct TestFixture {
        circuit_input: CircuitInput,
        public_input: CircuitPublicInput,
        expected_root: [u8; HASH_LEN],
    }

    fn make_fixture(leaf_index: u32) -> TestFixture {
        let key_seed = [0x42u8; SEED_LEN];
        let msg = b"test message for blind signature circuit";
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
            expected_root: root,
        }
    }

    /// Run the 3-party circuit and return the reconstructed root and views.
    fn run_circuit_3(
        fixture: &TestFixture,
        tape_seed: u8,
    ) -> (
        [u8; HASH_LEN],
        [View; 3],
        SharedCircuitInput,
    ) {
        let seed = [tape_seed; SEED_LEN];

        // Sharing tapes (round 0)
        let mut share_tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let shared_input = share_circuit_input(&fixture.circuit_input, &mut share_tapes);

        // Circuit tapes (round 1)
        let mut circuit_tapes = [
            LazyTape::new(&seed, 1, 0),
            LazyTape::new(&seed, 1, 1),
            LazyTape::new(&seed, 1, 2),
        ];
        let mut views = [View::new(), View::new(), View::new()];

        let result = evaluate_circuit(
            &shared_input,
            &fixture.public_input,
            &mut circuit_tapes,
            &mut views,
        );

        let root = reconstruct_hash_3(&result);
        (root, views, shared_input)
    }

    // -- Test 1: Circuit roundtrip with valid signature --

    #[test]
    fn test_circuit_roundtrip() {
        let fixture = make_fixture(0);
        let (computed_root, _views, _shared) = run_circuit_3(&fixture, 0xAA);
        assert_eq!(
            computed_root, fixture.expected_root,
            "Circuit-computed Merkle root does not match expected root"
        );
    }

    // -- Test 2: Circuit roundtrip with different leaf indices --

    #[test]
    fn test_circuit_roundtrip_various_leaves() {
        for &leaf_idx in &[0u32, 1, 42, 511, 1023] {
            let fixture = make_fixture(leaf_idx);
            let (computed_root, _views, _shared) = run_circuit_3(&fixture, 0xBB);
            assert_eq!(
                computed_root, fixture.expected_root,
                "Root mismatch for leaf_index={}",
                leaf_idx
            );
        }
    }

    // -- Test 3: 2-party verification consistency --

    #[test]
    fn test_circuit_verify_consistency() {
        let fixture = make_fixture(0);
        let seed = [0xCC_u8; SEED_LEN];

        // --- 3-party prover ---
        let mut share_tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let shared_input = share_circuit_input(&fixture.circuit_input, &mut share_tapes);

        let mut circuit_tapes = [
            LazyTape::new(&seed, 1, 0),
            LazyTape::new(&seed, 1, 1),
            LazyTape::new(&seed, 1, 2),
        ];
        let mut prover_views = [View::new(), View::new(), View::new()];
        let result_3 = evaluate_circuit(
            &shared_input,
            &fixture.public_input,
            &mut circuit_tapes,
            &mut prover_views,
        );

        // --- 2-party verifier for each e ---
        for e in 0..3 {
            let next = (e + 1) % 3;
            let shared_pair = project_shared_input(&shared_input, e);

            let mut tape_e = LazyTape::new(&seed, 1, e as u8);
            let mut tape_next = LazyTape::new(&seed, 1, next as u8);
            let mut view_e = prover_views[e].clone();
            view_e.reset_read();
            let mut view_next = View::new();

            let result_2 = evaluate_circuit_verify(
                &shared_pair,
                &fixture.public_input,
                e,
                &mut tape_e,
                &mut tape_next,
                &mut view_e,
                &mut view_next,
            );

            // Check that the opened shares match.
            for i in 0..SHA256_STATE_WORDS {
                assert_eq!(
                    result_2[i][0], result_3[i][e],
                    "e={}, word={}: party e share mismatch",
                    e, i
                );
                assert_eq!(
                    result_2[i][1], result_3[i][next],
                    "e={}, word={}: party e+1 share mismatch",
                    e, i
                );
            }

            // Check that the recomputed view for party (e+1) matches.
            assert_eq!(
                view_next.outputs,
                prover_views[next].outputs,
                "e={}: view_next does not match prover view for party {}",
                e, next
            );
        }
    }

    // -- Test 4: Wrong signature yields wrong root --

    #[test]
    fn test_circuit_wrong_sig_fails() {
        let fixture = make_fixture(0);

        // Corrupt the first signature element.
        let mut bad_sig = fixture.circuit_input.wots_sig.clone();
        bad_sig[0] = [0xFF; HASH_LEN];

        let bad_input = CircuitInput {
            wots_sig: bad_sig,
            auth_path: fixture.circuit_input.auth_path.clone(),
        };

        let seed = [0xDD_u8; SEED_LEN];
        let mut share_tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let shared_input = share_circuit_input(&bad_input, &mut share_tapes);

        let mut circuit_tapes = [
            LazyTape::new(&seed, 1, 0),
            LazyTape::new(&seed, 1, 1),
            LazyTape::new(&seed, 1, 2),
        ];
        let mut views = [View::new(), View::new(), View::new()];
        let result = evaluate_circuit(
            &shared_input,
            &fixture.public_input,
            &mut circuit_tapes,
            &mut views,
        );

        let bad_root = reconstruct_hash_3(&result);
        assert_ne!(
            bad_root, fixture.expected_root,
            "Corrupted signature should NOT produce the correct Merkle root"
        );
    }

    // -- Test 5: Wrong auth path yields wrong root --

    #[test]
    fn test_circuit_wrong_auth_path_fails() {
        let fixture = make_fixture(0);

        let mut bad_path = fixture.circuit_input.auth_path.clone();
        bad_path[0] = [0xEE; HASH_LEN];

        let bad_input = CircuitInput {
            wots_sig: fixture.circuit_input.wots_sig.clone(),
            auth_path: bad_path,
        };

        let seed = [0xEE_u8; SEED_LEN];
        let mut share_tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let shared_input = share_circuit_input(&bad_input, &mut share_tapes);

        let mut circuit_tapes = [
            LazyTape::new(&seed, 1, 0),
            LazyTape::new(&seed, 1, 1),
            LazyTape::new(&seed, 1, 2),
        ];
        let mut views = [View::new(), View::new(), View::new()];
        let result = evaluate_circuit(
            &shared_input,
            &fixture.public_input,
            &mut circuit_tapes,
            &mut views,
        );

        let bad_root = reconstruct_hash_3(&result);
        assert_ne!(
            bad_root, fixture.expected_root,
            "Corrupted auth path should NOT produce the correct Merkle root"
        );
    }

    // -- Test 6: Domain-separated MPC hash matches plain hash --

    #[test]
    fn test_hash_in_mpc_matches_plain() {
        // Verify that hash_in_mpc(WotsChain, data, ...) produces the same
        // result as hash::hash_with_domain(Domain::WotsChain, data).
        let data = [0x42u8; 36]; // 32 bytes element + 4 bytes index
        let expected = hash::hash_with_domain(Domain::WotsChain, &data);

        let seed = [0xFFu8; SEED_LEN];
        let mut share_tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];

        // Convert data to words and share them.
        let data_words_plain = bytes_to_words(&data);
        let data_words_shared: Vec<[u32; 3]> = data_words_plain
            .iter()
            .map(|&w| {
                shares::share_u32(w, share_tapes[0].next_u32(), share_tapes[1].next_u32())
            })
            .collect();

        let mut circuit_tapes = [
            LazyTape::new(&seed, 1, 0),
            LazyTape::new(&seed, 1, 1),
            LazyTape::new(&seed, 1, 2),
        ];
        let mut views = [View::new(), View::new(), View::new()];

        let result = hash_in_mpc(
            Domain::WotsChain,
            &data_words_shared,
            data.len(),
            &mut circuit_tapes,
            &mut views,
        );

        let got = reconstruct_hash_3(&result);
        assert_eq!(
            got, expected,
            "MPC domain hash does not match plain domain hash"
        );
    }
}
