//! Measure serialized sizes and compare against paper Table 3.
//!
//! Run with: cargo run --example measure_sizes
//!
//! This only generates the MSS-layer components (keygen + commit + sign)
//! and estimates the final blind signature size from structural parameters.
//! A full unblind would take too long for a quick measurement.

use blindforest::params::{
    COMMITMENT_RAND_LEN, HASH_LEN, NUM_ROUNDS, SEED_LEN, SHA256_STATE_WORDS, TREE_HEIGHT,
    WOTS_LEN,
};
use blindforest::{generate_keypair, user_commit};

fn main() {
    let mut rng = rand_core::OsRng;

    // 1. Keygen
    let keypair = generate_keypair(&mut rng);

    // 2. User commits
    let message = b"Vote for Alice";
    let (_user_state, committed) = user_commit(message, &mut rng);

    // 3. Signer signs the commitment (produces WOTS sig + auth path)
    let response = keypair
        .secret_key
        .sign_committed(&committed)
        .expect("signing failed");

    // ---- Measure sizes ----

    let pk_size = HASH_LEN; // Merkle root
    let sk_size = SEED_LEN + 4; // seed + counter

    let mss_sig_size = response.serialized_size();
    let mss_wots_sig = response.wots_sig.serialized_size();
    let mss_auth_path = response.auth_path.siblings.len() * HASH_LEN;
    let mss_leaf_index = 4_usize;

    // Estimate ZKBoo proof size from structural parameters.
    //
    // The circuit evaluates ~524 SHA-256 compressions:
    //   - 256 WOTS chain hashes (exactly half of 512 doubled bits)
    //   - ~8 pk-compression compressions (16385 bytes padded / 64)
    //   - 1 leaf hash compression
    //   - 10 Merkle-node compressions
    //
    // Each SHA-256 compression has 64 rounds, each round's AND gate produces
    // 1 u32 output per view. That's ~64 * 524 = 33,536 u32 outputs per view.
    // But the exact count depends on the message hash bits.
    //
    // For size estimation, we compute based on the actual response.
    // In practice, the number of compressions is:
    //   chain_hashes (256) + pk_compress_blocks + 1 (leaf) + 10 (merkle)
    let pk_compress_msg_bytes = 1 + WOTS_LEN * HASH_LEN; // domain byte + data
    let pk_compress_blocks = (pk_compress_msg_bytes + 9 + 63) / 64; // SHA-256 padding
    let num_compressions = 256 + pk_compress_blocks + 1 + TREE_HEIGHT;
    let view_outputs_per_compression = 64_usize; // one AND-gate output per SHA-256 round
    let estimated_view_outputs = num_compressions * view_outputs_per_compression;
    let estimated_view_bytes = estimated_view_outputs * 4;

    // Per-round proof size:
    //   e (1) + seed_e (32) + seed_next (32) + view_e + input_share_e + input_share_next + output_share_third (32)
    // Input shares: (WOTS_LEN + TREE_HEIGHT) elements * SHA256_STATE_WORDS words * 4 bytes
    let input_share_words = (WOTS_LEN + TREE_HEIGHT) * SHA256_STATE_WORDS;
    let per_round_proof = 1 + SEED_LEN + SEED_LEN + estimated_view_bytes
        + input_share_words * 4  // input_share_e
        + input_share_words * 4  // input_share_next
        + SHA256_STATE_WORDS * 4; // output_share_third

    // Per-round commitment: 3 * HASH_LEN
    let per_round_commitment = 3 * HASH_LEN;

    let estimated_zkboo_proof = NUM_ROUNDS * (per_round_proof + per_round_commitment);
    let estimated_blind_sig = COMMITMENT_RAND_LEN + estimated_zkboo_proof + 4;

    // ---- Print table ----

    println!("=== BlindForest Size Report ===");
    println!();
    println!("--- Parameters ---");
    println!("  WOTS_LEN (doubled):    {}", WOTS_LEN);
    println!("  TREE_HEIGHT:           {}", TREE_HEIGHT);
    println!("  NUM_ROUNDS (ZKBoo):    {}", NUM_ROUNDS);
    println!("  Est. SHA-256 compressions per round: {}", num_compressions);
    println!("  Est. view outputs per round:         {}", estimated_view_outputs);
    println!();
    println!("--- MSS Layer (Table 3) ---");
    println!("  pk (Merkle root):       {:>8} B", pk_size);
    println!("  sk (seed + counter):    {:>8} B", sk_size);
    println!("  MSS sig (Sigma):        {:>8} B  ({:.1} KB)", mss_sig_size, mss_sig_size as f64 / 1024.0);
    println!("    WOTS sig ({} x {}):  {:>8} B", WOTS_LEN, HASH_LEN, mss_wots_sig);
    println!("    Auth path ({} x {}):  {:>8} B", TREE_HEIGHT, HASH_LEN, mss_auth_path);
    println!("    Leaf index:           {:>8} B", mss_leaf_index);
    println!();
    println!("--- Paper Table 3 Expected ---");
    println!("  pk:                     {:>8} B", 32);
    println!("  sk:                     {:>8} B", 36);
    println!("  MSS sig:                {:>8} B  (16.7 KB)", 16708);
    println!();
    println!("--- Final Blind Signature (estimated) ---");
    println!("  Per-round commitment:   {:>8} B", per_round_commitment);
    println!("  Per-round proof:        {:>8} B  ({:.1} KB)", per_round_proof, per_round_proof as f64 / 1024.0);
    println!("  ZKBoo proof (all rounds): {:>12} B  ({:.1} MB)", estimated_zkboo_proof, estimated_zkboo_proof as f64 / (1024.0 * 1024.0));
    println!("  Total blind sig:        {:>12} B  ({:.1} MB)", estimated_blind_sig, estimated_blind_sig as f64 / (1024.0 * 1024.0));
}
