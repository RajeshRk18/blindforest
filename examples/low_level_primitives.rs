//! Using low-level primitives: WOTS, Merkle trees, commitments, hashing.
//!
//! This demonstrates the building blocks underlying the blind signature scheme.
//!
//! Run with: cargo run --example low_level_primitives

use blindforest::commitment::{self, CommitmentRandomness};
use blindforest::hash::{self, Domain, DomainHasher};
use blindforest::merkle::auth::{recompute_root, verify_auth_path};
use blindforest::merkle::tree::build_tree;
use blindforest::params::{HASH_LEN, NUM_LEAVES, SEED_LEN};
use blindforest::wots::keygen::{wots_keygen, wots_pk_to_leaf};
use blindforest::wots::sign::wots_sign;
use blindforest::wots::verify::wots_verify;

fn main() {
    // =========================================================================
    // Hashing with domain separation
    // =========================================================================
    println!("=== Domain-Separated Hashing ===");

    let data = b"hello world";
    let h1 = hash::hash_with_domain(Domain::Prf, data);
    let h2 = hash::hash_with_domain(Domain::Commitment, data);
    println!("Prf(\"hello world\"): {:02x?}", &h1[..8]);
    println!("Commitment(\"hello world\"): {:02x?}", &h2[..8]);
    assert_ne!(h1, h2, "different domains produce different hashes");

    // Incremental hashing
    let mut hasher = DomainHasher::new(Domain::Prf);
    hasher.update(b"hello ");
    hasher.update(b"world");
    let h3 = hasher.finalize();
    assert_eq!(h1, h3, "incremental and one-shot produce the same hash");
    println!("Incremental hashing matches one-shot: confirmed");

    // =========================================================================
    // Commitment scheme
    // =========================================================================
    println!("\n=== Commitment Scheme ===");

    let msg = b"secret ballot";
    let r = CommitmentRandomness([0xAB; 32]);
    let com = commitment::commit(msg, &r);
    println!("Com(msg, r) = {:02x?}", &com.value[..8]);

    // Verify the commitment
    assert!(commitment::verify_commitment(&com, msg, &r));
    assert!(!commitment::verify_commitment(&com, b"wrong", &r));
    println!("Commitment verification: correct message OK, wrong message rejected");

    // =========================================================================
    // WOTS one-time signature
    // =========================================================================
    println!("\n=== WOTS One-Time Signature ===");

    let seed = [0x42u8; SEED_LEN];
    let leaf_index = 0;

    // Generate a WOTS keypair
    let (sk, pk) = wots_keygen(&seed, leaf_index);
    println!("WOTS public key ({} elements)", pk.elements.len());

    // Sign a message hash
    let msg_hash = hash::hash_raw(b"message to sign");
    let sig = wots_sign(&sk, &msg_hash);
    println!("WOTS signature ({} elements)", sig.elements.len());

    // Verify the signature
    assert!(wots_verify(&pk, &msg_hash, &sig));
    println!("WOTS signature verified: OK");

    // Wrong hash fails
    let wrong_hash = hash::hash_raw(b"wrong message");
    assert!(!wots_verify(&pk, &wrong_hash, &sig));
    println!("WOTS wrong message rejected: OK");

    // =========================================================================
    // Merkle tree
    // =========================================================================
    println!("\n=== Merkle Tree ===");

    // Build a tree from WOTS public keys
    let leaves: Vec<[u8; HASH_LEN]> = (0..NUM_LEAVES)
        .map(|i| {
            let (_, pk) = wots_keygen(&seed, i as u32);
            wots_pk_to_leaf(&pk)
        })
        .collect();

    let tree = build_tree(&leaves);
    let root = tree.root();
    println!("Merkle root ({} leaves): {:02x?}", NUM_LEAVES, &root[..8]);

    // Extract and verify an authentication path
    let idx = 42;
    let path = tree.auth_path(idx);
    println!("Auth path for leaf {}: {} siblings", idx, path.siblings.len());

    let recomputed = recompute_root(&leaves[idx], idx, &path);
    assert_eq!(recomputed, root);
    println!("Recomputed root matches: OK");

    assert!(verify_auth_path(&leaves[idx], idx, &path, &root));
    println!("Auth path verified: OK");

    // Wrong leaf fails
    let wrong_leaf = [0xFF; HASH_LEN];
    assert!(!verify_auth_path(&wrong_leaf, idx, &path, &root));
    println!("Wrong leaf rejected: OK");

    println!("\nAll low-level primitives working correctly.");
}
