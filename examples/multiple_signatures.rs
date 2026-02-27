//! Signing multiple messages with one keypair.
//!
//! Each signature consumes one Merkle leaf (1024 total).
//! This example uses reduced ZKBoo rounds for speed.
//!
//! Run with: cargo run --example multiple_signatures

use blindforest::blind::keygen::generate_keypair_from_seed;
use blindforest::blind::user::{user_commit, user_unblind_with_rounds};
use blindforest::params::SEED_LEN;

fn main() {
    let seed = [0x42u8; SEED_LEN];
    let keypair = generate_keypair_from_seed(&seed);
    let mut rng = rand_core::OsRng;

    let messages: &[&[u8]] = &[
        b"Vote for Alice",
        b"Vote for Bob",
        b"Vote for Charlie",
    ];

    // Use 1 ZKBoo round for speed (NOT secure -- use full rounds in production).
    let num_rounds = 1;

    for (i, msg) in messages.iter().enumerate() {
        // BS.Sig1: commit
        let (state, committed) = user_commit(*msg, &mut rng);

        // BS.Sig2: signer signs
        let response = keypair.secret_key.sign_committed(&committed).unwrap();
        println!(
            "Message {}: signed with leaf {} (\"{}\")",
            i,
            response.leaf_index,
            core::str::from_utf8(msg).unwrap()
        );

        // BS.Sig3: unblind (reduced rounds for demo speed)
        let sig = user_unblind_with_rounds(
            &state,
            &keypair.public_key,
            &response,
            num_rounds,
            &mut rng,
        )
        .unwrap();

        // BS.Vfy: verify
        keypair
            .public_key
            .verify_with_rounds(*msg, &sig)
            .unwrap();
        println!("  -> verified (leaf {})", response.leaf_index);
    }

    println!("\nAll {} messages signed and verified.", messages.len());
    println!("Remaining signing capacity: {} leaves", 1024 - messages.len());
}
