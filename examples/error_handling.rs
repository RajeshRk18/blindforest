//! Error handling: wrong message, wrong key, and error types.
//!
//! Run with: cargo run --example error_handling

use blindforest::blind::keygen::generate_keypair_from_seed;
use blindforest::blind::user::{user_commit, user_unblind_with_rounds};
use blindforest::error::Error;
use blindforest::params::SEED_LEN;

fn main() {
    let mut rng = rand_core::OsRng;

    // --- 1. Wrong Message ---
    println!("=== Wrong Message ===");
    {
        let seed = [0x42u8; SEED_LEN];
        let keypair = generate_keypair_from_seed(&seed);

        let (state, committed) = user_commit(b"correct message", &mut rng);
        let response = keypair.secret_key.sign_committed(&committed).unwrap();
        let sig = user_unblind_with_rounds(
            &state,
            &keypair.public_key,
            &response,
            1,
            &mut rng,
        )
        .unwrap();

        // Verify with the correct message: OK
        assert!(keypair
            .public_key
            .verify_with_rounds(b"correct message", &sig)
            .is_ok());
        println!("Correct message: OK");

        // Verify with a wrong message: VerificationFailed
        match keypair
            .public_key
            .verify_with_rounds(b"wrong message", &sig)
        {
            Err(Error::VerificationFailed) => {
                println!("Wrong message: VerificationFailed (as expected)")
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    // --- 2. Wrong Public Key ---
    println!("\n=== Wrong Public Key ===");
    {
        let keypair1 = generate_keypair_from_seed(&[0x42u8; SEED_LEN]);
        let keypair2 = generate_keypair_from_seed(&[0x43u8; SEED_LEN]);

        let (state, committed) = user_commit(b"hello", &mut rng);
        let response = keypair1.secret_key.sign_committed(&committed).unwrap();
        let sig = user_unblind_with_rounds(
            &state,
            &keypair1.public_key,
            &response,
            1,
            &mut rng,
        )
        .unwrap();

        // Verify against the correct key: OK
        assert!(keypair1
            .public_key
            .verify_with_rounds(b"hello", &sig)
            .is_ok());
        println!("Correct key: OK");

        // Verify against a different key: fails
        match keypair2.public_key.verify_with_rounds(b"hello", &sig) {
            Err(_) => println!("Wrong key: verification failed (as expected)"),
            Ok(()) => panic!("should not verify against wrong key"),
        }
    }

    // --- 3. Key Exhaustion ---
    println!("\n=== Key Exhaustion ===");
    println!("Each keypair supports up to 1024 signatures (NUM_LEAVES).");
    println!("After all leaves are used, sign_committed() returns Error::KeyExhausted.");
    println!("(Skipping live demo -- signing 1024 times is slow.)");
    println!("Usage pattern:");
    println!("  match sk.sign_committed(&committed) {{");
    println!("      Ok(response) => {{ /* success */ }}");
    println!("      Err(Error::KeyExhausted) => {{ /* generate new keypair */ }}");
    println!("      Err(e) => {{ /* other error */ }}");
    println!("  }}");

    // --- 4. Matching all error variants ---
    println!("\n=== Error Variants ===");
    let errors = [
        Error::VerificationFailed,
        Error::KeyExhausted,
        Error::InvalidInput,
        Error::InvalidAuthPath,
        Error::CommitmentMismatch,
        Error::ProofFormat,
    ];
    for e in &errors {
        println!("  {}", e);
    }

    println!("\nAll error cases demonstrated.");
}
