//! Deterministic key generation from a fixed seed.
//!
//! Useful for testing or when keys must be reproducible from a master secret.
//!
//! Run with: cargo run --example deterministic_keygen

use blindforest::generate_keypair_from_seed;
use blindforest::params::SEED_LEN;

fn main() {
    // A fixed 32-byte seed produces the same keypair every time.
    let seed = [0x42u8; SEED_LEN];

    println!("Generating keypair from seed...");
    let kp1 = generate_keypair_from_seed(&seed);
    let kp2 = generate_keypair_from_seed(&seed);

    assert_eq!(kp1.public_key.root, kp2.public_key.root);
    println!("Public key root: {:02x?}", &kp1.public_key.root[..8]);
    println!("Same seed -> same keypair: confirmed");

    // A different seed produces a different keypair.
    let other_seed = [0x43u8; SEED_LEN];
    let kp3 = generate_keypair_from_seed(&other_seed);
    assert_ne!(kp1.public_key.root, kp3.public_key.root);
    println!("Different seed -> different keypair: confirmed");
}
