//! Basic blind signature: keygen -> commit -> sign -> unblind -> verify.
//!
//! Run with: cargo run --example basic_blind_signature

use blindforest::{generate_keypair, user_commit, user_unblind};

fn main() {
    let mut rng = rand_core::OsRng;

    // 1. Signer generates a keypair (1024 one-time signing leaves).
    println!("Generating keypair...");
    let keypair = generate_keypair(&mut rng);
    println!("Public key root: {:02x?}", &keypair.public_key.root[..8]);

    // 2. User commits to the message (BS.Sig1).
    //    The signer never sees the original message.
    let message = b"Vote for Alice";
    let (user_state, committed) = user_commit(message, &mut rng);
    println!("Committed to message (commitment sent to signer)");

    // 3. Signer signs the commitment (BS.Sig2).
    //    The signer produces a WOTS signature + Merkle auth path.
    let response = keypair
        .secret_key
        .sign_committed(&committed)
        .expect("signing failed");
    println!("Signer responded (leaf index: {})", response.leaf_index);

    // 4. User unblinds the response to produce a blind signature (BS.Sig3).
    //    This generates a ZKBoo proof (expensive, ~219 rounds).
    println!("Unblinding (generating ZKBoo proof with 219 rounds)...");
    println!("This will take several minutes...");
    let signature = user_unblind(&user_state, &keypair.public_key, &response, &mut rng)
        .expect("unblinding failed");
    println!("Blind signature produced ({} proof rounds)", signature.proof.num_rounds());

    // 5. Anyone can verify the signature against the public key (BS.Vfy).
    //    The verifier learns nothing about the signer's choice of leaf.
    keypair
        .public_key
        .verify(message, &signature)
        .expect("verification failed");
    println!("Signature verified successfully!");
}
