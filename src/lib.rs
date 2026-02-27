#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod params;
pub mod hash;
pub mod prf;
pub mod commitment;
pub mod util;

pub mod wots;
pub mod merkle;
pub mod mpc;
pub mod zkboo;
pub mod blind;

// Core error types
pub use error::{Error, Result};

// Primary public API re-exports
pub use blind::types::{
    BlindSigKeyPair, BlindSigPublicKey, BlindSigSecretKey,
    BlindSignature, CommittedMessage, SignerResponse, UserState,
};
pub use blind::keygen::{generate_keypair, generate_keypair_from_seed};
pub use blind::user::{user_commit, user_unblind};
