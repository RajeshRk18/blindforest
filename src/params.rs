/// Height of the Merkle tree (2^H leaves = max signatures).
pub const TREE_HEIGHT: usize = 10;

/// Number of leaves in the Merkle tree.
pub const NUM_LEAVES: usize = 1 << TREE_HEIGHT;

/// Output length of the hash function in bytes (SHA-256).
pub const HASH_LEN: usize = 32;

/// Number of bits in the hash output.
pub const HASH_BITS: usize = HASH_LEN * 8;

/// WOTS parameter w (Winternitz parameter). w=1 means binary.
pub const WOTS_W: usize = 1;

/// Number of WOTS chain elements.
/// Paper uses doubled message m̂ = (M || M̄) where M̄ is bitwise complement,
/// so WOTS_LEN = 2 * HASH_BITS = 512.
pub const WOTS_LEN: usize = 2 * HASH_BITS;

/// Number of ZKBoo parties (MPC-in-the-head).
pub const NUM_PARTIES: usize = 3;

/// Number of ZKBoo repetition rounds for 128-bit soundness.
/// Soundness error per round is 2/3, so t rounds gives (2/3)^t.
/// For 128-bit security: t >= 128 * ln(2) / ln(3/2) ≈ 219.
pub const NUM_ROUNDS: usize = 219;

/// AES-256 key length in bytes.
pub const AES_KEY_LEN: usize = 32;

/// AES block size in bytes.
pub const AES_BLOCK_LEN: usize = 16;

/// AES-CTR nonce length in bytes.
pub const AES_NONCE_LEN: usize = 16;

/// PRF seed length in bytes.
pub const SEED_LEN: usize = 32;

/// Commitment randomness length in bytes.
pub const COMMITMENT_RAND_LEN: usize = 32;

/// Number of u32 words in a SHA-256 state.
pub const SHA256_STATE_WORDS: usize = 8;

/// Number of rounds in SHA-256 compression.
pub const SHA256_ROUNDS: usize = 64;

/// SHA-256 message schedule length in u32 words.
pub const SHA256_SCHEDULE_LEN: usize = 64;

/// SHA-256 block size in bytes.
pub const SHA256_BLOCK_LEN: usize = 64;
