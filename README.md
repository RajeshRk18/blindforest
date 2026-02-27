# blindforest

Hash-based blind signatures using ZKBoo proofs. Post-quantum secure, built entirely on symmetric primitives (SHA-256, AES).

Based on [Hash-Based Blind Signatures: First Steps](https://eprint.iacr.org/2025/2097) by Javier Herranz and Hugo Louiso.

## How it works

**Key setup.** The signer generates a Merkle tree over 1024 WOTS (Winternitz One-Time Signature) leaf keys. The tree root is the public key. Each leaf can sign exactly one message.

**Blind signing protocol.** The user and signer interact so that the signer signs a message *without ever seeing it*:

1. **BS.Sig1 — Commit.** The user computes `Com(msg; r)` using a hash-based commitment and sends it to the signer. The randomness `r` hides the message.
2. **BS.Sig2 — Sign.** The signer WOTS-signs the commitment value using the next available leaf, and returns the WOTS signature + Merkle authentication path.
3. **BS.Sig3 — Unblind.** The user verifies the signer's response, then generates a ZKBoo proof (MPC-in-the-head) demonstrating knowledge of a valid WOTS signature and Merkle path — without revealing the leaf index or signature itself.

**Verification.** Anyone can verify the blind signature given the message, signature, and public key. The verifier recomputes the commitment from the message and revealed randomness, then checks the ZKBoo proof against the Merkle root. The verifier learns nothing about which leaf was used.

```
User                          Signer
  |                             |
  |--- Com(msg; r) ----------->|   BS.Sig1: commitment hides the message
  |<-- wots_sig + auth_path ---|   BS.Sig2: signer signs without seeing msg
  |                             |
  |  ZKBoo prove               |   BS.Sig3: user produces blind signature
  |                             |
  Anyone can verify(msg, sig, pk)   BS.Vfy
```

## Parameters

| Parameter | Value |
|-----------|-------|
| Hash | SHA-256 |
| WOTS variant | w=1 (binary), doubled (M &#124;&#124; M̄), 512 chains |
| Merkle tree | 2^10 = 1024 leaves |
| ZKBoo rounds | 219 (128-bit soundness) |
| MPC parties | 3 |

## Sizes (Paper Table 3)

Measured on Apple M4, 24 GB RAM, macOS 26.3.

| Component | Size | Notes |
|-----------|------|-------|
| Public key (pk) | 32 B | Merkle root |
| Secret key (sk) | 36 B | Seed (32) + counter (4) |
| MSS signature (Sigma) | 16,708 B (16.3 KB) | Matches paper Table 3 |
| &emsp; WOTS signature | 16,384 B | 512 elements x 32 B |
| &emsp; Auth path | 320 B | 10 siblings x 32 B |
| &emsp; Leaf index | 4 B | u32 |
| Blind signature (estimated) | ~35.0 MB | 219 ZKBoo rounds |

### Breakdown per ZKBoo round

| Component | Size |
|-----------|------|
| Round commitment | 96 B (3 x 32 B) |
| Round proof | ~163.7 KB |
| &emsp; View outputs | ~131.0 KB (33,536 u32 words) |
| &emsp; Input shares (2 parties) | ~32.3 KB |
| &emsp; Seeds + challenge + output share | 97 B |
| SHA-256 compressions per round | ~524 |

Run `cargo run --example measure_sizes` to reproduce.

## Benchmarks

Measured on Apple M4, 24 GB RAM, macOS 26.3. Release mode (`cargo bench`).

### Protocol operations

| Operation | Time |
|-----------|------|
| Keygen (1024 leaves) | 526.40 ms |
| User commit | 189.79 ns |
| Signer sign (WOTS + auth path) | 518.83 us |
| ZKBoo prove (1 round) | 4.55 s |
| ZKBoo verify (1 round) | 2.97 s |
| End-to-end (1 round) | 7.52 s |
| End-to-end (219 rounds, estimated) | ~27.4 min |

### Primitives

| Operation | Time |
|-----------|------|
| SHA-256 raw (64 B) | 230.31 ns |
| SHA-256 domain-separated (64 B) | 222.07 ns |
| SHA-256 domain hasher (8192 B) | 14.21 us |
| Commitment (commit) | 225.11 ns |
| Commitment (verify) | 242.95 ns |
| PRF generate (32 B) | 822.52 ns |
| PRF fill (1024 B) | 4.25 us |

### WOTS

| Operation | Time |
|-----------|------|
| Keygen (512 chains) | 487.88 us |
| Sign | 30.01 us |
| Verify | 30.65 us |
| Recover PK | 30.07 us |
| PK to leaf | 28.78 us |

### Merkle tree

| Operation | Time |
|-----------|------|
| Build tree (1024 leaves) | 229.83 us |
| Auth path extract | 20.46 ns |
| Recompute root | 2.30 us |
| Verify auth path | 2.30 us |

### MPC internals

| Operation | Time |
|-----------|------|
| XOR gate | 1.45 ns |
| NOT gate | 1.05 ns |
| AND gate | 1.79 us |
| ADD gate | 14.42 us |
| Ch function | 1.80 us |
| Maj function | 1.81 us |
| SHA-256 compress (1 block, MPC) | 7.64 ms |
| SHA-256 full (1 block, MPC) | 7.66 ms |
| View commit (10k outputs) | 71.85 us |
| Tape stream (1000 u32) | 65.23 us |
| Fiat-Shamir challenge (219 rounds) | 41.16 us |
| Share circuit input | 558.82 us |
| Evaluate circuit (1 round) | 4.10 s |

Run `cargo bench` to reproduce.

## Usage

```rust
use blindforest::{generate_keypair, user_commit, user_unblind};

let mut rng = rand_core::OsRng;

// Signer: generate keypair (1024 one-time leaves)
let keypair = generate_keypair(&mut rng);

// User: commit to a message
let message = b"Vote for Alice";
let (state, committed) = user_commit(message, &mut rng);

// Signer: sign the commitment (never sees the message)
let response = keypair.secret_key.sign_committed(&committed).unwrap();

// User: unblind to produce the blind signature
let signature = user_unblind(&state, &keypair.public_key, &response, &mut rng).unwrap();

// Anyone: verify
keypair.public_key.verify(message, &signature).unwrap();
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Standard library support |
| `parallel` | Parallel proof generation via Rayon |

`no_std` compatible — disable default features:

```toml
blindforest = { version = "0.1", default-features = false }
```

## Running

```sh
cargo run --example basic_blind_signature
cargo test
cargo bench
```

## License

MIT
