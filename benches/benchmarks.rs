use criterion::{black_box, criterion_group, criterion_main, Criterion};

use blindforest::params::{HASH_LEN, NUM_LEAVES, SEED_LEN};

// =========================================================================
// Hash benchmarks
// =========================================================================

fn bench_hash(c: &mut Criterion) {
    use blindforest::hash::{self, Domain, DomainHasher};

    let mut group = c.benchmark_group("hash");
    let data = [0xABu8; 64];

    group.bench_function("hash_raw_64B", |b| {
        b.iter(|| hash::hash_raw(black_box(&data)))
    });

    group.bench_function("hash_with_domain_64B", |b| {
        b.iter(|| hash::hash_with_domain(Domain::MerkleNode, black_box(&data)))
    });

    group.bench_function("hash_with_domain2_32B+32B", |b| {
        let a = [0xAAu8; 32];
        let b_data = [0xBBu8; 32];
        b.iter(|| hash::hash_with_domain2(Domain::MerkleNode, black_box(&a), black_box(&b_data)))
    });

    group.bench_function("domain_hasher_8192B", |b| {
        let big = vec![0x42u8; 8192];
        b.iter(|| {
            let mut h = DomainHasher::new(Domain::WotsPkCompress);
            h.update(black_box(&big));
            h.finalize()
        })
    });

    group.finish();
}

// =========================================================================
// PRF benchmarks
// =========================================================================

fn bench_prf(c: &mut Criterion) {
    use blindforest::prf::Prf;

    let mut group = c.benchmark_group("prf");
    let seed = [0x42u8; SEED_LEN];

    group.bench_function("generate_32B", |b| {
        b.iter(|| {
            let mut prf = Prf::for_wots(&seed, 0, 0);
            prf.generate_hash()
        })
    });

    group.bench_function("generate_u32", |b| {
        b.iter(|| {
            let mut prf = Prf::for_tape(&seed, 0, 0);
            prf.generate_u32()
        })
    });

    group.bench_function("fill_1024B", |b| {
        let mut buf = [0u8; 1024];
        b.iter(|| {
            let mut prf = Prf::for_tape(&seed, 0, 0);
            prf.fill(black_box(&mut buf));
        })
    });

    group.finish();
}

// =========================================================================
// Commitment benchmarks
// =========================================================================

fn bench_commitment(c: &mut Criterion) {
    use blindforest::commitment::{self, CommitmentRandomness};

    let mut group = c.benchmark_group("commitment");
    let msg = b"hello world blind signature benchmark message";
    let r = CommitmentRandomness([0x42u8; 32]);

    group.bench_function("commit", |b| {
        b.iter(|| commitment::commit(black_box(msg), black_box(&r)))
    });

    let com = commitment::commit(msg, &r);
    group.bench_function("verify_commitment", |b| {
        b.iter(|| commitment::verify_commitment(black_box(&com), black_box(msg), black_box(&r)))
    });

    group.finish();
}

// =========================================================================
// WOTS benchmarks
// =========================================================================

fn bench_wots(c: &mut Criterion) {
    use blindforest::wots::keygen::{wots_keygen, wots_pk_to_leaf};
    use blindforest::wots::sign::wots_sign;
    use blindforest::wots::verify::{wots_recover_pk, wots_verify};
    use blindforest::hash;

    let mut group = c.benchmark_group("wots");
    let seed = [0x42u8; SEED_LEN];

    group.bench_function("keygen", |b| {
        b.iter(|| wots_keygen(black_box(&seed), black_box(0)))
    });

    let (sk, pk) = wots_keygen(&seed, 0);
    let msg_hash = hash::hash_raw(b"benchmark message");

    group.bench_function("sign", |b| {
        b.iter(|| wots_sign(black_box(&sk), black_box(&msg_hash)))
    });

    let sig = wots_sign(&sk, &msg_hash);

    group.bench_function("verify", |b| {
        b.iter(|| wots_verify(black_box(&pk), black_box(&msg_hash), black_box(&sig)))
    });

    group.bench_function("recover_pk", |b| {
        b.iter(|| wots_recover_pk(black_box(&msg_hash), black_box(&sig)))
    });

    group.bench_function("pk_to_leaf", |b| {
        b.iter(|| wots_pk_to_leaf(black_box(&pk)))
    });

    group.finish();
}

// =========================================================================
// Merkle tree benchmarks
// =========================================================================

fn bench_merkle(c: &mut Criterion) {
    use blindforest::merkle::tree::build_tree;
    use blindforest::merkle::auth::{recompute_root, verify_auth_path};
    use blindforest::wots::keygen::{wots_keygen, wots_pk_to_leaf};

    let mut group = c.benchmark_group("merkle");
    let seed = [0x42u8; SEED_LEN];

    // Pre-compute leaves
    let leaves: Vec<[u8; HASH_LEN]> = (0..NUM_LEAVES)
        .map(|i| {
            let (_, pk) = wots_keygen(&seed, i as u32);
            wots_pk_to_leaf(&pk)
        })
        .collect();

    group.bench_function("build_tree_1024_leaves", |b| {
        b.iter(|| build_tree(black_box(&leaves)))
    });

    let tree = build_tree(&leaves);
    let root = tree.root();

    group.bench_function("auth_path_extract", |b| {
        b.iter(|| tree.auth_path(black_box(42)))
    });

    let path = tree.auth_path(42);

    group.bench_function("recompute_root", |b| {
        b.iter(|| recompute_root(black_box(&leaves[42]), black_box(42), black_box(&path)))
    });

    group.bench_function("verify_auth_path", |b| {
        b.iter(|| {
            verify_auth_path(
                black_box(&leaves[42]),
                black_box(42),
                black_box(&path),
                black_box(&root),
            )
        })
    });

    group.finish();
}

// =========================================================================
// MPC gate benchmarks
// =========================================================================

fn bench_mpc_gates(c: &mut Criterion) {
    use blindforest::mpc::gates;
    use blindforest::mpc::shares::share_u32;
    use blindforest::mpc::tape::LazyTape;
    use blindforest::mpc::view::View;

    let mut group = c.benchmark_group("mpc_gates");
    let seed = [0x42u8; SEED_LEN];

    let a = share_u32(0xDEADBEEF, 0x11111111, 0x22222222);
    let b = share_u32(0xCAFEBABE, 0x33333333, 0x44444444);

    group.bench_function("xor", |b_bench| {
        b_bench.iter(|| gates::xor(black_box(a), black_box(b)))
    });

    group.bench_function("not", |b_bench| {
        b_bench.iter(|| gates::not(black_box(a)))
    });

    group.bench_function("and", |b_bench| {
        b_bench.iter(|| {
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = [View::new(), View::new(), View::new()];
            gates::and(black_box(a), black_box(b), &mut tapes, &mut views)
        })
    });

    group.bench_function("add", |b_bench| {
        b_bench.iter(|| {
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = [View::new(), View::new(), View::new()];
            gates::add(black_box(a), black_box(b), &mut tapes, &mut views)
        })
    });

    group.bench_function("ch", |b_bench| {
        let g = share_u32(0x12345678, 0x55555555, 0x66666666);
        b_bench.iter(|| {
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = [View::new(), View::new(), View::new()];
            gates::ch(black_box(a), black_box(b), black_box(g), &mut tapes, &mut views)
        })
    });

    group.bench_function("maj", |b_bench| {
        let g = share_u32(0x12345678, 0x55555555, 0x66666666);
        b_bench.iter(|| {
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = [View::new(), View::new(), View::new()];
            gates::maj(black_box(a), black_box(b), black_box(g), &mut tapes, &mut views)
        })
    });

    group.finish();
}

// =========================================================================
// MPC SHA-256 circuit benchmarks
// =========================================================================

fn bench_mpc_sha256(c: &mut Criterion) {
    use blindforest::mpc::sha256_circuit::{sha256_compress, sha256_pad, sha256_mpc};
    use blindforest::mpc::tape::LazyTape;
    use blindforest::mpc::view::View;
    use blindforest::mpc::shares::share_u32;

    let mut group = c.benchmark_group("mpc_sha256");
    let seed = [0x42u8; SEED_LEN];

    // Benchmark sha256_pad
    group.bench_function("pad_55B", |b| {
        let data = vec![0x42u8; 55];
        b.iter(|| sha256_pad(black_box(&data)))
    });

    // Benchmark single compress (one block)
    group.bench_function("compress_1_block", |b| {
        // Create shared IV and block
        let iv: [[u32; 3]; 8] = core::array::from_fn(|_| [0u32; 3]);
        let block: [[u32; 3]; 16] = core::array::from_fn(|j| share_u32(j as u32, 0x11, 0x22));
        b.iter(|| {
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = [View::new(), View::new(), View::new()];
            sha256_compress(
                black_box(&iv),
                black_box(&block),
                &mut tapes,
                &mut views,
            )
        })
    });

    // Benchmark full MPC SHA-256 (short message → 1 block)
    group.bench_function("sha256_mpc_1_block", |b| {
        let padded = sha256_pad(b"hello world");
        let shared: Vec<[u32; 3]> = padded.iter().map(|&w| share_u32(w, 0x11, 0x22)).collect();
        b.iter(|| {
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = [View::new(), View::new(), View::new()];
            sha256_mpc(black_box(&shared), &mut tapes, &mut views)
        })
    });

    group.sample_size(10);
    group.finish();
}

// =========================================================================
// MPC circuit benchmarks (full verification circuit)
// =========================================================================

fn bench_mpc_circuit(c: &mut Criterion) {
    use blindforest::mpc::circuit::{
        CircuitInput, CircuitPublicInput,
        evaluate_circuit, share_circuit_input,
    };
    use blindforest::mpc::tape::LazyTape;
    use blindforest::mpc::view::View;
    use blindforest::wots::keygen::{wots_keygen, wots_pk_to_leaf};
    use blindforest::wots::sign::wots_sign;
    use blindforest::merkle::tree::build_tree;
    use blindforest::hash;

    let mut group = c.benchmark_group("mpc_circuit");
    group.sample_size(10);

    let key_seed = [0x42u8; SEED_LEN];
    let msg_hash = hash::hash_raw(b"benchmark message");
    let leaf_index = 0u32;

    // Pre-build Merkle tree
    let mut leaves = Vec::with_capacity(NUM_LEAVES);
    for i in 0..NUM_LEAVES {
        let (_, pk) = wots_keygen(&key_seed, i as u32);
        leaves.push(wots_pk_to_leaf(&pk));
    }
    let tree = build_tree(&leaves);
    let root = tree.root();

    // Create circuit inputs
    let (sk, _) = wots_keygen(&key_seed, leaf_index);
    let sig = wots_sign(&sk, &msg_hash);
    let auth_path = tree.auth_path(leaf_index as usize);

    let circuit_input = CircuitInput {
        wots_sig: sig.elements.clone(),
        auth_path: auth_path.siblings.clone(),
    };
    let public_input = CircuitPublicInput {
        msg_hash,
        expected_root: root,
        leaf_index,
    };

    // Benchmark input sharing
    group.bench_function("share_circuit_input", |b| {
        let tape_seed = [0xABu8; SEED_LEN];
        b.iter(|| {
            let mut tapes = [
                LazyTape::new(&tape_seed, 0, 0),
                LazyTape::new(&tape_seed, 0, 1),
                LazyTape::new(&tape_seed, 0, 2),
            ];
            share_circuit_input(black_box(&circuit_input), &mut tapes)
        })
    });

    // Benchmark full circuit evaluation (1 round)
    group.bench_function("evaluate_circuit_1_round", |b| {
        let tape_seed = [0xABu8; SEED_LEN];
        b.iter(|| {
            let mut tapes = [
                LazyTape::new(&tape_seed, 0, 0),
                LazyTape::new(&tape_seed, 0, 1),
                LazyTape::new(&tape_seed, 0, 2),
            ];
            let shared = share_circuit_input(&circuit_input, &mut tapes);
            let mut views = [View::new(), View::new(), View::new()];
            evaluate_circuit(
                black_box(&shared),
                black_box(&public_input),
                &mut tapes,
                &mut views,
            )
        })
    });

    group.finish();
}

// =========================================================================
// ZKBoo benchmarks
// =========================================================================

fn bench_zkboo(c: &mut Criterion) {
    use blindforest::mpc::circuit::{CircuitInput, CircuitPublicInput};
    use blindforest::zkboo::prover::prove_with_rounds;
    use blindforest::zkboo::verifier::verify_with_rounds;
    use blindforest::wots::keygen::{wots_keygen, wots_pk_to_leaf};
    use blindforest::wots::sign::wots_sign;
    use blindforest::merkle::tree::build_tree;
    use blindforest::hash;

    let mut group = c.benchmark_group("zkboo");
    group.sample_size(10);

    let key_seed = [0x42u8; SEED_LEN];
    let msg_hash = hash::hash_raw(b"benchmark message");

    // Build tree
    let mut leaves = Vec::with_capacity(NUM_LEAVES);
    for i in 0..NUM_LEAVES {
        let (_, pk) = wots_keygen(&key_seed, i as u32);
        leaves.push(wots_pk_to_leaf(&pk));
    }
    let tree = build_tree(&leaves);
    let root = tree.root();

    let (sk, _) = wots_keygen(&key_seed, 0);
    let sig = wots_sign(&sk, &msg_hash);
    let auth_path = tree.auth_path(0);

    let circuit_input = CircuitInput {
        wots_sig: sig.elements.clone(),
        auth_path: auth_path.siblings.clone(),
    };
    let public_input = CircuitPublicInput {
        msg_hash,
        expected_root: root,
        leaf_index: 0,
    };

    // Benchmark prove with 1 round
    group.bench_function("prove_1_round", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| {
            prove_with_rounds(
                black_box(&circuit_input),
                black_box(&public_input),
                1,
                &mut rng,
            )
            .unwrap()
        })
    });

    // Benchmark verify with 1 round
    let mut rng = rand::thread_rng();
    let proof_1 = prove_with_rounds(&circuit_input, &public_input, 1, &mut rng).unwrap();

    group.bench_function("verify_1_round", |b| {
        b.iter(|| {
            verify_with_rounds(black_box(&proof_1), black_box(&public_input)).unwrap()
        })
    });

    group.finish();
}

// =========================================================================
// Blind signature protocol benchmarks
// =========================================================================

fn bench_blind_sig(c: &mut Criterion) {
    use blindforest::blind::keygen::generate_keypair_from_seed;
    use blindforest::blind::user::{user_commit, user_unblind_with_rounds};

    let mut group = c.benchmark_group("blind_sig");

    let seed = [0x42u8; SEED_LEN];

    // Benchmark keygen
    group.sample_size(10);
    group.bench_function("keygen", |b| {
        b.iter(|| generate_keypair_from_seed(black_box(&seed)))
    });

    // Benchmark user commit (cheap)
    group.sample_size(100);
    group.bench_function("user_commit", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| user_commit(black_box(b"benchmark message"), &mut rng))
    });

    // Benchmark signer sign_committed (cheap)
    // Fresh keypair per batch to avoid leaf exhaustion (1024 leaves available)
    group.bench_function("signer_sign_committed", |b| {
        let mut rng = rand::thread_rng();
        b.iter_custom(|iters| {
            let kp = generate_keypair_from_seed(&seed);
            let start = std::time::Instant::now();
            for _ in 0..iters.min(1024) {
                let (_, committed) = user_commit(b"msg", &mut rng);
                let _ = kp.secret_key.sign_committed(black_box(&committed));
            }
            start.elapsed()
        })
    });

    // Benchmark full protocol (1 round ZKBoo) - this is expensive
    group.sample_size(10);
    group.bench_function("e2e_1_round", |b| {
        let mut rng = rand::thread_rng();
        b.iter_custom(|iters| {
            let kp = generate_keypair_from_seed(&seed);
            let start = std::time::Instant::now();
            for _ in 0..iters.min(1024) {
                let message = b"benchmark blind signature message";
                let (state, committed) = user_commit(message, &mut rng);
                let response = kp.secret_key.sign_committed(&committed).unwrap();
                let sig = user_unblind_with_rounds(
                    &state,
                    &kp.public_key,
                    &response,
                    1,
                    &mut rng,
                )
                .unwrap();
                kp.public_key.verify_with_rounds(message, &sig).unwrap();
            }
            start.elapsed()
        })
    });

    group.finish();
}

// =========================================================================
// View commit benchmark
// =========================================================================

fn bench_view(c: &mut Criterion) {
    use blindforest::mpc::view::View;

    let mut group = c.benchmark_group("view");

    // Build a realistic-size view (AND gates in SHA-256: ~2000 per compress)
    let mut view = View::new();
    for i in 0..10_000u32 {
        view.record(i);
    }

    group.bench_function("commit_10k_outputs", |b| {
        b.iter(|| black_box(&view).commit())
    });

    group.finish();
}

// =========================================================================
// Tape streaming benchmark
// =========================================================================

fn bench_tape(c: &mut Criterion) {
    use blindforest::mpc::tape::LazyTape;

    let mut group = c.benchmark_group("tape");
    let seed = [0x42u8; SEED_LEN];

    group.bench_function("next_u32_x1000", |b| {
        b.iter(|| {
            let mut tape = LazyTape::new(&seed, 0, 0);
            for _ in 0..1000 {
                black_box(tape.next_u32());
            }
        })
    });

    group.bench_function("fill_4096B", |b| {
        let mut buf = [0u8; 4096];
        b.iter(|| {
            let mut tape = LazyTape::new(&seed, 0, 0);
            tape.fill(black_box(&mut buf));
        })
    });

    group.finish();
}

// =========================================================================
// Fiat-Shamir challenge benchmark
// =========================================================================

fn bench_challenge(c: &mut Criterion) {
    use blindforest::zkboo::challenge::compute_challenges;
    use blindforest::zkboo::types::RoundCommitment;
    use blindforest::params::NUM_ROUNDS;

    let mut group = c.benchmark_group("fiat_shamir");

    let msg_hash = [0xAAu8; HASH_LEN];
    let pk = [0xBBu8; HASH_LEN];

    // Build dummy commitments
    let commitments: Vec<RoundCommitment> = (0..NUM_ROUNDS)
        .map(|i| {
            let mut c = [[0u8; HASH_LEN]; 3];
            c[0][0] = i as u8;
            c[1][0] = (i >> 8) as u8;
            RoundCommitment { commitments: c }
        })
        .collect();

    group.bench_function("compute_challenges_219_rounds", |b| {
        b.iter(|| {
            compute_challenges(
                black_box(&msg_hash),
                black_box(&pk),
                black_box(&commitments),
            )
        })
    });

    group.finish();
}

// =========================================================================
// Entry point
// =========================================================================

criterion_group!(
    hash_benches, bench_hash
);
criterion_group!(
    prf_benches, bench_prf
);
criterion_group!(
    commitment_benches, bench_commitment
);
criterion_group!(
    wots_benches, bench_wots
);
criterion_group!(
    merkle_benches, bench_merkle
);
criterion_group!(
    gate_benches, bench_mpc_gates
);
criterion_group!(
    view_benches, bench_view
);
criterion_group!(
    tape_benches, bench_tape
);
criterion_group!(
    challenge_benches, bench_challenge
);
criterion_group!(
    name = sha256_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mpc_sha256
);
criterion_group!(
    name = circuit_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mpc_circuit
);
criterion_group!(
    name = zkboo_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_zkboo
);
criterion_group!(
    name = blind_sig_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_blind_sig
);

criterion_main!(
    hash_benches,
    prf_benches,
    commitment_benches,
    wots_benches,
    merkle_benches,
    gate_benches,
    view_benches,
    tape_benches,
    challenge_benches,
    sha256_benches,
    circuit_benches,
    zkboo_benches,
    blind_sig_benches,
);
