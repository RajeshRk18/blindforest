use crate::mpc::tape::LazyTape;
use crate::mpc::view::View;

/// XOR gate: each party XORs locally. Free (no communication).
#[inline]
pub fn xor(a: [u32; 3], b: [u32; 3]) -> [u32; 3] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]]
}

/// NOT gate: only party 0 flips bits. Free.
#[inline]
pub fn not(a: [u32; 3]) -> [u32; 3] {
    [!a[0], a[1], a[2]]
}

/// AND gate using Beaver-style multiplication.
/// Each party i computes:
///   z[i] = (a[i] & b[i]) ^ (a[i] & b[prev]) ^ (a[prev] & b[i]) ^ r[prev] ^ r[i]
/// where prev = (i+2)%3, and r[j] comes from party j's random tape.
///
/// The r[prev] ^ r[i] terms telescope and cancel in XOR-reconstruction:
///   z[0]^z[1]^z[2] = (a[0]^a[1]^a[2]) & (b[0]^b[1]^b[2])
///
/// This formulation ensures that party i's computation depends only on
/// its own shares and those of the previous party (i-1 mod 3), enabling
/// 2-party verification with parties e and e+1.
pub fn and(
    a: [u32; 3],
    b: [u32; 3],
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [u32; 3] {
    let r = [
        tapes[0].next_u32(),
        tapes[1].next_u32(),
        tapes[2].next_u32(),
    ];
    let mut z = [0u32; 3];
    for i in 0..3 {
        let prev = (i + 2) % 3;
        z[i] = (a[i] & b[i]) ^ (a[i] & b[prev]) ^ (a[prev] & b[i]) ^ r[prev] ^ r[i];
        views[i].record(z[i]);
    }
    z
}

/// Right rotate by `n` bits. Free (local operation).
#[inline]
pub fn rightrotate(a: [u32; 3], n: u32) -> [u32; 3] {
    [
        a[0].rotate_right(n),
        a[1].rotate_right(n),
        a[2].rotate_right(n),
    ]
}

/// Right shift by `n` bits. All parties shift independently. Free.
#[inline]
pub fn rightshift(a: [u32; 3], n: u32) -> [u32; 3] {
    [a[0] >> n, a[1] >> n, a[2] >> n]
}

/// ADD gate: 32-bit addition with carry chain using AND gates.
/// Computes a + b mod 2^32 using a ripple-carry adder on shares.
pub fn add(
    a: [u32; 3],
    b: [u32; 3],
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [u32; 3] {
    let mut result = [0u32; 3];
    let mut carry = [0u32; 3];

    for bit in 0..32 {
        // Extract bit `bit` from a and b
        let a_bit = [(a[0] >> bit) & 1, (a[1] >> bit) & 1, (a[2] >> bit) & 1];
        let b_bit = [(b[0] >> bit) & 1, (b[1] >> bit) & 1, (b[2] >> bit) & 1];

        // sum_bit = a_bit ^ b_bit ^ carry
        let sum_bit = xor(xor(a_bit, b_bit), carry);

        // Set the bit in result
        for i in 0..3 {
            result[i] |= (sum_bit[i] & 1) << bit;
        }

        // carry_out = (a_bit & b_bit) ^ (carry & (a_bit ^ b_bit))
        if bit < 31 {
            let ab = and(a_bit, b_bit, tapes, views);
            let a_xor_b = xor(a_bit, b_bit);
            let c_and_axb = and(carry, a_xor_b, tapes, views);
            carry = xor(ab, c_and_axb);
        }
    }

    result
}

/// SHA-256 Ch function: Ch(e, f, g) = (e AND f) XOR (NOT e AND g)
pub fn ch(
    e: [u32; 3],
    f: [u32; 3],
    g: [u32; 3],
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [u32; 3] {
    let ef = and(e, f, tapes, views);
    let not_e = not(e);
    let not_e_g = and(not_e, g, tapes, views);
    xor(ef, not_e_g)
}

/// SHA-256 Maj function: Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
pub fn maj(
    a: [u32; 3],
    b: [u32; 3],
    c: [u32; 3],
    tapes: &mut [LazyTape; 3],
    views: &mut [View; 3],
) -> [u32; 3] {
    let ab = and(a, b, tapes, views);
    let ac = and(a, c, tapes, views);
    let bc = and(b, c, tapes, views);
    xor(xor(ab, ac), bc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::shares::{reconstruct_u32, share_u32};
    use crate::params::SEED_LEN;

    fn make_tapes(round: u32) -> [LazyTape; 3] {
        let seed = [0x42u8; SEED_LEN];
        [
            LazyTape::new(&seed, round, 0),
            LazyTape::new(&seed, round, 1),
            LazyTape::new(&seed, round, 2),
        ]
    }

    fn make_views() -> [View; 3] {
        [View::new(), View::new(), View::new()]
    }

    #[test]
    fn test_xor_gate() {
        let a_val = 0xDEADBEEF_u32;
        let b_val = 0x12345678_u32;
        let a = share_u32(a_val, 0x11111111, 0x22222222);
        let b = share_u32(b_val, 0x33333333, 0x44444444);
        let c = xor(a, b);
        assert_eq!(reconstruct_u32(&c), a_val ^ b_val);
    }

    #[test]
    fn test_not_gate() {
        let a_val = 0xDEADBEEF_u32;
        let a = share_u32(a_val, 0x11111111, 0x22222222);
        let c = not(a);
        assert_eq!(reconstruct_u32(&c), !a_val);
    }

    #[test]
    fn test_and_gate() {
        let a_val = 0xDEADBEEF_u32;
        let b_val = 0x12345678_u32;
        let mut tapes = make_tapes(0);
        let mut views = make_views();

        let a = share_u32(a_val, tapes[0].next_u32(), tapes[1].next_u32());
        // Need fresh tapes for the AND gate randomness
        let mut tapes = make_tapes(1);
        let b = share_u32(b_val, tapes[0].next_u32(), tapes[1].next_u32());
        let mut tapes = make_tapes(2);
        let c = and(a, b, &mut tapes, &mut views);
        assert_eq!(reconstruct_u32(&c), a_val & b_val);
    }

    #[test]
    fn test_and_gate_fuzz() {
        // Fuzz AND gate with many random values
        for seed_byte in 0..50u8 {
            let seed = [seed_byte; SEED_LEN];
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = make_views();

            let a_val = (seed_byte as u32).wrapping_mul(0x01010101);
            let b_val = (seed_byte as u32).wrapping_mul(0x10101010);

            let a = share_u32(a_val, tapes[0].next_u32(), tapes[1].next_u32());
            let b = share_u32(b_val, tapes[0].next_u32(), tapes[1].next_u32());
            let c = and(a, b, &mut tapes, &mut views);

            assert_eq!(
                reconstruct_u32(&c),
                a_val & b_val,
                "AND gate failed for seed_byte={}",
                seed_byte
            );
        }
    }

    #[test]
    fn test_add_gate() {
        let a_val = 0x80000001_u32;
        let b_val = 0x80000001_u32;
        let seed = [0x42u8; SEED_LEN];
        let mut tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let mut views = make_views();

        let a = share_u32(a_val, tapes[0].next_u32(), tapes[1].next_u32());
        let b = share_u32(b_val, tapes[0].next_u32(), tapes[1].next_u32());
        let c = add(a, b, &mut tapes, &mut views);
        assert_eq!(reconstruct_u32(&c), a_val.wrapping_add(b_val));
    }

    #[test]
    fn test_add_gate_fuzz() {
        for seed_byte in 0..50u8 {
            let seed = [seed_byte; SEED_LEN];
            let mut tapes = [
                LazyTape::new(&seed, 0, 0),
                LazyTape::new(&seed, 0, 1),
                LazyTape::new(&seed, 0, 2),
            ];
            let mut views = make_views();

            let a_val = (seed_byte as u32).wrapping_mul(0xDEADBEEF);
            let b_val = (seed_byte as u32).wrapping_mul(0xCAFEBABE);

            let a = share_u32(a_val, tapes[0].next_u32(), tapes[1].next_u32());
            let b = share_u32(b_val, tapes[0].next_u32(), tapes[1].next_u32());
            let c = add(a, b, &mut tapes, &mut views);

            assert_eq!(
                reconstruct_u32(&c),
                a_val.wrapping_add(b_val),
                "ADD gate failed for seed_byte={}",
                seed_byte
            );
        }
    }

    #[test]
    fn test_ch_function() {
        let e_val = 0xDEADBEEF_u32;
        let f_val = 0x12345678_u32;
        let g_val = 0xCAFEBABE_u32;
        let seed = [0x42u8; SEED_LEN];
        let mut tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let mut views = make_views();

        let e = share_u32(e_val, tapes[0].next_u32(), tapes[1].next_u32());
        let f = share_u32(f_val, tapes[0].next_u32(), tapes[1].next_u32());
        let g = share_u32(g_val, tapes[0].next_u32(), tapes[1].next_u32());
        let result = ch(e, f, g, &mut tapes, &mut views);

        let expected = (e_val & f_val) ^ (!e_val & g_val);
        assert_eq!(reconstruct_u32(&result), expected);
    }

    #[test]
    fn test_maj_function() {
        let a_val = 0xDEADBEEF_u32;
        let b_val = 0x12345678_u32;
        let c_val = 0xCAFEBABE_u32;
        let seed = [0x42u8; SEED_LEN];
        let mut tapes = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let mut views = make_views();

        let a = share_u32(a_val, tapes[0].next_u32(), tapes[1].next_u32());
        let b = share_u32(b_val, tapes[0].next_u32(), tapes[1].next_u32());
        let c = share_u32(c_val, tapes[0].next_u32(), tapes[1].next_u32());
        let result = maj(a, b, c, &mut tapes, &mut views);

        let expected = (a_val & b_val) ^ (a_val & c_val) ^ (b_val & c_val);
        assert_eq!(reconstruct_u32(&result), expected);
    }

    #[test]
    fn test_rightrotate() {
        let val = 0x80000001_u32;
        let shares = share_u32(val, 0x11111111, 0x22222222);
        let result = rightrotate(shares, 1);
        assert_eq!(reconstruct_u32(&result), val.rotate_right(1));
    }

    #[test]
    fn test_rightshift() {
        let val = 0x80000001_u32;
        let shares = share_u32(val, 0x11111111, 0x22222222);
        let result = rightshift(shares, 1);
        assert_eq!(reconstruct_u32(&result), val >> 1);
    }
}
