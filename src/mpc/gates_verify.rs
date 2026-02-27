use crate::mpc::tape::LazyTape;
use crate::mpc::view::View;

/// XOR gate (2-party verification). Free.
#[inline]
pub fn xor_verify(a: [u32; 2], b: [u32; 2]) -> [u32; 2] {
    [a[0] ^ b[0], a[1] ^ b[1]]
}

/// NOT gate (2-party verification).
/// In ZKBoo the NOT gate flips only party 0's share.
/// During verify, we open parties e and e+1. If e==0, party 0 is the
/// first in the pair. If e==2, party 0 is the second (e+1=0 mod 3).
/// If e==1, party 0 is hidden.
#[inline]
pub fn not_verify(a: [u32; 2], e: usize) -> [u32; 2] {
    match e {
        0 => [!a[0], a[1]], // party 0 is first in pair
        2 => [a[0], !a[1]], // party 0 is second in pair (e=2, e+1=0)
        _ => a,             // party 0 is hidden (e=1)
    }
}

/// AND gate (2-party verification).
/// We have parties e and e+1. Party e's view output is read from its view.
/// Party e+1's output is computed using the same formula as the prover:
///   z[i] = (a[i] & b[i]) ^ (a[i] & b[prev]) ^ (a[prev] & b[i]) ^ r[prev] ^ r[i]
/// For i = e+1, prev = e. We need r[e] and r[e+1].
///
/// The verifier has tapes for both party e and party e+1.
pub fn and_verify(
    a: [u32; 2],
    b: [u32; 2],
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [u32; 2] {
    // Party e's output comes from its view
    let z_e = view_e.next_output();

    // Consume r[e] from party e's tape (to keep it in sync)
    let r_e = tape_e.next_u32();

    // Party e+1's output is computed: prev = e
    let r_next = tape_next.next_u32();
    let z_next = (a[1] & b[1]) ^ (a[1] & b[0]) ^ (a[0] & b[1]) ^ r_e ^ r_next;
    view_next.record(z_next);

    [z_e, z_next]
}

/// Right rotate (2-party verify). Free.
#[inline]
pub fn rightrotate_verify(a: [u32; 2], n: u32) -> [u32; 2] {
    [a[0].rotate_right(n), a[1].rotate_right(n)]
}

/// Right shift (2-party verify). Free.
#[inline]
pub fn rightshift_verify(a: [u32; 2], n: u32) -> [u32; 2] {
    [a[0] >> n, a[1] >> n]
}

/// ADD gate (2-party verification) using bit-by-bit carry chain.
pub fn add_verify(
    a: [u32; 2],
    b: [u32; 2],
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [u32; 2] {
    let mut result = [0u32; 2];
    let mut carry = [0u32; 2];

    for bit in 0..32 {
        let a_bit = [(a[0] >> bit) & 1, (a[1] >> bit) & 1];
        let b_bit = [(b[0] >> bit) & 1, (b[1] >> bit) & 1];

        let sum_bit = xor_verify(xor_verify(a_bit, b_bit), carry);
        for i in 0..2 {
            result[i] |= (sum_bit[i] & 1) << bit;
        }

        if bit < 31 {
            let ab = and_verify(a_bit, b_bit, tape_e, tape_next, view_e, view_next);
            let a_xor_b = xor_verify(a_bit, b_bit);
            let c_and_axb = and_verify(carry, a_xor_b, tape_e, tape_next, view_e, view_next);
            carry = xor_verify(ab, c_and_axb);
        }
    }

    result
}

/// SHA-256 Ch function (2-party verification).
pub fn ch_verify(
    e_shares: [u32; 2],
    f: [u32; 2],
    g: [u32; 2],
    e: usize,
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [u32; 2] {
    let ef = and_verify(e_shares, f, tape_e, tape_next, view_e, view_next);
    let not_e = not_verify(e_shares, e);
    let not_e_g = and_verify(not_e, g, tape_e, tape_next, view_e, view_next);
    xor_verify(ef, not_e_g)
}

/// SHA-256 Maj function (2-party verification).
pub fn maj_verify(
    a: [u32; 2],
    b: [u32; 2],
    c: [u32; 2],
    tape_e: &mut LazyTape,
    tape_next: &mut LazyTape,
    view_e: &mut View,
    view_next: &mut View,
) -> [u32; 2] {
    let ab = and_verify(a, b, tape_e, tape_next, view_e, view_next);
    let ac = and_verify(a, c, tape_e, tape_next, view_e, view_next);
    let bc = and_verify(b, c, tape_e, tape_next, view_e, view_next);
    xor_verify(xor_verify(ab, ac), bc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::gates;
    use crate::mpc::shares::share_u32;
    use crate::params::SEED_LEN;

    /// Test that 2-party AND verification produces the same result as 3-party.
    #[test]
    fn test_and_verify_consistency() {
        let seed = [0x42u8; SEED_LEN];

        // 3-party proving
        let mut tapes_3 = [
            LazyTape::new(&seed, 0, 0),
            LazyTape::new(&seed, 0, 1),
            LazyTape::new(&seed, 0, 2),
        ];
        let mut views_3 = [View::new(), View::new(), View::new()];

        let a_val = 0xDEADBEEF_u32;
        let b_val = 0xCAFEBABE_u32;
        let a = share_u32(a_val, 0x11111111, 0x22222222);
        let b = share_u32(b_val, 0x33333333, 0x44444444);
        let z_3 = gates::and(a, b, &mut tapes_3, &mut views_3);

        // Now verify with parties e=0 and e+1=1
        let e = 0;
        let mut tape_e_v = LazyTape::new(&seed, 0, e as u8);
        let mut tape_next = LazyTape::new(&seed, 0, (e + 1) as u8);
        let mut view_e = views_3[e].clone();
        view_e.reset_read();
        let mut view_next = View::new();

        let a_pair = [a[e], a[e + 1]];
        let b_pair = [b[e], b[e + 1]];
        let z_2 = and_verify(
            a_pair,
            b_pair,
            &mut tape_e_v,
            &mut tape_next,
            &mut view_e,
            &mut view_next,
        );

        assert_eq!(z_2[0], z_3[e]);
        assert_eq!(z_2[1], z_3[e + 1]);
    }
}
