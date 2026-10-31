//! GF(256) over x^8 + x^4 + x^3 + x^2 + 1, and Reed–Solomon correction of one QR block.
//!
//! A block is read as a polynomial whose first byte is the highest power. QR's generator has the
//! roots α^0 .. α^(ecc-1), so syndrome i is the block evaluated at α^i.

/// The most error correction codewords a QR block carries (versions 9 and up at most levels)
pub const MAX_ECC: usize = 30;

const fn tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    (exp, log)
}

static TABLES: ([u8; 512], [u8; 256]) = tables();

fn exp(i: usize) -> u8 {
    TABLES.0[i % 255]
}

fn log(a: u8) -> usize {
    TABLES.1[a as usize] as usize
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        TABLES.0[log(a) + log(b)]
    }
}

fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        0
    } else {
        TABLES.0[log(a) + 255 - log(b)]
    }
}

/// p(x) with p[i] the coefficient of x^i
fn eval(p: &[u8], x: u8) -> u8 {
    p.iter().rev().fold(0, |acc, &c| mul(acc, x) ^ c)
}

fn syndromes(block: &[u8], ecc: usize, s: &mut [u8; MAX_ECC]) -> bool {
    let mut clean = true;
    for (i, si) in s.iter_mut().enumerate().take(ecc) {
        let a = exp(i);
        *si = block.iter().fold(0, |acc, &c| mul(acc, a) ^ c);
        clean &= *si == 0;
    }
    clean
}

/// Corrects `block` (data then `ecc` codewords) in place. `erasures` are byte positions known to be
/// unreliable: each costs one check codeword instead of the two an unknown error costs. `reserve`
/// check codewords are kept from correction altogether, so that 2·errors + erasures + reserve may
/// reach `ecc` and no further: with none in reserve, almost any garbage corrects to some codeword.
/// Returns how many bytes changed, or None when the damage is beyond that or does not check out.
pub fn correct(block: &mut [u8], ecc: usize, erasures: &[usize], reserve: usize) -> Option<usize> {
    let n = block.len();
    let rho = erasures.len();
    if ecc == 0 || ecc > MAX_ECC || n > 255 || ecc >= n || rho + reserve > ecc {
        return None;
    }
    let mut s = [0u8; MAX_ECC];
    if syndromes(block, ecc, &mut s) {
        return Some(0);
    }

    // The erasure locator Γ(x) = Π (1 + X_i x), X_i = α^(position's power)
    let mut gamma = [0u8; MAX_ECC + 2];
    gamma[0] = 1;
    for (count, &k) in erasures.iter().enumerate() {
        let x = exp(*n.checked_sub(1 + k).as_ref()?);
        for i in (1..=count + 1).rev() {
            gamma[i] ^= mul(gamma[i - 1], x);
        }
    }

    // Berlekamp–Massey for errors and erasures, started from Γ: the shortest errata locator Λ(x)
    let mut lambda = gamma;
    let mut b = gamma;
    let mut l = rho;
    for r in rho + 1..=ecc {
        let mut delta = 0;
        for j in 0..r.min(MAX_ECC + 2) {
            delta ^= mul(lambda[j], s[r - 1 - j]);
        }
        // x·B(x), shifted into a fresh array so the update reads the old B
        let mut xb = [0u8; MAX_ECC + 2];
        xb[1..].copy_from_slice(&b[..MAX_ECC + 1]);
        if delta == 0 {
            b = xb;
            continue;
        }
        let mut t = lambda;
        for i in 0..MAX_ECC + 2 {
            t[i] ^= mul(delta, xb[i]);
        }
        if 2 * l < r + rho {
            for i in 0..MAX_ECC + 2 {
                b[i] = div(lambda[i], delta);
            }
            l = r + rho - l;
        } else {
            b = xb;
        }
        lambda = t;
    }
    if l > ecc || lambda[l + 1..].iter().any(|&c| c != 0) || 2 * l + reserve > ecc + rho {
        return None;
    }

    // Ω(x) = S(x)Λ(x) mod x^ecc, and Λ'(x), its formal derivative: only the odd terms survive
    let mut omega = [0u8; MAX_ECC];
    for i in 0..ecc {
        for j in 0..=i.min(l) {
            omega[i] ^= mul(s[i - j], lambda[j]);
        }
    }
    let mut deriv = [0u8; MAX_ECC + 1];
    for i in (1..=l).step_by(2) {
        deriv[i - 1] = lambda[i];
    }

    // Chien search over every position, then Forney for each magnitude. Position k holds x^(n-1-k)
    let (mut roots, mut changed) = (0, 0);
    for k in 0..n {
        let power = n - 1 - k;
        let x_inv = exp(255 - power % 255);
        if eval(&lambda[..=l], x_inv) != 0 {
            continue;
        }
        let denom = eval(&deriv[..l.max(1)], x_inv);
        if denom == 0 {
            return None;
        }
        let e = mul(exp(power), div(eval(&omega[..ecc], x_inv), denom));
        block[k] ^= e;
        roots += 1;
        changed += usize::from(e != 0);
    }
    if roots != l || !syndromes(block, ecc, &mut s) {
        return None;
    }
    Some(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The remainder of data · x^ecc divided by the generator, written independently of `correct`
    fn encode(data: &[u8], ecc: usize, out: &mut [u8]) {
        let mut gen = [0u8; MAX_ECC + 1];
        gen[0] = 1;
        for i in 0..ecc {
            // multiply by (x - α^i), with gen[j] the coefficient of x^j
            for j in (1..=i + 1).rev() {
                gen[j] = gen[j - 1] ^ mul(gen[j], exp(i));
            }
            gen[0] = mul(gen[0], exp(i));
        }
        let mut g = [0u8; MAX_ECC + 1];
        for j in 0..=ecc {
            g[j] = gen[ecc - j];
        }
        let mut rem = [0u8; MAX_ECC];
        for &b in data {
            let factor = b ^ rem[0];
            rem.copy_within(1..ecc, 0);
            rem[ecc - 1] = 0;
            for j in 0..ecc {
                rem[j] ^= mul(g[j + 1], factor);
            }
        }
        out[..data.len()].copy_from_slice(data);
        out[data.len()..data.len() + ecc].copy_from_slice(&rem[..ecc]);
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
    }

    #[test]
    fn corrects_up_to_half_the_ecc() {
        let mut rng = Lcg(7);
        for &(data_len, ecc) in &[
            (19usize, 7usize),
            (16, 10),
            (13, 13),
            (9, 17),
            (15, 22),
            (118, 30),
            (24, 30),
            (1, 2),
        ] {
            for errors in 0..=ecc / 2 {
                for _ in 0..40 {
                    let mut data = [0u8; 255];
                    for b in data.iter_mut().take(data_len) {
                        *b = rng.next() as u8;
                    }
                    let mut block = [0u8; 255];
                    encode(&data[..data_len], ecc, &mut block);
                    let n = data_len + ecc;
                    let clean = block;
                    let mut hit = [false; 255];
                    let mut placed = 0;
                    while placed < errors {
                        let p = rng.next() as usize % n;
                        if hit[p] {
                            continue;
                        }
                        hit[p] = true;
                        block[p] ^= (rng.next() % 255 + 1) as u8;
                        placed += 1;
                    }
                    assert_eq!(
                        correct(&mut block[..n], ecc, &[], 0),
                        Some(errors),
                        "len {data_len} ecc {ecc} errors {errors}"
                    );
                    assert_eq!(block[..n], clean[..n]);
                }
            }
        }
    }

    #[test]
    fn refuses_or_never_claims_a_wrong_fix_beyond_capacity() {
        let mut rng = Lcg(11);
        let (data_len, ecc) = (16usize, 10usize);
        for _ in 0..500 {
            let mut data = [0u8; 16];
            for b in data.iter_mut() {
                *b = rng.next() as u8;
            }
            let mut block = [0u8; 26];
            encode(&data, ecc, &mut block);
            for _ in 0..ecc / 2 + 1 + (rng.next() % 4) as usize {
                let p = rng.next() as usize % (data_len + ecc);
                block[p] ^= (rng.next() % 255 + 1) as u8;
            }
            // Beyond capacity it may refuse, or land on another valid codeword; it must never return
            // a block that fails its own syndromes
            if correct(&mut block, ecc, &[], 0).is_some() {
                let mut s = [0u8; MAX_ECC];
                assert!(syndromes(&block, ecc, &mut s));
            }
        }
    }

    #[test]
    fn corrects_erasures_and_errors_together() {
        let mut rng = Lcg(13);
        for &(data_len, ecc) in &[(19usize, 7usize), (34, 10), (16, 10), (24, 30), (118, 30)] {
            for erasures in 0..=ecc {
                for errors in 0..=(ecc - erasures) / 2 {
                    for _ in 0..20 {
                        let mut data = [0u8; 255];
                        for b in data.iter_mut().take(data_len) {
                            *b = rng.next() as u8;
                        }
                        let n = data_len + ecc;
                        let mut block = [0u8; 255];
                        encode(&data[..data_len], ecc, &mut block);
                        let clean = block;
                        // Distinct positions: the first `erasures` are flagged (and may or may not be
                        // wrong, as a smudged module may still have read right), the rest are silent errors
                        let mut picked = [0usize; 64];
                        let mut count = 0;
                        while count < erasures + errors {
                            let p = rng.next() as usize % n;
                            if !picked[..count].contains(&p) {
                                picked[count] = p;
                                count += 1;
                            }
                        }
                        for (i, &p) in picked[..count].iter().enumerate() {
                            if i >= erasures || rng.next() % 2 == 0 {
                                block[p] ^= (rng.next() % 255 + 1) as u8;
                            }
                        }
                        let got = correct(&mut block[..n], ecc, &picked[..erasures], 0);
                        assert!(
                            got.is_some(),
                            "len {data_len} ecc {ecc} erasures {erasures} errors {errors}"
                        );
                        assert_eq!(block[..n], clean[..n]);
                    }
                }
            }
        }
    }

    #[test]
    fn a_reserve_turns_garbage_away() {
        // Random blocks are not codewords. With erasures filling what the reserve leaves, every
        // one corrects to something; with 4 in reserve, practically none should
        let mut rng = Lcg(17);
        for &(data_len, ecc) in &[(19usize, 7usize), (34, 10), (80, 20)] {
            let (mut loose, mut kept) = (0, 0);
            for _ in 0..20_000 {
                let mut block = [0u8; 255];
                for b in block.iter_mut().take(data_len + ecc) {
                    *b = rng.next() as u8;
                }
                let picked: std::vec::Vec<usize> = (0..ecc - 4).map(|i| i * 2).collect();
                let mut copy = block;
                loose +=
                    usize::from(correct(&mut copy[..data_len + ecc], ecc, &picked, 0).is_some());
                let mut copy = block;
                kept +=
                    usize::from(correct(&mut copy[..data_len + ecc], ecc, &picked, 4).is_some());
            }
            assert!(
                loose > 0,
                "the test should show garbage passing without a reserve"
            );
            assert_eq!(
                kept, 0,
                "({data_len}, {ecc}): {kept} garbage blocks corrected with a reserve"
            );
        }
    }
}
