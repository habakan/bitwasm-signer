//! From a grid of modules to the bytes it carries: format and version words, unmasking, the zigzag
//! read, de-interleaving, Reed–Solomon and the segments.

use crate::gf;
use crate::tables::{
    self, alignment_positions, format_word, level_from_bits, raw_data_modules, size, version_word,
};

/// Scratch space for one decode, kept out of the stack
pub struct Work {
    pub codewords: [u8; tables::MAX_CODEWORDS],
    pub blocks: [u8; tables::MAX_CODEWORDS + 81],
    pub data: [u8; tables::MAX_CODEWORDS],
    /// The least sure bit of each codeword, laid out as `codewords` and then as `blocks`
    pub sure: [u8; tables::MAX_CODEWORDS],
    pub block_sure: [u8; tables::MAX_CODEWORDS + 81],
    /// One block being corrected, its untouched copy, its sureness and its erasure order. Kept here
    /// rather than on the stack so that wiping covers them: they hold the data codewords
    pub one: [u8; 256],
    pub clean: [u8; 256],
    pub one_sure: [u8; 256],
    pub order: [usize; 256],
}

impl Work {
    pub const ZERO: Work = Work {
        codewords: [0; tables::MAX_CODEWORDS],
        blocks: [0; tables::MAX_CODEWORDS + 81],
        data: [0; tables::MAX_CODEWORDS],
        sure: [0; tables::MAX_CODEWORDS],
        block_sure: [0; tables::MAX_CODEWORDS + 81],
        one: [0; 256],
        clean: [0; 256],
        one_sure: [0; 256],
        order: [0; 256],
    };

    pub fn wipe(&mut self) {
        self.codewords.fill(0);
        self.blocks.fill(0);
        self.data.fill(0);
        self.sure.fill(0);
        self.block_sure.fill(0);
        self.one.fill(0);
        self.clean.fill(0);
        self.one_sure.fill(0);
        self.order.fill(0);
    }
}

/// What a grid decoded to: the length written and the error correction level (0 = L .. 3 = H)
pub struct Decoded {
    pub len: usize,
    pub level: usize,
    /// The mode indicator (1 numeric, 2 alphanumeric, 4 byte, 8 kanji) when the code holds exactly
    /// one segment and no ECI, structured append or FNC1 header; otherwise 0
    pub mode: u32,
}

/// A codeword whose least sure bit sits this close to its threshold may be marked as an erasure
const UNSURE: u8 = 32;

/// Check codewords never spent on erasures. Each one left over makes a wrong correction about 256
/// times less likely, and a camera makes many attempts a second
const SPARE: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Format,
    /// The version word names another version; the caller can sample the grid again at that size
    Version(usize),
    Correction,
    Data,
    /// The decoded text does not fit the output buffer
    Overflow,
}

fn dark(grid: &[u8], n: usize, x: usize, y: usize) -> u32 {
    grid[y * n + x] as u32
}

/// Both copies of the format word, compared against all 32 valid words; up to 3 bits may be wrong
pub fn read_format(grid: &[u8], n: usize) -> Option<(usize, u32)> {
    let (mut a, mut b) = (0u32, 0u32);
    for i in 0..6 {
        a |= dark(grid, n, 8, i) << i;
    }
    a |= dark(grid, n, 8, 7) << 6 | dark(grid, n, 8, 8) << 7 | dark(grid, n, 7, 8) << 8;
    for i in 9..15 {
        a |= dark(grid, n, 14 - i, 8) << i;
    }
    for i in 0..8 {
        b |= dark(grid, n, n - 1 - i, 8) << i;
    }
    for i in 8..15 {
        b |= dark(grid, n, 8, n - 15 + i) << i;
    }
    let mut best = (u32::MAX, 0, 0);
    for level_bits in 0..4 {
        for mask in 0..8 {
            let w = format_word(level_bits, mask);
            let d = (w ^ a).count_ones().min((w ^ b).count_ones());
            if d < best.0 {
                best = (d, level_bits, mask);
            }
        }
    }
    (best.0 <= 3).then(|| (level_from_bits(best.1), best.2))
}

/// The version from either copy of the version word, if one is within 3 bits of a valid word
pub fn read_version(grid: &[u8], n: usize) -> Option<usize> {
    let (mut a, mut b) = (0u32, 0u32);
    for i in 0..18 {
        let (p, q) = (n - 11 + i % 3, i / 3);
        a |= dark(grid, n, p, q) << i;
        b |= dark(grid, n, q, p) << i;
    }
    let mut best = (u32::MAX, 0);
    for v in 7..=tables::MAX_VERSION as u32 {
        let w = version_word(v);
        let d = (w ^ a).count_ones().min((w ^ b).count_ones());
        if d < best.0 {
            best = (d, v as usize);
        }
    }
    (best.0 <= 3).then_some(best.1)
}

fn is_function(version: usize, n: usize, align: &([usize; 7], usize), x: usize, y: usize) -> bool {
    if (x < 9 && y < 9) || (x >= n - 8 && y < 9) || (x < 9 && y >= n - 8) || x == 6 || y == 6 {
        return true;
    }
    if version >= 7 && ((x >= n - 11 && x < n - 8 && y < 6) || (y >= n - 11 && y < n - 8 && x < 6))
    {
        return true;
    }
    let (pos, count) = align;
    for i in 0..*count {
        for j in 0..*count {
            let corner =
                (i == 0 && j == 0) || (i == 0 && j == count - 1) || (i == count - 1 && j == 0);
            if !corner && x + 2 >= pos[i] && x <= pos[i] + 2 && y + 2 >= pos[j] && y <= pos[j] + 2 {
                return true;
            }
        }
    }
    false
}

fn masked(mask: u32, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (x / 3 + y / 2) % 2 == 0,
        5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3) % 2 == 0,
        _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
    }
}

/// Decodes a sampled grid (1 = dark, row by row) of the given version into `out`, returning the length
/// `sure` says, per module, how far its grey sat from the threshold. When a block will not correct,
/// its least sure codewords are tried again as erasures
pub fn decode_grid(
    grid: &[u8],
    sure: &[u8],
    version: usize,
    out: &mut [u8],
    work: &mut Work,
) -> Result<Decoded, Error> {
    let n = size(version);
    let (level, mask) = read_format(grid, n).ok_or(Error::Format)?;
    if version >= 7 {
        match read_version(grid, n) {
            Some(v) if v == version => {}
            Some(v) => return Err(Error::Version(v)),
            None => return Err(Error::Format),
        }
    }

    // The zigzag: two-module columns from the right, alternating up and down, skipping the timing column
    let total = raw_data_modules(version) / 8;
    let align = alignment_positions(version);
    let codewords = &mut work.codewords[..total];
    codewords.fill(0);
    let cw_sure = &mut work.sure[..total];
    cw_sure.fill(255);
    let mut bit = 0;
    let mut right = n - 1;
    loop {
        if right == 6 {
            right = 5;
        }
        let upward = (right + 1) & 2 == 0;
        for vert in 0..n {
            let y = if upward { n - 1 - vert } else { vert };
            for j in 0..2 {
                let x = right - j;
                if bit < total * 8 && !is_function(version, n, &align, x, y) {
                    let v = grid[y * n + x] != 0;
                    if v != masked(mask, x, y) {
                        codewords[bit >> 3] |= 0x80 >> (bit & 7);
                    }
                    cw_sure[bit >> 3] = cw_sure[bit >> 3].min(sure[y * n + x]);
                    bit += 1;
                }
            }
        }
        if right < 2 {
            break;
        }
        right -= 2;
    }

    // De-interleave: short blocks carry one data codeword fewer, and the read skips that column for them
    let blocks = tables::BLOCKS[level][version] as usize;
    let ecc = tables::ECC_PER_BLOCK[level][version] as usize;
    let short_len = total / blocks;
    let shorts = blocks - total % blocks;
    let stride = short_len + 1;
    let mut k = 0;
    for i in 0..stride {
        for b in 0..blocks {
            if i != short_len - ecc || b >= shorts {
                work.blocks[b * stride + i] = codewords[k];
                work.block_sure[b * stride + i] = cw_sure[k];
                k += 1;
            }
        }
    }

    // ISO/IEC 18004's misdecode protection: the smallest codes keep some check codewords for
    // detection only, as correcting with every one of them lets garbage through
    let protect = match (version, level) {
        (1, 0) => 3,
        (1, 1) | (2, 0) => 2,
        (1, _) | (3, 0) => 1,
        _ => 0,
    };
    let mut len = 0;
    for b in 0..blocks {
        let data_len = short_len - ecc + usize::from(b >= shorts);
        let m = data_len + ecc;
        let w = &mut *work;
        w.one[..data_len].copy_from_slice(&w.blocks[b * stride..b * stride + data_len]);
        w.one[data_len..m].copy_from_slice(&w.blocks[(b + 1) * stride - ecc..(b + 1) * stride]);
        w.one_sure[..data_len].copy_from_slice(&w.block_sure[b * stride..b * stride + data_len]);
        w.one_sure[data_len..m]
            .copy_from_slice(&w.block_sure[(b + 1) * stride - ecc..(b + 1) * stride]);
        w.clean = w.one;
        let mut ok = gf::correct(&mut w.one[..m], ecc, &[], protect).is_some();
        if !ok {
            // The least sure codewords, least sure first, as erasures. Each spends a check codeword,
            // and SPARE (or a third, in larger blocks) are kept back from any correction so a wrong
            // one is still caught. Then half as many, in case real errors sit elsewhere
            let reserve = SPARE.max(ecc / 3).max(protect);
            let mut count = 0;
            for p in 0..m {
                if w.one_sure[p] < UNSURE {
                    let at = w.order[..count]
                        .iter()
                        .position(|&q| w.one_sure[p] < w.one_sure[q])
                        .unwrap_or(count);
                    w.order.copy_within(at..count, at + 1);
                    w.order[at] = p;
                    count += 1;
                }
            }
            let room = ecc.saturating_sub(reserve);
            for take in [count.min(room), count.min(room / 2)] {
                if take == 0 {
                    continue;
                }
                w.one = w.clean;
                if gf::correct(&mut w.one[..m], ecc, &w.order[..take], reserve).is_some() {
                    ok = true;
                    break;
                }
            }
        }
        if !ok {
            return Err(Error::Correction);
        }
        w.data[len..len + data_len].copy_from_slice(&w.one[..data_len]);
        len += data_len;
    }
    let (len, mode) = segments(&work.data[..len], version, out)?;
    Ok(Decoded { len, level, mode })
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn left(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    fn read(&mut self, n: usize) -> Result<u32, Error> {
        if n > self.left() {
            return Err(Error::Data);
        }
        let mut v = 0;
        for _ in 0..n {
            v = v << 1 | (self.data[self.pos >> 3] >> (7 - (self.pos & 7)) & 1) as u32;
            self.pos += 1;
        }
        Ok(v)
    }
}

const ALNUM: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn count_bits(version: usize, small: usize, medium: usize, large: usize) -> usize {
    if version <= 9 {
        small
    } else if version <= 26 {
        medium
    } else {
        large
    }
}

/// The segments, written out as bytes: digits and alphanumerics as ASCII, byte mode as is, kanji
/// as Shift JIS. ECI and structured append headers are read past
fn segments(data: &[u8], version: usize, out: &mut [u8]) -> Result<(usize, u32), Error> {
    let mut bits = Bits { data, pos: 0 };
    let mut len = 0;
    let (mut segs, mut mode, mut headers) = (0, 0, false);
    let mut push = |b: u8, len: &mut usize| -> Result<(), Error> {
        *out.get_mut(*len).ok_or(Error::Overflow)? = b;
        *len += 1;
        Ok(())
    };
    while bits.left() >= 4 {
        let indicator = bits.read(4)?;
        if matches!(indicator, 1 | 2 | 4 | 8) {
            segs += 1;
            mode = indicator;
        } else if indicator != 0 {
            headers = true;
        }
        match indicator {
            0 => break,
            1 => {
                let mut count = bits.read(count_bits(version, 10, 12, 14))? as usize;
                while count > 0 {
                    let (digits, width) = match count {
                        1 => (1, 4),
                        2 => (2, 7),
                        _ => (3, 10),
                    };
                    let v = bits.read(width)?;
                    if v >= [10, 100, 1000][digits - 1] {
                        return Err(Error::Data);
                    }
                    for d in (0..digits).rev() {
                        push(b'0' + (v / 10u32.pow(d as u32) % 10) as u8, &mut len)?;
                    }
                    count -= digits;
                }
            }
            2 => {
                let mut count = bits.read(count_bits(version, 9, 11, 13))? as usize;
                while count >= 2 {
                    let v = bits.read(11)? as usize;
                    if v >= 45 * 45 {
                        return Err(Error::Data);
                    }
                    push(ALNUM[v / 45], &mut len)?;
                    push(ALNUM[v % 45], &mut len)?;
                    count -= 2;
                }
                if count == 1 {
                    let v = bits.read(6)? as usize;
                    push(*ALNUM.get(v).ok_or(Error::Data)?, &mut len)?;
                }
            }
            4 => {
                let count = bits.read(count_bits(version, 8, 16, 16))?;
                for _ in 0..count {
                    push(bits.read(8)? as u8, &mut len)?;
                }
            }
            8 => {
                let count = bits.read(count_bits(version, 8, 10, 12))?;
                for _ in 0..count {
                    let v = bits.read(13)?;
                    let sjis = (v / 0xc0) << 8 | v % 0xc0;
                    let sjis = if sjis + 0x8140 <= 0x9ffc {
                        sjis + 0x8140
                    } else {
                        sjis + 0xc140
                    };
                    push((sjis >> 8) as u8, &mut len)?;
                    push(sjis as u8, &mut len)?;
                }
            }
            7 => {
                // ECI: one to three bytes, sized by the leading bits of the first
                let first = bits.read(8)?;
                if first & 0x80 != 0 {
                    bits.read(if first & 0x40 == 0 { 8 } else { 16 })?;
                }
            }
            3 => {
                bits.read(16)?;
            }
            5 => {}
            9 => {
                bits.read(8)?;
            }
            _ => return Err(Error::Data),
        }
    }
    Ok((len, if segs == 1 && !headers { mode } else { 0 }))
}
