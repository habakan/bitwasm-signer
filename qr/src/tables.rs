//! The per-version constants of ISO/IEC 18004. The test suite checks each against an independent
//! encoder (Nayuki's QR-Code-generator), so a typo here fails a test rather than a scan.

/// Error correction levels in the order the tables use: L, M, Q, H
pub const LEVELS: usize = 4;

/// Error correction codewords per block, indexed by level then version (index 0 unused)
#[rustfmt::skip]
pub const ECC_PER_BLOCK: [[u8; 41]; LEVELS] = [
    [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];

/// Blocks the codewords are split into, indexed the same way
#[rustfmt::skip]
pub const BLOCKS: [[u8; 41]; LEVELS] = [
    [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

/// The largest version and side length
pub const MAX_VERSION: usize = 40;
pub const MAX_SIZE: usize = 17 + 4 * MAX_VERSION;
/// Codewords in a version 40 symbol, the most any version holds
pub const MAX_CODEWORDS: usize = 3706;

pub const fn size(version: usize) -> usize {
    17 + 4 * version
}

/// Modules left for data and error correction once the function patterns are drawn, remainder
/// bits included
pub const fn raw_data_modules(version: usize) -> usize {
    let mut n = (16 * version + 128) * version + 64;
    if version >= 2 {
        let align = version / 7 + 2;
        n -= (25 * align - 10) * align - 55;
        if version >= 7 {
            n -= 36;
        }
    }
    n
}

/// Centres of the alignment patterns along one axis; the rest of the array is unused
pub fn alignment_positions(version: usize) -> ([usize; 7], usize) {
    let mut out = [0usize; 7];
    if version < 2 {
        return (out, 0);
    }
    let count = version / 7 + 2;
    let step = (version * 8 + count * 3 + 5) / (count * 4 - 4) * 2;
    out[0] = 6;
    for (k, i) in (1..count).rev().enumerate() {
        out[i] = size(version) - 7 - k * step;
    }
    (out, count)
}

/// The level index for the two level bits a format word carries
pub const fn level_from_bits(bits: u32) -> usize {
    match bits {
        1 => 0,
        0 => 1,
        3 => 2,
        _ => 3,
    }
}

/// The 15-bit format word for these level bits and mask, masked as it is drawn
pub const fn format_word(level_bits: u32, mask: u32) -> u32 {
    let data = level_bits << 3 | mask;
    let mut rem = data;
    let mut i = 0;
    while i < 10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        i += 1;
    }
    (data << 10 | rem) ^ 0x5412
}

/// The 18-bit version word, drawn from version 7 up
pub const fn version_word(version: u32) -> u32 {
    let mut rem = version;
    let mut i = 0;
    while i < 12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
        i += 1;
    }
    version << 12 | rem
}
