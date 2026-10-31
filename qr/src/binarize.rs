//! Greyscale to dark and light. Each 8x8 block gets the mean of the 5x5 blocks around it as its
//! threshold, so a shadow over part of the code does not swallow it the way one global cut would.

pub const BLOCK: usize = 8;

/// Blocks in the largest frame the module accepts
pub const MAX_BLOCKS: usize = (crate::MAX_WIDTH / BLOCK + 1) * (crate::MAX_HEIGHT / BLOCK + 1);

/// A block whose pixels span less than this is taken to be flat, background or the inside of a module
const FLAT: u8 = 24;

/// Each block's threshold into `thresholds`: a pixel is dark when its grey is at or below its
/// block's threshold. Nothing is copied, so a frame costs its own size and no more
pub fn binarize(px: &[u8], w: usize, h: usize, means: &mut [u8], thresholds: &mut [u8]) {
    let (bw, bh) = (w.div_ceil(BLOCK), h.div_ceil(BLOCK));
    for by in 0..bh {
        for bx in 0..bw {
            let (mut lo, mut hi, mut sum, mut count) = (255u8, 0u8, 0u32, 0u32);
            for y in by * BLOCK..((by + 1) * BLOCK).min(h) {
                for &v in &px[y * w + bx * BLOCK..y * w + ((bx + 1) * BLOCK).min(w)] {
                    lo = lo.min(v);
                    hi = hi.max(v);
                    sum += v as u32;
                    count += 1;
                }
            }
            let mut mean = (sum / count) as u8;
            if hi - lo <= FLAT {
                // A flat block sits below its own pixels, so it reads as light unless its neighbours,
                // already done, say the area around it is darker
                mean = lo / 2;
                if bx > 0 && by > 0 {
                    let around = (means[(by - 1) * bw + bx] as u32
                        + 2 * means[by * bw + bx - 1] as u32
                        + means[(by - 1) * bw + bx - 1] as u32)
                        / 4;
                    if (lo as u32) < around {
                        mean = around as u8;
                    }
                }
            }
            means[by * bw + bx] = mean;
        }
    }
    for by in 0..bh {
        let (y0, y1) = (by.saturating_sub(2), (by + 3).min(bh));
        for bx in 0..bw {
            let (x0, x1) = (bx.saturating_sub(2), (bx + 3).min(bw));
            let mut sum = 0u32;
            for yy in y0..y1 {
                for xx in x0..x1 {
                    sum += means[yy * bw + xx] as u32;
                }
            }
            let threshold = (sum / ((y1 - y0) * (x1 - x0)) as u32) as u8;
            thresholds[by * bw + bx] = threshold;
        }
    }
}
