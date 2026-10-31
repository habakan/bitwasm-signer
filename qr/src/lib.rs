//! qr.wasm: reads a QR code from 8-bit greyscale pixels.
//!
//! Zero imports, no allocator, no unwinding, like the parser and signer: the host writes pixels into
//! the buffer this module exports and reads the decoded bytes back. Nothing here depends on another
//! QR library; the tests compare against one written by someone else.
// std only on the host, where the tests build this crate as a library
#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

pub mod binarize;
pub mod decode;
pub mod gf;
pub mod scan;
pub mod tables;

#[cfg(target_arch = "wasm32")]
mod exports;

/// The largest frame accepted: 1280x720 either way up, as large as a camera preview needs to be
pub const MAX_WIDTH: usize = 1280;
pub const MAX_HEIGHT: usize = 1280;
pub const MAX_PIXELS: usize = 1280 * 720;

/// Version 40 numeric mode at level L, the longest output a code can produce, is 7,089 digits
pub const OUTPUT_CAP: usize = 7168;

pub use scan::{Kind, WRONG_KIND};

/// Everything a read uses besides the pixels, their dark/light copy and the output, so it can be
/// wiped in one place
pub struct State {
    pub means: [u8; binarize::MAX_BLOCKS],
    pub thresholds: [u8; binarize::MAX_BLOCKS],
    pub scan: scan::Scan,
    pub work: decode::Work,
}

impl State {
    pub const ZERO: State = State {
        means: [0; binarize::MAX_BLOCKS],
        thresholds: [0; binarize::MAX_BLOCKS],
        scan: scan::Scan::ZERO,
        work: decode::Work::ZERO,
    };

    pub fn wipe(&mut self) {
        self.means.fill(0);
        self.thresholds.fill(0);
        self.scan.wipe();
        self.work.wipe();
    }
}

/// Decodes the first code of `kind` in the greyscale `px`. The length written to `out`; 0 when no
/// code was found; -1 when one was found but did not decode; WRONG_KIND when it decoded to something
/// not of `kind`; -2 when the size is not accepted. A light-on-dark code is tried when nothing
/// dark-on-light reads
pub fn read(px: &[u8], w: usize, h: usize, kind: Kind, out: &mut [u8], state: &mut State) -> i32 {
    if w < 21 || h < 21 || w > MAX_WIDTH || h > MAX_HEIGHT || w * h > px.len().min(MAX_PIXELS) {
        return -2;
    }
    binarize::binarize(&px[..w * h], w, h, &mut state.means, &mut state.thresholds);
    let mut img = scan::Image {
        grey: &px[..w * h],
        thresholds: &state.thresholds,
        w: w as i32,
        h: h as i32,
        inverted: false,
    };
    let r = scan::read(&img, kind, out, &mut state.scan, &mut state.work);
    // A light-on-dark code can still show something finder-like the right way up, so -1 does not
    // rule it out; a read or a code of the wrong kind does
    if r > 0 || r == WRONG_KIND {
        return r;
    }
    img.inverted = true;
    scan::read(&img, kind, out, &mut state.scan, &mut state.work)
}
