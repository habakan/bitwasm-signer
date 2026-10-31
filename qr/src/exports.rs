//! The module's entry points.

use crate::{Kind, State, MAX_PIXELS, OUTPUT_CAP};

static mut PIXELS: [u8; MAX_PIXELS] = [0; MAX_PIXELS];
static mut OUTPUT: [u8; OUTPUT_CAP] = [0; OUTPUT_CAP];
static mut STATE: State = State::ZERO;
static mut WIDTH: usize = 0;
static mut HEIGHT: usize = 0;

/// Sets the frame size for the next qr_decode. 1 if accepted, 0 if not
#[no_mangle]
pub extern "C" fn qr_init(w: u32, h: u32) -> i32 {
    let (w, h) = (w as usize, h as usize);
    if w < 21 || h < 21 || w > crate::MAX_WIDTH || h > crate::MAX_HEIGHT || w * h > MAX_PIXELS {
        return 0;
    }
    unsafe {
        WIDTH = w;
        HEIGHT = h;
    }
    1
}

/// Where the host writes width x height bytes of greyscale, row by row
#[no_mangle]
pub extern "C" fn qr_input() -> *mut u8 {
    (&raw mut PIXELS) as *mut u8
}

#[no_mangle]
pub extern "C" fn qr_input_cap() -> u32 {
    MAX_PIXELS as u32
}

#[no_mangle]
pub extern "C" fn qr_output() -> *const u8 {
    (&raw const OUTPUT) as *const u8
}

#[no_mangle]
pub extern "C" fn qr_output_cap() -> u32 {
    OUTPUT_CAP as u32
}

/// Reads the frame for any code. Returns the length at qr_output, 0 if no code was found, -1 if one
/// was found but did not decode, -2 if no size is set
#[no_mangle]
pub extern "C" fn qr_decode() -> i32 {
    qr_decode_as(0)
}

/// As qr_decode, for one kind: 0 any code, 1 a SeedQR only, 2 frames of an animated UR, followed
/// from one frame to the next. -3 means a code was read but it is not of that kind
#[no_mangle]
pub extern "C" fn qr_decode_as(kind: u32) -> i32 {
    let kind = match kind {
        0 => Kind::Any,
        1 => Kind::SeedQr,
        2 => Kind::Animated,
        _ => return -2,
    };
    unsafe {
        let (w, h) = (WIDTH, HEIGHT);
        if w == 0 {
            return -2;
        }
        crate::read(
            &*(&raw const PIXELS),
            w,
            h,
            kind,
            &mut *(&raw mut OUTPUT),
            &mut *(&raw mut STATE),
        )
    }
}

/// Zeroes the frame, the output and every intermediate buffer, the animated
/// tracking included: after reading a SeedQR, nothing of it should stay in this module's memory
#[no_mangle]
pub extern "C" fn qr_wipe() {
    unsafe {
        (*(&raw mut PIXELS)).fill(0);
        (*(&raw mut OUTPUT)).fill(0);
        (*(&raw mut STATE)).wipe();
    }
    scrub_stack();
}

/// Zeroes most of the 64 KB stack below this frame: a decode leaves codewords in the locals of
/// functions that have returned. Volatile, so the stores are not dropped as dead
#[inline(never)]
fn scrub_stack() {
    let mut area = [0u8; 56 * 1024];
    for b in area.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::hint::black_box(&area);
}
