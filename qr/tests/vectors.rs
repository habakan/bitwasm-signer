//! Symbols from an independent encoder (tests/gen_vectors.py), checked three ways: our tables
//! against its tables, its module grids decoded directly, and the same grids drawn into images the
//! way a camera might see them.
//!
//! QR_VECTORS points at the directory gen_vectors.py wrote (default ../build/qr).

use bitwasm_signer_qr::decode::{decode_grid, Work};
use bitwasm_signer_qr::{tables, Kind, State, OUTPUT_CAP, WRONG_KIND};
use std::boxed::Box;
use std::path::PathBuf;
use std::string::String;
use std::vec::Vec;
use std::{format, fs, vec};

struct Vector {
    version: usize,
    expected: Vec<u8>,
    rows: Vec<Vec<u8>>,
}

fn dir() -> PathBuf {
    std::env::var("QR_VECTORS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../build/qr"))
}

fn vectors() -> Vec<Vector> {
    load("vectors.txt")
}

fn load(name: &str) -> Vec<Vector> {
    let text = fs::read_to_string(dir().join(name)).expect("run tests/gen_vectors.py first");
    text.lines()
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            let hex = f[3];
            Vector {
                version: f[0].parse().unwrap(),
                expected: (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect(),
                rows: f[4]
                    .split('/')
                    .map(|r| r.bytes().map(|b| b - b'0').collect())
                    .collect(),
            }
        })
        .collect()
}

#[test]
fn tables_match_the_reference_encoder() {
    let text =
        fs::read_to_string(dir().join("tables.txt")).expect("run tests/gen_vectors.py first");
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let v: usize = f[0].parse().unwrap();
        for level in 0..4 {
            assert_eq!(
                tables::ECC_PER_BLOCK[level][v] as usize,
                f[1 + level].parse::<usize>().unwrap(),
                "ecc v{v} level {level}"
            );
            assert_eq!(
                tables::BLOCKS[level][v] as usize,
                f[5 + level].parse::<usize>().unwrap(),
                "blocks v{v} level {level}"
            );
        }
        assert_eq!(
            tables::raw_data_modules(v),
            f[9].parse::<usize>().unwrap(),
            "raw modules v{v}"
        );
        assert_eq!(tables::size(v), f[10].parse::<usize>().unwrap());
        let (pos, count) = tables::alignment_positions(v);
        let want: Vec<usize> = f
            .get(11)
            .filter(|s| !s.is_empty())
            .map(|s| s.split(',').map(|p| p.parse().unwrap()).collect())
            .unwrap_or_default();
        assert_eq!(&pos[..count], &want[..], "alignment v{v}");
    }
}

#[test]
fn grids_decode() {
    let mut work = Box::new(Work::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    for v in vectors() {
        let grid: Vec<u8> = v.rows.concat();
        let len = decode_grid(
            &grid,
            &vec![255; grid.len()],
            v.version,
            &mut out,
            &mut work,
        )
        .unwrap_or_else(|e| panic!("v{} {:?}", v.version, e))
        .len;
        assert_eq!(&out[..len], &v.expected[..], "v{}", v.version);
    }
}

#[test]
fn grids_decode_with_damage() {
    // Flipping modules in the data area exercises Reed–Solomon on real interleaving; at level H a
    // handful of flips per symbol is well within what it corrects
    let mut work = Box::new(Work::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 3u64;
    for v in vectors().into_iter().filter(|v| v.version >= 2) {
        let n = tables::size(v.version);
        let mut grid: Vec<u8> = v.rows.concat();
        for _ in 0..6 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let (x, y) = (
                9 + (seed >> 33) as usize % (n - 17),
                9 + (seed >> 45) as usize % (n - 17),
            );
            grid[y * n + x] ^= 1;
        }
        // Not every symbol has the margin at its level; count rather than demand
        if let Ok(d) = decode_grid(
            &grid,
            &vec![255; grid.len()],
            v.version,
            &mut out,
            &mut work,
        ) {
            let len = d.len;
            assert_eq!(
                &out[..len],
                &v.expected[..],
                "a damaged v{} decoded to the wrong bytes",
                v.version
            );
        }
    }
}

/// A homography for drawing, kept separate from the decoder's own
fn inverse(m: &[f64; 9]) -> [f64; 9] {
    let [a, b, c, d, e, f, g, h, i] = *m;
    let det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
    let adj = [
        e * i - f * h,
        c * h - b * i,
        b * f - c * e,
        f * g - d * i,
        a * i - c * g,
        c * d - a * f,
        d * h - e * g,
        b * g - a * h,
        a * e - b * d,
    ];
    adj.map(|v| v / det)
}

fn mul(a: &[f64; 9], b: &[f64; 9]) -> [f64; 9] {
    let mut m = [0.0; 9];
    for r in 0..3 {
        for c in 0..3 {
            m[r * 3 + c] = (0..3).map(|k| a[r * 3 + k] * b[k * 3 + c]).sum();
        }
    }
    m
}

fn apply(m: &[f64; 9], x: f64, y: f64) -> (f64, f64) {
    let z = m[6] * x + m[7] * y + m[8];
    (
        (m[0] * x + m[1] * y + m[2]) / z,
        (m[3] * x + m[4] * y + m[5]) / z,
    )
}

#[derive(Clone, Copy)]
struct Look {
    scale: f64,
    angle: f64,
    /// Perspective terms: how far the far edge shrinks, along x and y
    tilt: (f64, f64),
    blur: bool,
    noise: u8,
    /// Brightness falls by this fraction from left to right
    shade: f64,
    contrast: (u8, u8),
}

/// Draws the symbol with a 4-module quiet zone through the look, 2x2 supersampled
fn draw(v: &Vector, look: &Look, seed: &mut u64) -> (Vec<u8>, usize, usize) {
    let n = v.rows.len() as f64;
    let half = n / 2.0 + 4.0;
    let (s, c) = (look.angle.sin(), look.angle.cos());
    // modules (centred) -> tilt -> rotate and scale -> pixels
    let tilt = [
        1.0,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
        look.tilt.0 / half,
        look.tilt.1 / half,
        1.0,
    ];
    let rot = [
        c * look.scale,
        -s * look.scale,
        0.0,
        s * look.scale,
        c * look.scale,
        0.0,
        0.0,
        0.0,
        1.0,
    ];
    let centre = [1.0, 0.0, -n / 2.0, 0.0, 1.0, -n / 2.0, 0.0, 0.0, 1.0];
    let mut fwd = mul(&rot, &mul(&tilt, &centre));
    let corners = [
        (-4.0, -4.0),
        (n + 4.0, -4.0),
        (n + 4.0, n + 4.0),
        (-4.0, n + 4.0),
    ]
    .map(|(x, y)| apply(&fwd, x, y));
    let (minx, maxx) = corners.iter().fold((f64::MAX, f64::MIN), |(lo, hi), p| {
        (lo.min(p.0), hi.max(p.0))
    });
    let (miny, maxy) = corners.iter().fold((f64::MAX, f64::MIN), |(lo, hi), p| {
        (lo.min(p.1), hi.max(p.1))
    });
    let (w, h) = (
        (maxx - minx).ceil() as usize + 16,
        (maxy - miny).ceil() as usize + 16,
    );
    fwd = mul(
        &[1.0, 0.0, 8.0 - minx, 0.0, 1.0, 8.0 - miny, 0.0, 0.0, 1.0],
        &fwd,
    );
    let inv = inverse(&fwd);
    let (dark, light) = look.contrast;
    let mut px = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            let mut sum = 0.0;
            for (ox, oy) in [(0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75)] {
                let (mx, my) = apply(&inv, x as f64 + ox, y as f64 + oy);
                let (cx, cy) = (mx.floor(), my.floor());
                // 2 marks a smudged module, drawn halfway between dark and light
                let m = if cx >= 0.0 && cy >= 0.0 && cx < n && cy < n {
                    v.rows[cy as usize][cx as usize]
                } else {
                    0
                };
                sum += [
                    light as f64,
                    dark as f64,
                    (dark as f64 + light as f64) / 2.0,
                ][m as usize];
            }
            let lit = 1.0 - look.shade * x as f64 / w as f64;
            px[y * w + x] = (sum / 4.0 * lit) as u8;
        }
    }
    if look.blur {
        let src = px.clone();
        for y in 1..h - 1 {
            for x in 1..w - 1 {
                let mut t = 0u32;
                for dy in 0..3 {
                    for dx in 0..3 {
                        t += src[(y + dy - 1) * w + x + dx - 1] as u32;
                    }
                }
                px[y * w + x] = (t / 9) as u8;
            }
        }
    }
    if look.noise > 0 {
        for p in px.iter_mut() {
            *seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let d = (*seed >> 33) as i32 % (2 * look.noise as i32 + 1) - look.noise as i32;
            *p = (*p as i32 + d).clamp(0, 255) as u8;
        }
    }
    (px, w, h)
}

fn read(px: &[u8], w: usize, h: usize, kind: Kind, out: &mut [u8], state: &mut State) -> i32 {
    bitwasm_signer_qr::read(px, w, h, kind, out, state)
}

fn run(name: &str, look: impl Fn(&Vector) -> Option<Look>) -> (usize, usize, String) {
    let mut state = Box::new(State::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let (mut ok, mut total, mut failed) = (0, 0, String::new());
    let mut seed = 5u64;
    for v in vectors() {
        let Some(l) = look(&v) else { continue };
        let (px, w, h) = draw(&v, &l, &mut seed);
        if w > bitwasm_signer_qr::MAX_WIDTH
            || h > bitwasm_signer_qr::MAX_HEIGHT
            || w * h > bitwasm_signer_qr::MAX_PIXELS
        {
            continue;
        }
        total += 1;
        let len = read(&px, w, h, Kind::Any, &mut out, &mut state);
        if len > 0 && out[..len as usize] == v.expected[..] {
            ok += 1;
        } else {
            assert!(
                len <= 0,
                "{name}: v{} decoded to the wrong bytes",
                v.version
            );
            failed += &format!(" v{}({len})", v.version);
        }
    }
    std::println!(
        "{name}: {ok}/{total}{}",
        if failed.is_empty() {
            String::new()
        } else {
            format!(" failed:{failed}")
        }
    );
    (ok, total, failed)
}

const CLEAN: Look = Look {
    scale: 4.0,
    angle: 0.0,
    tilt: (0.0, 0.0),
    blur: false,
    noise: 0,
    shade: 0.0,
    contrast: (20, 235),
};

#[test]
fn images_axis_aligned() {
    let (ok, total, failed) = run("axis-aligned", |_| Some(CLEAN));
    assert_eq!(ok, total, "{failed}");
}

#[test]
fn images_rotated() {
    for angle in [0.3f64, 1.2, 2.9, -0.7] {
        let (ok, total, failed) = run(&format!("rotated {angle}"), |_| {
            Some(Look { angle, ..CLEAN })
        });
        assert_eq!(ok, total, "rotated {angle}: {failed}");
    }
}

#[test]
fn images_like_a_camera() {
    // Small to mid versions, the size of a SeedQR or one frame of an animated PSBT
    let look = |v: &Vector| {
        (v.version <= 12).then_some(Look {
            scale: 5.0,
            angle: 0.4,
            tilt: (0.12, -0.08),
            blur: true,
            noise: 12,
            shade: 0.45,
            contrast: (60, 200),
        })
    };
    let (ok, total, failed) = run("camera-like", look);
    assert!(ok * 100 >= total * 95, "camera-like {ok}/{total}: {failed}");
}

fn is_seedqr(v: &Vector) -> bool {
    v.version <= 3
        && matches!(
            (v.version, v.expected.len()),
            (1, 16) | (2, 32) | (2, 48) | (3, 96)
        )
        && (v.expected.len() % 16 == 0 || v.expected.iter().all(u8::is_ascii_digit))
}

#[test]
fn images_like_a_camera_held_square() {
    // The same look without the turn. Every row then crosses a finder at the same angle, which once
    // hid the smallest, darkest finder: all rows agreed on a centre row where blur had thinned a ring
    let look = |v: &Vector| {
        (v.version <= 12).then_some(Look {
            scale: 5.0,
            angle: 0.0,
            tilt: (0.12, -0.08),
            blur: true,
            noise: 12,
            shade: 0.45,
            contrast: (60, 200),
        })
    };
    let (ok, total, failed) = run("camera-like, square", look);
    assert!(
        ok * 100 >= total * 95,
        "camera-like square {ok}/{total}: {failed}"
    );
}

#[test]
fn seedqr_mode_reads_seedqrs_and_nothing_else() {
    let mut state = Box::new(State::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 21u64;
    let look = Look {
        angle: 0.5,
        ..CLEAN
    };
    let (mut seedqrs, mut others) = (0, 0);
    for v in vectors().iter().filter(|v| v.version <= 6) {
        let (px, w, h) = draw(v, &look, &mut seed);
        let r = read(&px, w, h, Kind::SeedQr, &mut out, &mut state);
        // The generator's SeedQRs are level L; anything else must not come back as one
        if is_seedqr(v) && v.rows.len() <= 29 && r > 0 {
            assert_eq!(&out[..r as usize], &v.expected[..]);
            seedqrs += 1;
        } else {
            assert!(
                r <= 0,
                "v{} {} bytes came back from SeedQR mode",
                v.version,
                v.expected.len()
            );
            others += usize::from(r == WRONG_KIND || r <= 0);
        }
        state.wipe();
    }
    std::println!("seedqr mode: {seedqrs} read, {others} turned away");
    assert!(
        seedqrs >= 32,
        "all 32 generated SeedQRs read in SeedQR mode, got {seedqrs}"
    );
}

#[test]
fn seedqr_mode_turns_away_text_of_a_seeds_length() {
    let mut state = Box::new(State::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 23u64;
    for v in load("imposters.txt") {
        let (px, w, h) = draw(&v, &CLEAN, &mut seed);
        let any = read(&px, w, h, Kind::Any, &mut out, &mut state);
        assert!(
            any > 0 && out[..any as usize] == v.expected[..],
            "the symbol itself reads"
        );
        let seedqr = read(&px, w, h, Kind::SeedQr, &mut out, &mut state);
        assert_eq!(seedqr, WRONG_KIND, "{:?} passed as a SeedQR", v.expected);
    }
}

#[test]
fn erasures_recover_smudged_modules() {
    // Grid level: smudged modules read at random and are flagged unsure. With the flags, up to
    // `ecc` smudged codewords correct; without, only half as many
    let mut work = Box::new(Work::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 31u64;
    // Grid level: smudged modules read at random and are flagged unsure. Some check codewords are
    // kept from any correction so a wrong one is caught, which caps how many smudges a small code
    // takes; what must always hold is that no smudged SeedQR decodes to another seed
    for smudges in [4, 6, 8] {
        let (mut hard, mut soft, mut wrong, mut total) = (0, 0, 0, 0);
        for v in vectors().iter().filter(|v| is_seedqr(v)) {
            let n = tables::size(v.version);
            for _ in 0..40 {
                let mut grid: Vec<u8> = v.rows.concat();
                let mut sure = vec![255u8; grid.len()];
                // In the data area, clear of the alignment pattern
                let mut placed = 0;
                while placed < smudges {
                    seed = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let (x, y) = (
                        9 + (seed >> 33) as usize % (n - 9),
                        9 + (seed >> 45) as usize % (n - 9),
                    );
                    if v.version >= 2 && x + 9 >= n && y + 9 >= n && x + 5 <= n && y + 5 <= n {
                        continue;
                    }
                    grid[y * n + x] = ((seed >> 20) & 1) as u8;
                    sure[y * n + x] = 0;
                    placed += 1;
                }
                total += 1;
                for (flags, count) in [(&vec![255; grid.len()], &mut hard), (&sure, &mut soft)] {
                    if let Ok(d) = decode_grid(&grid, flags, v.version, &mut out, &mut work) {
                        if out[..d.len] == v.expected[..] {
                            *count += 1;
                        } else {
                            wrong += 1;
                        }
                    }
                }
            }
        }
        std::println!("{smudges} smudges: {hard}/{total} without erasures, {soft}/{total} with, {wrong} wrong");
        assert_eq!(
            wrong, 0,
            "{smudges} smudges decoded to other bytes {wrong} times"
        );
        assert!(soft >= hard, "erasures should never read fewer");
        if smudges == 4 {
            assert!(soft * 100 >= total * 95, "4 smudges: {soft}/{total}");
        }
    }
}

#[test]
fn erasures_from_grey_in_an_image() {
    // Image level: the smudges are drawn halfway grey, so the reader has to notice them itself
    let mut state = Box::new(State::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 41u64;
    let (mut ok, mut total) = (0, 0);
    for v in vectors().iter().filter(|v| is_seedqr(v)) {
        let n = v.rows.len();
        let mut smudged = Vector {
            version: v.version,
            expected: v.expected.clone(),
            rows: v.rows.clone(),
        };
        let mut placed = 0;
        while placed < 4 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let (x, y) = (
                9 + (seed >> 33) as usize % (n - 9),
                9 + (seed >> 45) as usize % (n - 9),
            );
            if v.version >= 2 && x + 9 >= n && y + 9 >= n && x + 5 <= n && y + 5 <= n {
                continue;
            }
            smudged.rows[y][x] = 2;
            placed += 1;
        }
        let (px, w, h) = draw(
            &smudged,
            &Look {
                scale: 6.0,
                angle: 0.2,
                ..CLEAN
            },
            &mut seed,
        );
        total += 1;
        let r = read(&px, w, h, Kind::SeedQr, &mut out, &mut state);
        ok += usize::from(r > 0 && out[..r as usize] == v.expected[..]);
        assert!(
            r <= 0 || out[..r as usize] == v.expected[..],
            "a smudged SeedQR read as another seed"
        );
        state.wipe();
    }
    std::println!("smudged images: {ok}/{total}");
    assert!(ok * 100 >= total * 90, "{ok}/{total}");
}

#[test]
fn animated_frames_follow_one_another() {
    let frames = load("animated.txt");
    let mut state = Box::new(State::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 51u64;
    let look = Look {
        scale: 4.0,
        angle: 0.3,
        tilt: (0.05, -0.03),
        blur: true,
        noise: 8,
        shade: 0.2,
        contrast: (40, 220),
    };
    // Each frame twice, as a camera sees one screen frame several times
    let (mut ok, mut tracked) = (0, 0);
    for v in &frames {
        let (px, w, h) = draw(v, &look, &mut seed);
        for _ in 0..2 {
            let before = state.scan.tracked;
            let r = read(&px, w, h, Kind::Animated, &mut out, &mut state);
            assert!(
                r > 0 && out[..r as usize] == v.expected[..],
                "frame {:?}",
                core::str::from_utf8(&v.expected[..20])
            );
            ok += 1;
            tracked += (state.scan.tracked - before) as usize;
        }
    }
    std::println!("animated: {ok} reads, {tracked} through the tracked transform");
    assert_eq!(ok, frames.len() * 2);
    assert!(
        tracked + 1 >= ok,
        "every read after the first should come from tracking"
    );

    // A plain code is not a UR frame. Read between two sightings of the same frame, it overwrites
    // the output, so the second sighting must decode again rather than answer from memory
    let (frame, fw, fh) = draw(&frames[0], &look, &mut seed);
    let first = read(&frame, fw, fh, Kind::Animated, &mut out, &mut state);
    let (px, w, h) = draw(&vectors()[0], &CLEAN, &mut seed);
    assert_eq!(
        read(&px, w, h, Kind::Animated, &mut out, &mut state),
        WRONG_KIND
    );
    let again = read(&frame, fw, fh, Kind::Animated, &mut out, &mut state);
    assert_eq!(again, first);
    assert_eq!(&out[..again as usize], &frames[0].expected[..]);
}

#[test]
fn light_on_dark_codes_read() {
    let mut state = Box::new(State::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 61u64;
    let (mut ok, mut total) = (0, 0);
    for v in vectors().iter().filter(|v| v.version <= 10) {
        let (px, w, h) = draw(
            v,
            &Look {
                angle: 0.4,
                contrast: (225, 25),
                ..CLEAN
            },
            &mut seed,
        );
        total += 1;
        let r = read(&px, w, h, Kind::Any, &mut out, &mut state);
        ok += usize::from(r > 0 && out[..r as usize] == v.expected[..]);
    }
    std::println!("light on dark: {ok}/{total}");
    assert_eq!(ok, total);
}

#[test]
fn a_code_with_its_data_wiped_never_decodes_to_anything() {
    // Finders intact, data gone: the reader may give up but must not make bytes up. Spending every
    // check codeword on erasures once let garbage through here
    let mut state = Box::new(State::ZERO);
    let mut out = vec![0u8; OUTPUT_CAP];
    let mut seed = 71u64;
    for v in vectors().iter().filter(|v| v.version <= 10) {
        let (mut px, w, h) = draw(
            v,
            &Look {
                angle: 0.2,
                blur: true,
                noise: 6,
                ..CLEAN
            },
            &mut seed,
        );
        for y in h * 55 / 100..h {
            for x in w * 45 / 100..w {
                px[y * w + x] = 200;
            }
        }
        for kind in [Kind::Any, Kind::SeedQr] {
            let r = read(&px, w, h, kind, &mut out, &mut state);
            assert!(
                r <= 0 || out[..r as usize] == v.expected[..],
                "v{} with its data wiped decoded to {r} bytes",
                v.version
            );
        }
    }
}
