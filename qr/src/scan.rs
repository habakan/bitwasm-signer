//! Finding a QR in a dark/light image: the three finder patterns, the alignment pattern, the
//! perspective that maps modules to pixels, and the grid sampled through it.

use crate::binarize::BLOCK;
use crate::decode::{self, Error, Work};
use crate::tables::{self, size};

#[derive(Clone, Copy, Default)]
pub struct Finder {
    pub x: f32,
    pub y: f32,
    /// Module size in pixels
    pub ms: f32,
    pub hits: u32,
}

pub const MAX_FINDERS: usize = 64;

/// The frame: its grey and the threshold of each 8x8 block. `inverted` reads a light-on-dark code as
/// if it were dark-on-light
pub struct Image<'a> {
    pub grey: &'a [u8],
    pub thresholds: &'a [u8],
    pub w: i32,
    pub h: i32,
    pub inverted: bool,
}

impl Image<'_> {
    /// Inside the frame only
    fn at(&self, x: i32, y: i32) -> bool {
        let bw = (self.w as usize).div_ceil(BLOCK);
        let threshold = self.thresholds[y as usize / BLOCK * bw + x as usize / BLOCK];
        (self.grey[(y * self.w + x) as usize] <= threshold) != self.inverted
    }

    fn dark(&self, x: i32, y: i32) -> Option<bool> {
        (x >= 0 && y >= 0 && x < self.w && y < self.h).then(|| self.at(x, y))
    }

    /// The majority of a pixel and its two neighbours along (dx, dy), for checking a candidate: a
    /// lone noisy pixel would otherwise cut a ring short. Too costly for the scan of every row
    fn dark_along(&self, x: i32, y: i32, dx: i32, dy: i32) -> Option<bool> {
        let here = self.dark(x, y)?;
        let before = self.dark(x - dx, y - dy).unwrap_or(here);
        let after = self.dark(x + dx, y + dy).unwrap_or(here);
        Some(if before == after { before } else { here })
    }

    /// The colour of the module whose corners `t` maps from (mx, my) to (mx + 1, my + 1), from the
    /// mean grey of five points across it, and how far that mean sits from the threshold
    fn module(&self, t: &Transform, mx: f64, my: f64) -> (bool, u8) {
        let mut sum = 0u32;
        for (ox, oy) in [(0.5, 0.5), (0.3, 0.3), (0.7, 0.3), (0.3, 0.7), (0.7, 0.7)] {
            let (px, py) = t.apply(mx + ox, my + oy);
            let (x, y) = (round(px as f32), round(py as f32));
            if x < 0 || y < 0 || x >= self.w || y >= self.h {
                return (false, 0);
            }
            sum += self.grey[(y * self.w + x) as usize] as u32;
        }
        let (px, py) = t.apply(mx + 0.5, my + 0.5);
        let (x, y) = (
            round(px as f32).clamp(0, self.w - 1),
            round(py as f32).clamp(0, self.h - 1),
        );
        let bw = (self.w as usize).div_ceil(BLOCK);
        let threshold = self.thresholds[y as usize / BLOCK * bw + x as usize / BLOCK] as i32;
        let mean = (sum / 5) as i32;
        (
            (mean <= threshold) != self.inverted,
            mean.abs_diff(threshold).min(255) as u8,
        )
    }
}

fn abs(v: f32) -> f32 {
    if v < 0.0 {
        -v
    } else {
        v
    }
}

fn round(v: f32) -> i32 {
    if v < 0.0 {
        (v - 0.5) as i32
    } else {
        (v + 0.5) as i32
    }
}

fn sqrt(v: f32) -> f32 {
    // Newton's method: core has no sqrt without std, and pulling in libm would add imports
    if v <= 0.0 {
        return 0.0;
    }
    let mut x = if v > 1.0 { v / 2.0 } else { 1.0 };
    for _ in 0..20 {
        x = 0.5 * (x + v / x);
    }
    x
}

/// 1:1:3:1:1 within half a module each, the finder pattern's runs through its centre
fn finder_ratio(c: &[u32; 5]) -> bool {
    let total: u32 = c.iter().sum();
    if total < 7 {
        return false;
    }
    let m = total as f32 / 7.0;
    let v = m / 2.0;
    abs(m - c[0] as f32) < v
        && abs(m - c[1] as f32) < v
        && abs(3.0 * m - c[2] as f32) < 3.0 * v
        && abs(m - c[3] as f32) < v
        && abs(m - c[4] as f32) < v
}

/// Walks out from (x, y) both ways along (dx, dy) and checks the runs look like a finder. Returns the
/// centre's offset along the line and the pattern's length
fn cross_check(img: &Image, x: i32, y: i32, dx: i32, dy: i32, max: u32) -> Option<(f32, u32)> {
    let mut c = [0u32; 5];
    let (mut px, mut py) = (x, y);
    while img.dark_along(px, py, dx, dy)? {
        c[2] += 1;
        px -= dx;
        py -= dy;
    }
    while !img.dark_along(px, py, dx, dy)? {
        c[1] += 1;
        if c[1] > max {
            return None;
        }
        px -= dx;
        py -= dy;
    }
    while img.dark_along(px, py, dx, dy) == Some(true) {
        c[0] += 1;
        if c[0] > max {
            return None;
        }
        px -= dx;
        py -= dy;
    }
    let mut t = 1;
    while img.dark_along(x + t * dx, y + t * dy, dx, dy)? {
        c[2] += 1;
        t += 1;
    }
    while !img.dark_along(x + t * dx, y + t * dy, dx, dy)? {
        c[3] += 1;
        if c[3] > max {
            return None;
        }
        t += 1;
    }
    while img.dark_along(x + t * dx, y + t * dy, dx, dy) == Some(true) {
        c[4] += 1;
        if c[4] > max {
            return None;
        }
        t += 1;
    }
    finder_ratio(&c).then(|| {
        (
            t as f32 - c[4] as f32 - c[3] as f32 - c[2] as f32 / 2.0,
            c.iter().sum(),
        )
    })
}

fn add(finders: &mut [Finder; MAX_FINDERS], count: &mut usize, x: f32, y: f32, ms: f32) {
    for f in finders[..*count].iter_mut() {
        if abs(f.x - x) <= f.ms && abs(f.y - y) <= f.ms && abs(f.ms - ms) <= f.ms.max(1.0) {
            let n = f.hits as f32;
            f.x = (f.x * n + x) / (n + 1.0);
            f.y = (f.y * n + y) / (n + 1.0);
            f.ms = (f.ms * n + ms) / (n + 1.0);
            f.hits += 1;
            return;
        }
    }
    // A large code's data holds many one-row look-alikes; once the list is full, a new candidate
    // takes the place of one only a single row has seen, so the real finders are not crowded out
    let at = if *count < MAX_FINDERS {
        *count += 1;
        *count - 1
    } else if let Some(i) = finders.iter().position(|f| f.hits == 1) {
        i
    } else {
        return;
    };
    finders[at] = Finder { x, y, ms, hits: 1 };
}

/// Scans every row for 1:1:3:1:1 runs and confirms each down the column and back along the row
pub fn find_finders(img: &Image, finders: &mut [Finder; MAX_FINDERS]) -> usize {
    let (w, h) = (img.w as usize, img.h as usize);
    let mut count = 0;
    for y in 0..h {
        let mut runs = [0u32; 5];
        let mut run = 0u32;
        let mut seen = 0;
        let mut prev = false;
        for x in 0..=w {
            let here = (x < w).then(|| img.at(x as i32, y as i32));
            if x > 0 && here == Some(prev) {
                run += 1;
                continue;
            }
            // A lone pixel is noise: it joins the run before it, which goes on through this pixel
            if run == 1 && seen >= 1 && here.is_some() {
                run = runs[4] + 2;
                runs.copy_within(0..4, 1);
                runs[0] = 0;
                seen -= 1;
                prev = !prev;
                continue;
            }
            if x > 0 {
                runs.copy_within(1..5, 0);
                runs[4] = run;
                seen += 1;
                // The run just closed was dark: x - 1 was dark
                if seen >= 5 && prev && finder_ratio(&runs) {
                    let total: u32 = runs.iter().sum();
                    let cx = x as f32 - runs[4] as f32 - runs[3] as f32 - runs[2] as f32 / 2.0;
                    let (ix, iy) = (cx as i32, y as i32);
                    if let Some((oy, vt)) = cross_check(img, ix, iy, 0, 1, runs[2]) {
                        // A tall run is a different shape seen through a gap, not a finder
                        if 5 * vt.abs_diff(total) < 2 * total {
                            let cy = iy as f32 + oy;
                            // Confirmed back along the row through the centre, or the rows beside it
                            // or the one it was found on: every row finds the same centre, so if blur
                            // has thinned a ring on that one row, the finder would never be confirmed
                            let rows = [cy as i32, cy as i32 - 1, cy as i32 + 1, iy];
                            if let Some((ox, ht)) = rows
                                .iter()
                                .find_map(|&r| cross_check(img, ix, r, 1, 0, runs[2]))
                            {
                                let ms = (vt + ht) as f32 / 14.0;
                                add(finders, &mut count, ix as f32 + ox, cy, ms);
                            }
                        }
                    }
                }
            }
            run = 1;
            prev = here.unwrap_or(false);
        }
    }
    count
}

/// A homography, as the 3x3 matrix ZXing and others call PerspectiveTransform
#[derive(Clone, Copy)]
struct Transform([f64; 9]);

impl Transform {
    /// The unit square's corners (0,0), (1,0), (1,1), (0,1) to the four points given
    fn square_to_quad(p: [(f64, f64); 4]) -> Transform {
        let [(x0, y0), (x1, y1), (x2, y2), (x3, y3)] = p;
        let (dx3, dy3) = (x0 - x1 + x2 - x3, y0 - y1 + y2 - y3);
        if dx3 == 0.0 && dy3 == 0.0 {
            return Transform([x1 - x0, x2 - x1, x0, y1 - y0, y2 - y1, y0, 0.0, 0.0, 1.0]);
        }
        let (dx1, dx2, dy1, dy2) = (x1 - x2, x3 - x2, y1 - y2, y3 - y2);
        let denom = dx1 * dy2 - dx2 * dy1;
        let g = (dx3 * dy2 - dx2 * dy3) / denom;
        let h = (dx1 * dy3 - dx3 * dy1) / denom;
        Transform([
            x1 - x0 + g * x1,
            x3 - x0 + h * x3,
            x0,
            y1 - y0 + g * y1,
            y3 - y0 + h * y3,
            y0,
            g,
            h,
            1.0,
        ])
    }

    /// The inverse up to scale, which is all a homography needs
    fn adjoint(&self) -> Transform {
        let [a, b, c, d, e, f, g, h, i] = self.0;
        Transform([
            e * i - f * h,
            c * h - b * i,
            b * f - c * e,
            f * g - d * i,
            a * i - c * g,
            c * d - a * f,
            d * h - e * g,
            b * g - a * h,
            a * e - b * d,
        ])
    }

    fn then(&self, next: &Transform) -> Transform {
        let (a, b) = (&next.0, &self.0);
        let mut m = [0.0; 9];
        for r in 0..3 {
            for c in 0..3 {
                m[r * 3 + c] = (0..3).map(|k| a[r * 3 + k] * b[k * 3 + c]).sum();
            }
        }
        Transform(m)
    }

    fn apply(&self, x: f64, y: f64) -> (f64, f64) {
        let m = &self.0;
        let z = m[6] * x + m[7] * y + m[8];
        (
            (m[0] * x + m[1] * y + m[2]) / z,
            (m[3] * x + m[4] * y + m[5]) / z,
        )
    }

    /// Module coordinates to pixels, from four matching points
    fn between(modules: [(f64, f64); 4], pixels: [(f64, f64); 4]) -> Transform {
        Transform::square_to_quad(modules)
            .adjoint()
            .then(&Transform::square_to_quad(pixels))
    }
}

pub const MAX_ALIGN: usize = 8;

/// Candidates for the alignment pattern near `(ex, ey)`, nearest first: a dark module ringed by light
/// and then dark, one module each. Data can look the same, so the caller picks by how well each fits
fn find_alignment(
    img: &Image,
    ex: f32,
    ey: f32,
    ms: f32,
    found: &mut [(f32, f32, f32); MAX_ALIGN],
) -> usize {
    let near = |c: u32| abs(c as f32 - ms) < ms * 0.7;
    let mut count = 0;
    let r = 8.0 * ms;
    let (x0, x1) = (round(ex - r).max(0), round(ex + r).min(img.w - 1));
    let (y0, y1) = (round(ey - r).max(0), round(ey + r).min(img.h - 1));
    if x0 >= x1 || y0 >= y1 {
        return 0;
    }
    for y in y0..=y1 {
        let mut runs = [0u32; 3];
        let mut colours = [false; 3];
        let mut run = 0u32;
        let mut prev = img.at(x0, y);
        for x in x0..=x1 {
            let here = img.at(x, y);
            if here == prev {
                run += 1;
                continue;
            }
            runs.copy_within(1..3, 0);
            colours.copy_within(1..3, 0);
            runs[2] = run;
            colours[2] = prev;
            // light, dark, light, and the pixel after is dark again
            if !colours[0] && colours[1] && !colours[2] && here && runs.iter().all(|&c| near(c)) {
                let cx = x as f32 - runs[2] as f32 - runs[1] as f32 / 2.0;
                if let Some(cy) = check_alignment_column(img, cx as i32, y, ms) {
                    let d = (cx - ex) * (cx - ex) + (cy - ey) * (cy - ey);
                    // Rows through the same pattern land on the same spot; keep the nearest few spots
                    if !found[..count]
                        .iter()
                        .any(|p| abs(p.0 - cx) < ms && abs(p.1 - cy) < ms)
                    {
                        let at = found[..count].iter().position(|p| d < p.2).unwrap_or(count);
                        if at < MAX_ALIGN {
                            let end = count.min(MAX_ALIGN - 1);
                            found.copy_within(at..end, at + 1);
                            found[at] = (cx, cy, d);
                            count = (count + 1).min(MAX_ALIGN);
                        }
                    }
                }
            }
            prev = here;
            run = 1;
        }
    }
    count
}

fn check_alignment_column(img: &Image, x: i32, y: i32, ms: f32) -> Option<f32> {
    let max = (ms * 2.0) as u32 + 1;
    let mut c = [0u32; 3];
    let mut t = 0;
    while img.dark(x, y - t)? {
        c[1] += 1;
        t += 1;
        if c[1] > max {
            return None;
        }
    }
    while !img.dark(x, y - t)? {
        c[0] += 1;
        t += 1;
        if c[0] > max {
            return None;
        }
    }
    let mut t = 1;
    while img.dark(x, y + t)? {
        c[1] += 1;
        t += 1;
        if c[1] > max {
            return None;
        }
    }
    let end_dark = t;
    while !img.dark(x, y + t)? {
        c[2] += 1;
        t += 1;
        if c[2] > max {
            return None;
        }
    }
    let near = |c: u32| abs(c as f32 - ms) < ms * 0.7;
    c.iter()
        .all(|&v| near(v))
        .then(|| y as f32 + end_dark as f32 - c[1] as f32 / 2.0)
}

/// A finder's width along (ux, uy), from the centre out past the dark ring both ways: seven modules
fn finder_width(img: &Image, f: &Finder, ux: f32, uy: f32) -> Option<f32> {
    let mut width = 0.0;
    for dir in [1.0f32, -1.0] {
        let (mut state, mut t) = (0, 0.0f32);
        while state < 3 {
            t += 0.5;
            if t > f.ms * 12.0 {
                return None;
            }
            let dark = img.dark(round(f.x + dir * ux * t), round(f.y + dir * uy * t))?;
            // dark centre, light ring, dark ring, then light outside
            if dark == (state % 2 == 1) {
                state += 1;
            }
        }
        width += t;
    }
    Some(width)
}

/// Modules across the code, from the finders' widths measured along each edge: a module size taken
/// from horizontal runs is too large once the code is turned
fn modules_across(img: &Image, f: &[Finder; 3]) -> f32 {
    let [tl, tr, bl] = f;
    let along = |a: &Finder, b: &Finder| {
        let d = sqrt((b.x - a.x) * (b.x - a.x) + (b.y - a.y) * (b.y - a.y));
        let (ux, uy) = ((b.x - a.x) / d, (b.y - a.y) / d);
        let ms = match (finder_width(img, a, ux, uy), finder_width(img, b, ux, uy)) {
            (Some(p), Some(q)) => (p + q) / 14.0,
            _ => (a.ms + b.ms) / 2.0,
        };
        d / ms + 7.0
    };
    (along(tl, tr) + along(tl, bl)) / 2.0
}

/// Three finders in the order top-left, top-right, bottom-left, if they could be one code's corners
fn corners(a: &Finder, b: &Finder, c: &Finder) -> Option<([Finder; 3], f32)> {
    let d2 = |p: &Finder, q: &Finder| (p.x - q.x) * (p.x - q.x) + (p.y - q.y) * (p.y - q.y);
    let (ab, bc, ca) = (d2(a, b), d2(b, c), d2(c, a));
    // The corner is the finder opposite the longest side
    let (tl, p, q, long, s1, s2) = if bc >= ab && bc >= ca {
        (a, b, c, bc, ab, ca)
    } else if ca >= ab {
        (b, c, a, ca, bc, ab)
    } else {
        (c, a, b, ab, ca, bc)
    };
    let (lo, hi) = (a.ms.min(b.ms).min(c.ms), a.ms.max(b.ms).max(c.ms));
    if hi > lo * 2.0 {
        return None;
    }
    // Close to a right isosceles triangle, loosely enough for a code seen at an angle
    let legs = abs(s1 - s2) / s1.max(s2);
    let right = abs(long - s1 - s2) / long;
    if legs > 0.6 || right > 0.4 || s1.min(s2) < (7.0 * lo) * (7.0 * lo) {
        return None;
    }
    let cross = (p.x - tl.x) * (q.y - tl.y) - (p.y - tl.y) * (q.x - tl.x);
    let order = if cross > 0.0 {
        [*tl, *p, *q]
    } else {
        [*tl, *q, *p]
    };
    Some((order, legs + right))
}

/// Function modules of a version 40 code and the ring of quiet zone around it
const MAX_KNOWN: usize = 2500;

/// Modules every code of this version shares: finders and their separators, the timing patterns,
/// the alignment patterns, the dark module, and the light ring just outside, which is all that pins
/// the far corner of a version 1 code
fn known(version: usize, list: &mut [(i16, i16, bool); MAX_KNOWN]) -> usize {
    let n = size(version);
    let mut k = 0;
    for i in -1..=n as i16 {
        list[k] = (i, -1, false);
        list[k + 1] = (i, n as i16, false);
        list[k + 2] = (-1, i, false);
        list[k + 3] = (n as i16, i, false);
        k += 4;
    }
    let mut push = |x: usize, y: usize, dark: bool| {
        list[k] = (x as i16, y as i16, dark);
        k += 1;
    };
    for (ox, oy) in [(0, 0), (n - 7, 0), (0, n - 7)] {
        for dy in 0..7usize {
            for dx in 0..7usize {
                push(ox + dx, oy + dy, dx.abs_diff(3).max(dy.abs_diff(3)) != 2);
            }
        }
    }
    for i in 0..8 {
        push(7, i, false);
        push(i, 7, false);
        push(n - 8, i, false);
        push(n - 8 + i, 7, false);
        push(7, n - 1 - i, false);
        push(i, n - 8, false);
    }
    for i in 8..n - 8 {
        push(i, 6, i % 2 == 0);
        push(6, i, i % 2 == 0);
    }
    let (pos, count) = tables::alignment_positions(version);
    for i in 0..count {
        for j in 0..count {
            if (i == 0 && j == 0) || (i == 0 && j == count - 1) || (i == count - 1 && j == 0) {
                continue;
            }
            for dy in 0..5usize {
                for dx in 0..5usize {
                    push(
                        pos[i] + dx - 2,
                        pos[j] + dy - 2,
                        dx.abs_diff(2).max(dy.abs_diff(2)) != 1,
                    );
                }
            }
        }
    }
    push(8, n - 8, true);
    k
}

fn fitness(img: &Image, t: &Transform, known: &[(i16, i16, bool)]) -> usize {
    known
        .iter()
        .filter(|&&(x, y, dark)| {
            let (px, py) = t.apply(x as f64 + 0.5, y as f64 + 0.5);
            img.dark(round(px as f32), round(py as f32)) == Some(dark)
        })
        .count()
}

type Quad = [(f64, f64); 4];

/// Module coordinates of the four anchors: three finder centres and the alignment pattern from
/// version 2 on, otherwise where the centre of a fourth finder would be
fn anchors(version: usize) -> Quad {
    let n = size(version) as f64;
    let a = if version >= 2 { n - 6.5 } else { n - 3.5 };
    [(3.5, 3.5), (n - 3.5, 3.5), (a, a), (3.5, n - 3.5)]
}

/// Where the anchors fall in the image: the finder centres, and for the fourth whichever of the flat
/// estimate and the alignment candidates fits best. Then each point is nudged while more of the
/// known modules come out right. A real perspective is one homography, so four well-placed points
/// sample it exactly
fn place(
    img: &Image,
    f: &[Finder; 3],
    version: usize,
    known: &[(i16, i16, bool)],
) -> (Quad, usize) {
    let modules = anchors(version);
    let [tl, tr, bl] = f;
    let ms = ((tl.ms + tr.ms + bl.ms) / 3.0) as f64;
    let k = ((modules[2].0 - 3.5) / (modules[1].0 - 3.5)) as f32;
    let (ex, ey) = (
        tl.x + (tr.x - tl.x + bl.x - tl.x) * k,
        tl.y + (tr.y - tl.y + bl.y - tl.y) * k,
    );
    let score = |q: &Quad| fitness(img, &Transform::between(modules, *q), known);

    let mut quad = [
        (tl.x as f64, tl.y as f64),
        (tr.x as f64, tr.y as f64),
        (ex as f64, ey as f64),
        (bl.x as f64, bl.y as f64),
    ];
    let mut best = score(&quad);
    if version >= 2 {
        let mut found = [(0.0f32, 0.0f32, 0.0f32); MAX_ALIGN];
        let count = find_alignment(img, ex, ey, ms as f32, &mut found);
        for &(x, y, _) in &found[..count] {
            let mut q = quad;
            q[2] = (x as f64, y as f64);
            let s = score(&q);
            if s > best {
                (best, quad) = (s, q);
            }
        }
    }
    let mut step = ms * 2.0;
    while step >= ms / 8.0 && best < known.len() {
        for _ in 0..16 {
            let mut improved = false;
            for i in 0..4 {
                for (dx, dy) in [(step, 0.0), (-step, 0.0), (0.0, step), (0.0, -step)] {
                    let mut q = quad;
                    q[i].0 += dx;
                    q[i].1 += dy;
                    let s = score(&q);
                    if s > best {
                        (best, quad, improved) = (s, q, true);
                    }
                }
            }
            if !improved {
                break;
            }
        }
        step /= 2.0;
    }
    (quad, best)
}

/// Patterns found to fit by least squares: three finders and up to 46 alignment patterns
const MAX_PAIRS: usize = 49;

/// The homography that best maps `from` to `to` in the least squares sense (DLT with h33 = 1).
/// Coordinates are scaled first so the 8x8 normal equations stay well conditioned
fn fit_homography(
    pairs: &[((f64, f64), (f64, f64))],
    module_scale: f64,
    pixel_scale: f64,
) -> Option<Transform> {
    let mut a = [[0.0f64; 9]; 8];
    for &((x, y), (u, v)) in pairs {
        let (x, y, u, v) = (
            x / module_scale,
            y / module_scale,
            u / pixel_scale,
            v / pixel_scale,
        );
        for (row, rhs) in [
            ([x, y, 1.0, 0.0, 0.0, 0.0, -x * u, -y * u], u),
            ([0.0, 0.0, 0.0, x, y, 1.0, -x * v, -y * v], v),
        ] {
            for i in 0..8 {
                for j in 0..8 {
                    a[i][j] += row[i] * row[j];
                }
                a[i][8] += row[i] * rhs;
            }
        }
    }
    // Gaussian elimination with partial pivoting
    for c in 0..8 {
        let p = (c..8).max_by(|&i, &j| {
            abs64(a[i][c])
                .partial_cmp(&abs64(a[j][c]))
                .unwrap_or(core::cmp::Ordering::Equal)
        })?;
        if abs64(a[p][c]) < 1e-12 {
            return None;
        }
        a.swap(c, p);
        for r in 0..8 {
            if r != c {
                let k = a[r][c] / a[c][c];
                for j in c..9 {
                    a[r][j] -= k * a[c][j];
                }
            }
        }
    }
    let h: [f64; 8] = core::array::from_fn(|i| a[i][8] / a[i][i]);
    // Undo the scaling: pixels = P * H * M^-1 with P = diag(s, s, 1) and M = diag(m, m, 1)
    let (m, s) = (module_scale, pixel_scale);
    Some(Transform([
        h[0] * s / m,
        h[1] * s / m,
        h[2] * s,
        h[3] * s / m,
        h[4] * s / m,
        h[5] * s,
        h[6] / m,
        h[7] / m,
        1.0,
    ]))
}

fn abs64(v: f64) -> f64 {
    if v < 0.0 {
        -v
    } else {
        v
    }
}

/// How many modules of a square pattern centred on module (cx, cy) match, sampled through `t` and
/// shifted by (dx, dy) pixels. `dark(ring)` gives each ring's colour out to `rings`
fn template(
    img: &Image,
    t: &Transform,
    cx: f64,
    cy: f64,
    dx: f64,
    dy: f64,
    rings: i32,
    dark: fn(i32) -> bool,
) -> usize {
    let mut hits = 0;
    for my in -rings..=rings {
        for mx in -rings..=rings {
            let (px, py) = t.apply(cx + mx as f64, cy + my as f64);
            hits += usize::from(
                img.dark(round((px + dx) as f32), round((py + dy) as f32))
                    == Some(dark(mx.abs().max(my.abs()))),
            );
        }
    }
    hits
}

/// Where the pattern centred on module (cx, cy) really is: the best match within `reach` quarter
/// modules of where `t` puts it, if it matches well enough to trust
#[allow(clippy::too_many_arguments)]
fn snap(
    img: &Image,
    t: &Transform,
    cx: f64,
    cy: f64,
    ms: f64,
    reach: i32,
    rings: i32,
    dark: fn(i32) -> bool,
    need: usize,
) -> Option<(f64, f64)> {
    let step = ms / 4.0;
    let mut best = (0, f64::MAX, 0.0, 0.0);
    for j in -reach..=reach {
        for i in -reach..=reach {
            let (dx, dy) = (i as f64 * step, j as f64 * step);
            let hits = template(img, t, cx, cy, dx, dy, rings, dark);
            let d = dx * dx + dy * dy;
            if hits > best.0 || (hits == best.0 && d < best.1) {
                best = (hits, d, dx, dy);
            }
        }
    }
    let (px, py) = t.apply(cx, cy);
    (best.0 >= need).then(|| (px + best.2, py + best.3))
}

/// Refits the transform to where the finders and alignment patterns really are, a few times over.
/// One alignment pattern cannot correct a strong perspective across a large code; all of them can
fn refit(img: &Image, version: usize, mut t: Transform, ms: f64) -> Option<Transform> {
    let n = size(version) as f64;
    let (pos, count) = tables::alignment_positions(version);
    let finder = |ring: i32| ring != 2 && ring != 4;
    let alignment = |ring: i32| ring != 1;
    // The first pass looks furthest, while the fit is still rough
    for reach in [12, 6, 4] {
        let mut pairs = [((0.0, 0.0), (0.0, 0.0)); MAX_PAIRS];
        let mut k = 0;
        for c in [(3.5, 3.5), (n - 3.5, 3.5), (3.5, n - 3.5)] {
            if let Some(p) = snap(img, &t, c.0, c.1, ms, reach, 4, finder, 75) {
                pairs[k] = (c, p);
                k += 1;
            }
        }
        for i in 0..count {
            for j in 0..count {
                if (i == 0 && j == 0) || (i == 0 && j == count - 1) || (i == count - 1 && j == 0) {
                    continue;
                }
                let c = (pos[i] as f64 + 0.5, pos[j] as f64 + 0.5);
                if let Some(p) = snap(img, &t, c.0, c.1, ms, reach, 2, alignment, 23) {
                    pairs[k] = (c, p);
                    k += 1;
                }
            }
        }
        if k < 4 {
            return None;
        }
        t = fit_homography(&pairs[..k], n, (img.w.max(img.h)) as f64)?;
    }
    Some(t)
}

/// Every module's colour into `grid` and how sure that is into `margin`
fn sample(img: &Image, t: &Transform, n: usize, grid: &mut [u8], margin: &mut [u8]) {
    for y in 0..n {
        for x in 0..n {
            let (dark, m) = img.module(t, x as f64, y as f64);
            grid[y * n + x] = u8::from(dark);
            margin[y * n + x] = m;
        }
    }
}

/// A fit made for version `from` restated for version `to`: the finders stay where they were found,
/// so module coordinates are scaled about the top-left finder's centre by the ratio of the spans
/// between finder centres. Under a strong perspective the estimated version is easily one off, and
/// this keeps the fit instead of starting over
fn rescale(t: &Transform, from: usize, to: usize) -> Transform {
    let s = (size(from) as f64 - 7.0) / (size(to) as f64 - 7.0);
    Transform([
        s,
        0.0,
        3.5 * (1.0 - s),
        0.0,
        s,
        3.5 * (1.0 - s),
        0.0,
        0.0,
        1.0,
    ])
    .then(t)
}

/// Whether all three finders look like finders in two dimensions: a 9x9 patch around each, laid
/// along the code's edges and scaled by the finder's own measured width. A row and a column through
/// texture can pass 1:1:3:1:1; a patch rarely does, and this costs 243 samples where a placement
/// costs thousands. Noise matches about half; 60% leaves room for blur
fn plausible(img: &Image, f: &[Finder; 3]) -> bool {
    let [tl, tr, bl] = f;
    let unit = |a: &Finder, b: &Finder| {
        let d = sqrt((b.x - a.x) * (b.x - a.x) + (b.y - a.y) * (b.y - a.y));
        ((b.x - a.x) / d, (b.y - a.y) / d)
    };
    let (u, v) = (unit(tl, tr), unit(tl, bl));
    f.iter().all(|c| {
        // Blur can hide a ring from the width walk; the module size from the runs then stands in
        let mu = finder_width(img, c, u.0, u.1).map_or(c.ms, |w| w / 7.0);
        let mv = finder_width(img, c, v.0, v.1).map_or(c.ms, |w| w / 7.0);
        let mut hits = 0;
        for my in -4i32..=4 {
            for mx in -4i32..=4 {
                let (x, y) = (
                    c.x + mx as f32 * mu * u.0 + my as f32 * mv * v.0,
                    c.y + mx as f32 * mu * u.1 + my as f32 * mv * v.1,
                );
                let ring = mx.abs().max(my.abs());
                hits += usize::from(img.dark(round(x), round(y)) == Some(ring != 2 && ring != 4));
            }
        }
        hits * 100 >= 81 * 60
    })
}

/// Triples placed per frame at most
const MAX_TRIPLES: usize = 6;

/// Offsets for the fourth point in modules, nearest first
#[rustfmt::skip]
const JIGGLE: [(f64, f64); 25] = [
    (0.0, 0.0), (0.5, 0.0), (-0.5, 0.0), (0.0, 0.5), (0.0, -0.5), (0.5, 0.5), (-0.5, -0.5), (0.5, -0.5), (-0.5, 0.5),
    (1.0, 0.0), (-1.0, 0.0), (0.0, 1.0), (0.0, -1.0), (1.0, 1.0), (-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0),
    (1.0, 0.5), (-1.0, -0.5), (0.5, 1.0), (-0.5, -1.0), (1.0, -0.5), (-1.0, 0.5), (0.5, -1.0), (-0.5, 1.0),
];

/// What the host is reading, so codes it is not expecting are turned away early
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Any,
    /// Standard or Compact SeedQR only: versions 1 to 3 at level L, 16 or 32 bytes or 48 or 96 digits
    SeedQr,
    /// Frames of an animated UR: the code is followed from frame to frame
    Animated,
}

/// A code was read that is not of the kind asked for
pub const WRONG_KIND: i32 = -3;

/// A Compact SeedQR is one byte segment of entropy and a Standard one a single numeric segment, at
/// level L; text that happens to have the right length is not a seed
fn accepted(kind: Kind, version: usize, d: &decode::Decoded, out: &[u8]) -> bool {
    match kind {
        Kind::Any => true,
        Kind::SeedQr => {
            d.level == 0
                && matches!(
                    (version, d.len, d.mode),
                    (1, 16, 4) | (2, 32, 4) | (2, 48, 1) | (3, 96, 1)
                )
        }
        Kind::Animated => out.len() >= 3 && out[..3].eq_ignore_ascii_case(b"ur:"),
    }
}

/// Where the last animated frame was found: its transform, version and length
#[derive(Clone, Copy)]
struct Track {
    t: Transform,
    version: usize,
    len: usize,
    live: bool,
    /// The output still holds that frame's bytes: any later decode, of any kind, may overwrite them
    held: bool,
}

const NO_TRACK: Track = Track {
    t: Transform([0.0; 9]),
    version: 0,
    len: 0,
    live: false,
    held: false,
};

pub struct Scan {
    pub finders: [Finder; MAX_FINDERS],
    pub grid: [u8; tables::MAX_SIZE * tables::MAX_SIZE],
    pub margin: [u8; tables::MAX_SIZE * tables::MAX_SIZE],
    /// The grid of the last animated frame read, to notice the same frame again
    prev: [u8; tables::MAX_SIZE * tables::MAX_SIZE],
    track: Track,
    /// Animated frames read through the tracked transform, without searching
    pub tracked: u32,
    /// Work left for this read, in units of one sampled-and-decoded grid
    budget: u32,
}

impl Scan {
    pub const ZERO: Scan = Scan {
        finders: [Finder {
            x: 0.0,
            y: 0.0,
            ms: 0.0,
            hits: 0,
        }; MAX_FINDERS],
        grid: [0; tables::MAX_SIZE * tables::MAX_SIZE],
        margin: [0; tables::MAX_SIZE * tables::MAX_SIZE],
        prev: [0; tables::MAX_SIZE * tables::MAX_SIZE],
        track: NO_TRACK,
        tracked: 0,
        budget: 0,
    };

    pub fn wipe(&mut self) {
        self.finders = [Finder::default(); MAX_FINDERS];
        self.grid.fill(0);
        self.margin.fill(0);
        self.prev.fill(0);
        self.track = NO_TRACK;
        self.tracked = 0;
    }
}

/// Work allowed per read, so a frame built to look like codes that never decode costs a bounded
/// time. An attempt costs 1, a refit about 4 attempts' worth of sampling and a placement about 10;
/// a real code reads well within this, even after a wrong version guess
const BUDGET: u32 = 100;
const REFIT: u32 = 4;
const PLACE: u32 = 10;

fn spend(scan: &mut Scan, units: u32) -> bool {
    let ok = scan.budget >= units;
    scan.budget = if ok { scan.budget - units } else { 0 };
    ok
}

enum Attempt {
    Read(i32),
    /// The version word names another version
    Other(usize),
    /// Not even the format word read: moving the far corner will not help
    NoFormat,
    Failed,
}

/// Samples through `t` and decodes. A code of the wrong kind ends the search: it was read, it is
/// just not what the host wants
fn attempt(
    img: &Image,
    t: &Transform,
    v: usize,
    kind: Kind,
    out: &mut [u8],
    scan: &mut Scan,
    work: &mut Work,
) -> Attempt {
    if !spend(scan, 1) {
        return Attempt::Failed;
    }
    let n = size(v);
    sample(img, t, n, &mut scan.grid, &mut scan.margin);
    scan.track.held = false;
    match decode::decode_grid(&scan.grid[..n * n], &scan.margin[..n * n], v, out, work) {
        Ok(d) if accepted(kind, v, &d, &out[..d.len]) => {
            if kind == Kind::Animated {
                scan.track = Track {
                    t: *t,
                    version: v,
                    len: d.len,
                    live: true,
                    held: true,
                };
                scan.prev[..n * n].copy_from_slice(&scan.grid[..n * n]);
            }
            Attempt::Read(d.len as i32)
        }
        Ok(_) => Attempt::Read(WRONG_KIND),
        Err(Error::Version(other)) if other != v => Attempt::Other(other),
        Err(Error::Format) => Attempt::NoFormat,
        Err(_) => Attempt::Failed,
    }
}

/// The first code that decodes: its length, 0 when no finder triple was found, -1 when one was found
/// but nothing decoded, WRONG_KIND when it decoded to something not of `kind`
pub fn read(img: &Image, kind: Kind, out: &mut [u8], scan: &mut Scan, work: &mut Work) -> i32 {
    scan.budget = BUDGET;
    // An animated code stays put between frames: the last frame's transform is tried first, and a
    // grid identical to the last one read is the same frame still on screen
    if kind == Kind::Animated && scan.track.live {
        let track = scan.track;
        let n = size(track.version);
        sample(img, &track.t, n, &mut scan.grid, &mut scan.margin);
        if track.held && scan.grid[..n * n] == scan.prev[..n * n] {
            scan.tracked += 1;
            return track.len as i32;
        }
        if let Attempt::Read(r) = attempt(img, &track.t, track.version, kind, out, scan, work) {
            scan.tracked += u32::from(r > 0);
            return r;
        }
        if track.version >= 2 {
            let ((x0, y0), (x1, y1)) = (track.t.apply(0.0, 0.0), track.t.apply(1.0, 0.0));
            let ms = sqrt(((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0)) as f32) as f64;
            if let Some(t) = spend(scan, REFIT)
                .then(|| refit(img, track.version, track.t, ms))
                .flatten()
            {
                if let Attempt::Read(r) = attempt(img, &t, track.version, kind, out, scan, work) {
                    scan.tracked += u32::from(r > 0);
                    return r;
                }
            }
        }
    }

    let count = find_finders(img, &mut scan.finders);
    let finders = &mut scan.finders[..count];
    // The most confirmed first; a finder crossed by a single row is usually noise
    finders.sort_unstable_by(|a, b| b.hits.cmp(&a.hits));
    let usable = finders
        .iter()
        .filter(|f| f.hits >= 2)
        .count()
        .max(count.min(3))
        .min(10);

    let mut triples = [([Finder::default(); 3], 0.0f32); 32];
    let mut found = 0;
    for i in 0..usable {
        for j in i + 1..usable {
            for k in j + 1..usable {
                if let Some(t) = corners(&finders[i], &finders[j], &finders[k]) {
                    if found < triples.len() {
                        triples[found] = t;
                        found += 1;
                    }
                }
            }
        }
    }
    triples[..found]
        .sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal));

    let max_version = if kind == Kind::SeedQr {
        3
    } else {
        tables::MAX_VERSION as i32
    };
    // The best-shaped triples only, so a frame of texture costs a bounded amount of work
    for (f, _) in triples[..found.min(MAX_TRIPLES)].iter() {
        let modules = modules_across(img, f);
        let estimate = round((modules - 17.0) / 4.0).clamp(1, tables::MAX_VERSION as i32);
        if !plausible(img, f) {
            continue;
        }
        let ms = ((f[0].ms + f[1].ms + f[2].ms) / 3.0) as f64;
        let mut known_modules = [(0i16, 0i16, false); MAX_KNOWN];
        for delta in [0i32, -1, 1, -2, 2] {
            let mut version = estimate + delta;
            if !(1..=max_version).contains(&version) {
                continue;
            }
            // The version word can name another version; that one is placed and read in turn
            // A fit for the version the word was read through, carried over to the version it names
            let mut hint: Option<(Transform, usize)> = None;
            'version: for _ in 0..2 {
                let v = version as usize;
                let k = known(v, &mut known_modules);
                if let Some((t, from)) = hint.take() {
                    if v >= 2 {
                        if let Some(t) = spend(scan, REFIT)
                            .then(|| refit(img, v, rescale(&t, from, v), ms))
                            .flatten()
                        {
                            if let Attempt::Read(r) = attempt(img, &t, v, kind, out, scan, work) {
                                return r;
                            }
                        }
                    }
                }
                if !spend(scan, PLACE) {
                    return -1;
                }
                let (quad, score) = place(img, f, v, &known_modules[..k]);
                // Under 70% of the fixed modules in place means the wrong version or a wrong fit
                if score * 10 < k * 7 {
                    break;
                }
                if v >= 2 {
                    let base = Transform::between(anchors(v), quad);
                    if let Some(t) = spend(scan, REFIT)
                        .then(|| refit(img, v, base, ms))
                        .flatten()
                        .filter(|t| fitness(img, t, &known_modules[..k]) >= score)
                    {
                        match attempt(img, &t, v, kind, out, scan, work) {
                            Attempt::Read(r) => return r,
                            Attempt::Other(o) => {
                                version = o as i32;
                                hint = Some((t, v));
                                continue 'version;
                            }
                            Attempt::NoFormat | Attempt::Failed => {}
                        }
                    }
                }
                // Nothing fixed sits near the far corner of a small code, so if it does not read, the
                // fourth point is moved about by up to a module and Reed–Solomon says which is right.
                // Larger codes have alignment patterns there and only get the placement as it is
                let offsets = if v <= 6 { &JIGGLE[..] } else { &JIGGLE[..1] };
                for &(dx, dy) in offsets {
                    let mut q = quad;
                    q[2] = (q[2].0 + dx * ms, q[2].1 + dy * ms);
                    match attempt(
                        img,
                        &Transform::between(anchors(v), q),
                        v,
                        kind,
                        out,
                        scan,
                        work,
                    ) {
                        Attempt::Read(r) => return r,
                        Attempt::Other(o) if (1..=max_version as usize).contains(&o) => {
                            version = o as i32;
                            hint = Some((Transform::between(anchors(v), q), v));
                            continue 'version;
                        }
                        Attempt::NoFormat => break,
                        _ => {}
                    }
                }
                break;
            }
        }
    }
    if found > 0 {
        -1
    } else {
        0
    }
}
