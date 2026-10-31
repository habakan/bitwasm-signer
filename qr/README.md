# qr.wasm

Reads a QR code from 8-bit greyscale pixels. Written from ISO/IEC 18004 in Rust with no dependencies,
so the code that reads a SeedQR is small enough to read in full and depends on no other QR library.

```sh
make qr-deps      # the reference encoder the tests compare against
make check-qr     # build, test, and check the module's shape
```

## Driving it

| export | |
|---|---|
| `qr_init(w, h)` | sets the frame size; 1 if accepted (21 to 1280 on each side, at most 1280 x 720 pixels either way up) |
| `qr_input()`, `qr_input_cap()` | where to write `w * h` bytes of greyscale, row by row |
| `qr_decode()` | reads the frame for any code: the length at `qr_output()`, 0 if no code was found, -1 if one was found but did not decode |
| `qr_decode_as(kind)` | the same for one kind of code (below); -3 if a code was read that is not of that kind |
| `qr_output()`, `qr_output_cap()` | the decoded bytes: digits and alphanumerics as ASCII, byte mode as is, kanji as Shift JIS |
| `qr_wipe()` | zeroes the frame, the output, every intermediate buffer and most of the stack |

After a SeedQR, call `qr_wipe`: the frame is the secret as much as the decoded bytes are.

| kind | | |
|---|---|---|
| 0 | any | every version and mode |
| 1 | SeedQR | versions 1 to 3 at level L, holding a single segment: 16 or 32 bytes in byte mode, or 48 or 96 digits in numeric mode; anything else is turned away |
| 2 | animated UR | the output must start with `ur:`; the code is followed from frame to frame |

**Animated codes** stay put on a screen while their content changes, and a camera sees each screen
frame several times. So after a frame is read, the next call first samples through the same
transform: a grid identical to the last is answered at once, and a new frame usually decodes without
searching for finders at all (about 0.5 ms against 7 ms for a version 8 code in V8). Only when that
fails does it search the whole frame again. A read of anything else in between means the next
sighting is decoded again rather than answered from the last one.

**Smudges and faint modules**: each module's colour comes from the mean grey of five points across
it, and how far that mean sits from the local threshold is kept. When a block does not correct, its
least sure codewords are passed to Reed–Solomon as erasures. An erasure costs one check codeword
where an unknown error costs two, so a hand-filled or worn SeedQR with a few doubtful modules
still reads.

Some check codewords are kept from correction altogether, so a wrong correction is still caught:
with every one spent, almost any garbage corrects to some codeword. Without erasures, versions 1 to 3
keep the number ISO/IEC 18004 sets aside for misdecode protection (up to 3 at version 1, level L).
With erasures, at least four are kept, or a third in larger blocks.

The frame is not copied: a pixel is dark when its grey is at or below its 8x8 block's threshold,
worked out when it is looked at. The module's memory is 1.15 MB, almost all of it the frame buffer.

Light-on-dark codes are tried when nothing dark-on-light reads.

Each read has a work budget, so a frame built to look like codes that never decode costs a bounded
time (under 0.2 s in V8 for two version 40 lookalikes with random data, against 1.8 s without it).

## How it reads

1. **Dark and light**: each 8x8 block is thresholded at the mean of the 5x5 blocks around it, so a
   shadow across the code does not hide part of it.
2. **Finder patterns**: rows are scanned for 1:1:3:1:1 runs, a lone pixel counting as noise, and
   each hit is confirmed down the column and back along the row (or a row beside it, as blur can
   thin a ring on the one row every hit agrees on). Before a triple is placed, a 9x9 patch around
   each finder, laid along the code's edges, must look like a finder, so texture costs little.
3. **Placing the grid**: three finders and the alignment pattern give a first homography. Each point
   is then nudged while more of the fixed modules (finders, separators, timing, alignment, the quiet
   zone) land where they should. From version 2 on, every alignment pattern is then found near where
   that fit puts it and the homography is refitted to all of them by least squares.
4. **Decoding**: format and version words by nearest valid word, unmasking, the zigzag read,
   de-interleaving, Reed–Solomon per block, then the segments.

## Tests

`tests/gen_vectors.py` has [Nayuki's QR-Code-generator](https://github.com/nayuki/QR-Code-generator)
make 193 symbols: every version at every level in byte, numeric and alphanumeric mode, Standard and
Compact SeedQRs under all eight masks, and a mixed symbol with ECI. `tests/vectors.rs` then checks:

- our version tables against the encoder's own
- every symbol's module grid decodes to the encoded bytes, and still does with modules flipped
- every symbol drawn axis-aligned and turned four ways reads (193 of 193 each)
- versions 1 to 12 drawn tilted, turned, blurred, noisy, unevenly lit and low in contrast read at
  95% or more (80 of 81 when this was written), and the same not turned (77 of 81)
- SeedQR mode reads all 32 SeedQRs and returns nothing for the other symbols, nor for text of a
  seed's length (16 digits, 32 alphanumerics, entropy split across segments or behind an ECI)
- SeedQR grids with 4, 6 and 8 smudged modules (1,280 each): 1,225, 1,088 and 893 decode with
  erasures against 1,190, 1,014 and 847 without, and none decodes to other bytes; drawn with 4 grey
  smudges, 30 of 32 read
- Reed–Solomon with erasures and a reserve of four corrects none of 60,000 random blocks
- codes with their data area wiped never come back with bytes
- an animated frame seen again after another code was read decodes again
- 12 animated UR frames, each read twice: every read after the first goes through the tracked transform
- light-on-dark symbols up to version 10: all read

A wrong decode fails the test outright; a missed read is only counted.

In V8, a 640x480 frame takes about 3 ms with nothing in it, 5 ms with a SeedQR, 0.5 ms for a
tracked animated frame, about 65 ms for a version 20 code with its data cut off, and under 0.2 s for
the worst frame built so far. Frames turned far enough to exceed 1280 x 720 are skipped by the rotation tests.
