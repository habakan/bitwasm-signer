#!/usr/bin/env python3
"""Writes QR symbols made by an encoder this module shares no code with: Nayuki's QR-Code-generator.

Usage: python3 qr/tests/gen_vectors.py third_party/QR-Code-generator/python build/qr

vectors.txt, one symbol per line: version level mask expected-hex rows (each row as 0s and 1s, joined
by '/'). tables.txt: Nayuki's own per-version constants, for checking ours against them.
"""
import os
import random
import sys

sys.path.insert(0, sys.argv[1])
from qrcodegen import QrCode, QrSegment  # noqa: E402

out_dir = sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
rng = random.Random(1)
LEVELS = [QrCode.Ecc.LOW, QrCode.Ecc.MEDIUM, QrCode.Ecc.QUARTILE, QrCode.Ecc.HIGH]
ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def capacity_bits(version, level):
    return QrCode._get_num_data_codewords(version, level) * 8


def symbol(segs, version, level, mask, expected):
    qr = QrCode.encode_segments(segs, level, version, version, mask, False)
    assert qr.get_version() == version and qr.get_mask() == mask
    rows = "/".join("".join("1" if qr.get_module(x, y) else "0" for x in range(qr.get_size())) for y in range(qr.get_size()))
    return f"{version} {LEVELS.index(level)} {mask} {expected.hex()} {rows}"


def fill(version, level, kind):
    """A payload of this kind using most of the symbol, so every block carries data"""
    bits = capacity_bits(version, level) - 4 - QrSegment.Mode.BYTE.num_char_count_bits(version)
    if kind == "byte":
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(max(1, bits // 8 // 2), bits // 8 + 1)))
        return [QrSegment.make_bytes(data)], data
    if kind == "numeric":
        n = max(1, (bits * 3) // 10 - 2)
        text = "".join(rng.choice("0123456789") for _ in range(rng.randrange(n // 2 + 1, n + 1)))
        return [QrSegment.make_numeric(text)], text.encode()
    n = max(1, (bits * 2) // 11 - 2)
    text = "".join(rng.choice(ALNUM) for _ in range(rng.randrange(n // 2 + 1, n + 1)))
    return [QrSegment.make_alphanumeric(text)], text.encode()


lines = []
for version in range(1, 41):
    for li, level in enumerate(LEVELS):
        kind = ["byte", "numeric", "alnum"][(version + li) % 3]
        segs, expected = fill(version, level, kind)
        lines.append(symbol(segs, version, level, (version * 3 + li) % 8, expected))

# SeedQR as wallets draw it: Standard is four digits per word index, Compact is the raw entropy
words = [rng.randrange(2048) for _ in range(24)]
for n, version in ((12, 2), (24, 3)):
    digits = "".join(f"{w:04d}" for w in words[:n])
    for mask in range(8):
        lines.append(symbol([QrSegment.make_numeric(digits)], version, QrCode.Ecc.LOW, mask, digits.encode()))
for n, version in ((16, 1), (32, 2)):
    entropy = bytes(rng.randrange(256) for _ in range(n))
    for mask in range(8):
        lines.append(symbol([QrSegment.make_bytes(entropy)], version, QrCode.Ecc.LOW, mask, entropy))

# Mixed segments and ECI in one symbol
mixed = [QrSegment.make_eci(26), QrSegment.make_numeric("0123456789"), QrSegment.make_alphanumeric("AB-CD"), QrSegment.make_bytes(b"\x00\xffhi")]
lines.append(symbol(mixed, 5, QrCode.Ecc.MEDIUM, 3, b"0123456789AB-CD\x00\xffhi"))

# Frames of an animated UR: same length, so the same version, as an encoder's fixed fragments are
animated = []
for i in range(12):
    body = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(160))
    text = f"UR:CRYPTO-PSBT/{i + 1}-12/{body}"[:180]
    animated.append(symbol([QrSegment.make_alphanumeric(text)], 8, QrCode.Ecc.LOW, i % 8, text.encode()))
with open(os.path.join(out_dir, "animated.txt"), "w") as f:
    f.write("\n".join(animated) + "\n")

# Not SeedQRs, though their lengths match one: digits where entropy bytes belong, text, and
# entropy split across two segments. SeedQR mode must turn each away
imposters = [
    symbol([QrSegment.make_numeric("1234567890123456")], 1, QrCode.Ecc.LOW, 0, b"1234567890123456"),
    symbol([QrSegment.make_alphanumeric("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")], 2, QrCode.Ecc.LOW, 1, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
    symbol([QrSegment.make_numeric("12345678"), QrSegment.make_bytes(b"abcdefgh")], 1, QrCode.Ecc.LOW, 2, b"12345678abcdefgh"),
    symbol([QrSegment.make_eci(26), QrSegment.make_bytes(bytes(range(16)))], 1, QrCode.Ecc.LOW, 3, bytes(range(16))),
]
with open(os.path.join(out_dir, "imposters.txt"), "w") as f:
    f.write("\n".join(imposters) + "\n")

with open(os.path.join(out_dir, "vectors.txt"), "w") as f:
    f.write("\n".join(lines) + "\n")

with open(os.path.join(out_dir, "tables.txt"), "w") as f:
    for version in range(1, 41):
        ecc = [QrCode._ECC_CODEWORDS_PER_BLOCK[lv.ordinal][version] for lv in LEVELS]
        blocks = [QrCode._NUM_ERROR_CORRECTION_BLOCKS[lv.ordinal][version] for lv in LEVELS]
        size = version * 4 + 17
        align = QrCode.encode_segments([], QrCode.Ecc.LOW, version, version, 0)._get_alignment_pattern_positions()
        raw = QrCode._get_num_raw_data_modules(version)
        f.write(f"{version} {' '.join(map(str, ecc))} {' '.join(map(str, blocks))} {raw} {size} {','.join(map(str, align))}\n")
print(f"{len(lines)} symbols")
