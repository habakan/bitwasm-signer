"""Prints what the module reported, in the same lines as signer/hosts/js/dump.mjs, so that the two
hosts can be diffed byte for byte.

  python3 dump.py <signer.wasm> <parser.wasm> <psbt>
"""

import base64
import sys
from pathlib import Path

from jitsu_in import Instance, Signer, SignerError
from jitsu_in.signer import MAX_INPUTS, NONCE_SIZE, OWNER, PLAN_N_INPUTS, PLAN_SIZE, TEXT_KIND

signer_path, parser_path, psbt_path = sys.argv[1:4]
MNEMONIC = "abandon " * 11 + "about"

P = Instance(Path(parser_path).read_bytes())
psbt = Path(psbt_path).read_bytes()
P.memory[P.parser_input():P.parser_input() + len(psbt)] = psbt
if P.parser_parse(len(psbt), 0x73C5DA0A) != 0:
    sys.exit("the parser refused the PSBT")
plan = bytes(P.memory[P.parser_plan():P.parser_plan() + PLAN_SIZE])
prevtxs = []
for i in range(plan[PLAN_N_INPUTS]):
    n, at = P.parser_prevtx_len(i), P.parser_input() + P.parser_prevtx_off(i)
    prevtxs.append(bytes(P.memory[at:at + n]) if n else None)

S = Signer(Path(signer_path).read_bytes())
S.init().seed_from_mnemonic(bytearray(MNEMONIC.encode())).set_plan(plan).set_prevtxs(prevtxs)
review = S.review()
d = S.display()
print(f"fingerprint {S.fingerprint}")
print(f"fee {d['fee']} spend {d['spend']}")
for o in d["outputs"]:
    print(f"out {o['amount']} {OWNER[o['owner']]} {TEXT_KIND[o['text_kind']]} {o['text']}")
signed_inputs = [i for i, yes in enumerate(review["will_sign"]) if yes]
if not signed_inputs:
    sys.exit("the signer found no input to sign")
slot = signed_inputs[0]
nonces = bytearray(MAX_INPUTS * NONCE_SIZE)
nonces[slot * NONCE_SIZE] = 1
nonces[slot * NONCE_SIZE + 1:(slot + 1) * NONCE_SIZE] = bytes([0x5A]) * 32
anti = S.sign(nonces)
if anti[0]["input"] != slot or anti[0]["point"] is None:
    sys.exit("the anti-exfil point was not returned")
S.review()
for s in S.sign():
    print(f"sig {s['input']} {s['sig'].hex()}")
if not S.account_cbor():
    sys.exit("the signer returned no crypto-account CBOR")
keys = [
    "[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/<0;1>/*",
    "[3f635a63/48h/0h/0h/2h]xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHqytAzKZWsKz8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybr/<0;1>/*",
    "[b8688df1/48h/0h/0h/2h]xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX/<0;1>/*",
]
wallet = S.multisig_load("wsh(sortedmulti(2," + ",".join(keys) + "))")
if (wallet["threshold"] != 2 or wallet["ours"] != 0 or
        wallet["fingerprints"] != ["73c5da0a", "3f635a63", "b8688df1"] or
        wallet["receive"] != "bc1qea2gkgeszr7wm66x2ejkgdxm9nhg9462sszn75zmkhazev0t02vs70kkll" or
        not wallet["descriptor"].endswith("#d9p6ar8k") or not S.multisig_cbor()):
    sys.exit("the multisig wallet did not match the expected account")
S.multisig_unload()
try:
    S.multisig_cbor()
except SignerError as e:
    if e.code != 13:
        raise
else:
    sys.exit("an unloaded wallet still had crypto-output CBOR")
chain, index = S.find_address("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", count=20)
print(f"found {chain} {index}")
print(f"desc {S.xpub(purpose=86, account=1)['descriptor']}")
print(f"dice {S.mnemonic_from_dice(bytearray(b'3' * 99)).decode()}")
print(f"seedqr {S.seedqr_from_mnemonic(bytearray(MNEMONIC.encode())).decode()}")
print(f"bip85 {S.bip85_mnemonic(words=24, index=3).decode()}")
shown = S.message_review(b"dump\n", purpose=49, chain=1, index=2)
print(f"message {shown['address']} {shown['text']} {base64.b64encode(S.message_sign()).decode()}")
S.unload()
S.init().seed_from_seedqr(bytearray.fromhex("5bbd9d71a8ec7990831aff359d426545"))
print(f"seedqr fingerprint {S.fingerprint}")
S.unload()
