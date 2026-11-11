#!/usr/bin/env python3
"""Generate isolated ironwood_memo negative tests.

Each negative is named by its assert message. Inputs: native vectors 0 and 2 (fixtures/memo/native-vectors.json,
from the pinned Orchard Rust fixture) in the synthetic one-transaction block of
scripts/prepare_memo_fixtures.py. Every changed ciphertext comes from
scripts/chacha20poly1305.py (RFC 8439), every changed key from a Python Pallas model
plus hashlib BLAKE2b, and every digest, txid and header hash from hashlib. The
model is checked against the native epk, KDF key and ciphertext first. No value
comes from Noir. Execution only; no proof.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

from chacha20poly1305 import aead_encrypt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "noir/ironwood/src/memo/negative_tests.nr"
spec = importlib.util.spec_from_file_location(
    "memo_fixtures", ROOT / "scripts/prepare_memo_fixtures.py"
)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
VECTORS = json.loads(
    (ROOT / "fixtures/memo/native-vectors.json").read_text()
)["vectors"]

# Pallas: y^2 = x^3 + 5 over P, group order Q.
P = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
Q = 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001


def limbs_int(xs):
    return sum(int(x) << (120 * i) for i, x in enumerate(xs))


def point(p):
    return (limbs_int(p["x"]), limbs_int(p["y"]))


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        s = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        s = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (s * s - a[0] - b[0]) % P
    return (x, (s * (a[0] - x) - a[1]) % P)


def mul(k, a):
    r = None
    while k:
        if k & 1:
            r = add(r, a)
        a, k = add(a, a), k >> 1
    return r


def encode(a):
    assert a is not None and (a[1] * a[1] - a[0] ** 3 - 5) % P == 0
    b = bytearray(a[0].to_bytes(32, "little"))
    b[31] |= (a[1] & 1) << 7
    return list(b)


def kdf(shared, epk):
    return hashlib.blake2b(
        bytes(shared + epk), digest_size=32, person=b"Zcash_OrchardKDF"
    ).digest()


def encrypt(key, plaintext):
    return list(aead_encrypt(bytes(key), bytes(12), bytes(plaintext)))


def check_model(v):
    esk = limbs_int(v["esk"])
    g_d, pk_d = (
        point(v["note"]["receiver"]["g_d"]),
        point(v["note"]["receiver"]["pk_d"]),
    )
    epk = encode(mul(esk, g_d))
    assert epk == v["ephemeral_key"]
    key = kdf(encode(mul(esk, pk_d)), epk)
    assert list(key) == v["key"]
    assert encrypt(key, v["plaintext"]) == v["ciphertext"]


for _v in VECTORS:
    check_model(_v)
V0, V1, V2 = VECTORS[0], VECTORS[1], VECTORS[2]
BASE = fixtures.build(V0)[0]


def full_of(v):
    return copy.deepcopy(fixtures.build(v)[0]["full"][0])


def compact_of(v, full):
    return (
        list(limbs_int(v["note"]["rho"]).to_bytes(32, "little"))
        + v["cmx"]
        + v["ephemeral_key"]
        + full["encrypted_note"][:52]
    )


def block(compact, full):
    """Digests, txid and header hash of the prepare-memo-fixtures block layout
    (one V6 transaction, tx_count 1) holding these Actions in this order."""
    h = fixtures.h
    memos = list(
        h(sum((f["encrypted_note"][52:564] for f in full), []), "ZTxIdIrnActMH_v6")
    )
    noncompact = list(
        h(
            sum(
                (
                    f["value_commitment"]
                    + f["randomized_key"]
                    + f["encrypted_note"][564:]
                    + f["outgoing_ciphertext"]
                    for f in full
                ),
                [],
            ),
            "ZTxIdIrnActNH_v6",
        )
    )
    hdr = h(
        b"".join(
            x.to_bytes(4, "little") for x in [0x80000006, 0xD884B698, 0x37A5165B, 0, 0]
        ),
        "ZTxIdHeadersHash",
    )
    irn = h(
        list(h(sum(compact, []), "ZTxIdIrnActCH_v6"))
        + memos
        + noncompact
        + [3]
        + [0] * 8,
        "ZTxIdIronwd_H_v6",
    )
    txid = hashlib.blake2b(
        hdr + bytes(96) + irn,
        digest_size=32,
        person=b"ZcashTxHash_" + bytes.fromhex("5b16a537"),
    ).digest()
    header = bytearray(1487)
    header[0] = 4
    header[36:68] = txid
    header[140:143] = bytes.fromhex("fd4005")
    return memos, noncompact, list(txid), list(fixtures.sha(header))


def arr(x):
    return "[" + ", ".join(str(int(v)) for v in x) + "]"


def fq(x):
    return f"Fq::from_limbs({arr(x)})"


def pallas(p):
    return f"Pallas::from_coordinates({fq(p['x'])}, {fq(p['y'])}, false)"


def note(name, n, pk_d=None):
    r = n["receiver"]
    return f"""fn {name}() -> NoteOpening {{
    NoteOpening {{
        receiver: ExpandedReceiver {{ g_d: {pallas(r["g_d"])}, pk_d: {pallas(pk_d or r["pk_d"])} }},
        value: {int(n["value"])},
        rho: {fq(n["rho"])},
        rseed: {arr(n["rseed"])},
    }}
}}
"""


def full_expr(f):
    return (
        f"FullActionCiphertext {{ encrypted_note: {arr(f['encrypted_note'])}, value_commitment: {arr(f['value_commitment'])}, "
        f"randomized_key: {arr(f['randomized_key'])}, outgoing_ciphertext: {arr(f['outgoing_ciphertext'])} }}"
    )


def case(name, compact, full, index=0, rebuilt_compact=None):
    """A block whose digests, txid and header hash are rebuilt for `full` and
    `compact` (rebuilt_compact: the compact bytes hashed, if they differ)."""
    n = len(full)
    memos, noncompact, txid, hash_ = block(compact, full)
    return f"""fn {name}() -> (Inclusion<{n}, 32>, [FullActionCiphertext; {n}], [u8; 32]) {{
    (
        witness([{", ".join(arr(c) for c in compact)}], {arr(memos)}, {arr(noncompact)}, {arr(txid)}, {index}),
        [{", ".join(full_expr(f) for f in full)}],
        {arr(hash_)},
    )
}}
"""


def reencrypt(**changes):
    """Vector 0's Action with its ciphertext re-encrypted under the true key
    after changing plaintext bytes {offset: xor mask}; digests rebuilt."""
    plaintext = list(V0["plaintext"])
    for offset, mask in changes.get("xor", {}).items():
        plaintext[offset] ^= mask
    if "lead" in changes:
        plaintext[0] = changes["lead"]
    f = full_of(V0)
    f["encrypted_note"] = encrypt(V0["key"], plaintext)
    return [compact_of(V0, f)], [f]


def render():
    assert V0["plaintext"][0] == 3 and BASE["witness"]["action_count"] == 1
    f0 = full_of(V0)
    tag = full_of(V0)
    tag["encrypted_note"][579] ^= 1
    # esk + 1: a consistent encryption to the same receiver with another epk.
    esk = (limbs_int(V0["esk"]) + 1) % Q
    g_d, pk_d = (
        point(V0["note"]["receiver"]["g_d"]),
        point(V0["note"]["receiver"]["pk_d"]),
    )
    epk = encode(mul(esk, g_d))
    other_esk = full_of(V0)
    other_esk["encrypted_note"] = encrypt(
        kdf(encode(mul(esk, pk_d)), epk), V0["plaintext"]
    )
    other_esk_compact = compact_of(V0, other_esk)
    other_esk_compact[64:96] = epk
    assert epk != V0["ephemeral_key"]
    prefix = compact_of(V0, f0)
    prefix[96] ^= 1
    f2 = full_of(V2)
    # Wrong key: vector 0's opening with another pk_d and the matching raw
    # receiver bytes, so the receiver and epk checks pass and only the KDF key
    # differs. The note commitment binds pk_d, so the full claim would stop at
    # its cmx check first; these use verify_memo_from_opening.
    v1_pk_d = V1["note"]["receiver"]["pk_d"]
    assert V1["raw_receiver"][11:] == encode(point(v1_pk_d)) != V0["raw_receiver"][11:]
    g_d_raw = V0["raw_receiver"][:11] + encode(g_d)
    s = f"""// Generated by scripts/generate_memo_negative_tests.py from
// fixtures/memo/native-vectors.json (vectors 0 and 2) in the block layout
// of scripts/prepare_memo_fixtures.py. Do not edit. Changed ciphertexts, keys,
// digests, txids and header hashes come from scripts/chacha20poly1305.py, hashlib and a
// Python Pallas model checked against the native vectors. Execution only.
use crate::memo::FullActionCiphertext;
use bigcurve::{{BigCurve, Pallas}};
use bignum::{{BigNum, Pallas_Fq as Fq}};
use crate::notes::{{ExpandedReceiver, NoteOpening}};
use crate::transactions::digest::V6Effects;
use crate::transactions::effects::Inclusion;
global RAW_0: [u8; 43] = {arr(V0["raw_receiver"])};
global MEMO_0: [u8; 512] = {arr(V0["memo"])};
global EPK_0: [u8; 32] = {arr(V0["ephemeral_key"])};
global CIPHERTEXT_0: [u8; 580] = {arr(V0["ciphertext"])};
global RAW_2: [u8; 43] = {arr(V2["raw_receiver"])};
global MEMO_2: [u8; 512] = {arr(V2["memo"])};
{note("note_0", V0["note"])}{note("note_2", V2["note"])}// The prepare-memo-fixtures block: one V6 transaction (tx_count 1), so the
// header's Merkle root is the txid.
fn witness<let N: u32>(
    compact_actions: [[u8; 148]; N],
    memos_digest: [u8; 32],
    noncompact_digest: [u8; 32],
    txid: [u8; 32],
    action_index: u32,
) -> Inclusion<N, 32> {{
    let mut header = [0u8; 1487];
    header[0] = 4;
    for i in 0..32 {{
        header[36 + i] = txid[i];
    }}
    header[140] = 253;
    header[141] = 64;
    header[142] = 5;
    Inclusion {{
        effects: V6Effects {{
            compact_actions,
            memos_digest,
            noncompact_digest,
            flags: 3,
            value_balance: [0; 8],
            transparent_digest: [0; 32],
            sapling_digest: [0; 32],
            orchard_digest: [0; 32],
            lock_time: 0,
            expiry_height: 0,
        }},
        header,
        siblings: [[0; 32]; 32],
        action_index,
        tx_index: 0,
        tx_count: 1,
        action_count: N,
    }}
}}
{case("base", [compact_of(V0, f0)], [f0])}// Last tag byte changed; noncompact digest, txid and header rebuilt.
{case("tag_last_byte", [compact_of(V0, tag)], [tag])}// epk and ciphertext of a consistent encryption with esk + 1.
{case("other_esk", [other_esk_compact], [other_esk])}// Compact ciphertext prefix changed in the hashed Action only; txid and
// header rebuilt, the full ciphertext (and its digests) unchanged.
{case("compact_prefix", [prefix], [f0])}#[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
fn tag_last_byte_rejects() {{
    let (w, full, hash) = tag_last_byte();
    let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
}}
#[test(should_fail_with = "Ephemeral key does not match note randomness")]
fn epk_of_other_esk_rejects() {{
    let (w, full, hash) = other_esk();
    let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
}}
#[test(should_fail_with = "Compact ciphertext mismatch")]
fn compact_prefix_rejects_with_header_rebuilt() {{
    let (w, full, hash) = compact_prefix();
    let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
}}
#[test(should_fail_with = "Memo requires at least one Action")]
fn zero_action_count_rejects() {{
    let (mut w, full, hash) = base();
    w.action_count = 0;
    let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
}}
// The raw receiver is not hashed into the block or the note commitment; these
// change one raw byte and call the opening helper, whose first checks are the
// raw receiver's pk_d bytes, then its diversifier.
#[test(should_fail_with = "Raw receiver pk_d mismatch")]
fn raw_receiver_pk_d_byte_rejects() {{
    let mut raw = RAW_0;
    raw[11] ^= 1;
    crate::memo::verify_memo_from_opening(note_0(), raw, EPK_0, CIPHERTEXT_0, MEMO_0);
}}
#[test(should_fail_with = "Raw receiver diversifier mismatch")]
fn raw_receiver_diversifier_byte_rejects() {{
    let mut raw = RAW_0;
    raw[0] ^= 1;
    crate::memo::verify_memo_from_opening(note_0(), raw, EPK_0, CIPHERTEXT_0, MEMO_0);
}}
mod extended {{
    use super::{{
        base, CIPHERTEXT_0, EPK_0, MEMO_0, MEMO_2, note_0, note_2, RAW_0, RAW_2, witness,
    }};
    use crate::memo::FullActionCiphertext;
    use bigcurve::{{BigCurve, Pallas}};
    use bignum::{{BigNum, Pallas_Fq as Fq}};
    use crate::notes::{{ExpandedReceiver, NoteOpening}};
    use crate::transactions::effects::Inclusion;
    // Vector 0's Action re-encrypted under its true key from a changed
    // plaintext; digests, txid and header rebuilt.
{case("lead_byte_2", *reencrypt(lead=2))}{case("plaintext_d", *reencrypt(xor={1: 1}))}{case("plaintext_value", *reencrypt(xor={12: 1}))}{case("plaintext_rseed", *reencrypt(xor={20: 1}))}{case("plaintext_memo", *reencrypt(xor={152: 1}))}// Two Actions (vector 2, then vector 0); the claim selects Action 1.
{case("two_actions", [compact_of(V2, f2), compact_of(V0, f0)], [f2, f0], index=1)}// The same two notes with the ciphertexts crossed: each compact prefix and
// every digest follows the crossed ciphertexts, so only the AEAD equality of
// the selected Action can reject.
{case("crossed", [compact_of(V2, f0), compact_of(V0, f2)], [f0, f2], index=1)}{note("note_0_with_v1_pk_d", V0["note"], v1_pk_d)}{note("note_0_with_g_d_as_pk_d", V0["note"], V0["note"]["receiver"]["g_d"])}    global RAW_0_WITH_V1_PK_D: [u8; 43] = {arr(V0["raw_receiver"][:11] + V1["raw_receiver"][11:])};
    global RAW_0_WITH_G_D_AS_PK_D: [u8; 43] = {arr(g_d_raw)};
    #[test]
    fn rebuilt_block_verifies() {{
        let (w, full, hash) = base();
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    #[test]
    fn second_of_two_actions_verifies() {{
        let (w, full, hash) = two_actions();
        let (_, cmx) = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
        assert(cmx == {arr(V0["cmx"])});
    }}
    #[test]
    fn first_of_two_actions_verifies() {{
        let (mut w, full, hash) = two_actions();
        w.action_index = 0;
        let (_, cmx) = crate::memo::verify_memo_created_in_block(note_2(), RAW_2, MEMO_2, w, full, hash);
        assert(cmx == {arr(V2["cmx"])});
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn crossed_ciphertexts_reject() {{
        let (w, full, hash) = crossed();
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn lead_byte_2_rejects() {{
        let (w, full, hash) = lead_byte_2();
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn plaintext_diversifier_rejects() {{
        let (w, full, hash) = plaintext_d();
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn plaintext_value_rejects() {{
        let (w, full, hash) = plaintext_value();
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn plaintext_rseed_rejects() {{
        let (w, full, hash) = plaintext_rseed();
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn plaintext_memo_rejects() {{
        let (w, full, hash) = plaintext_memo();
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    // The memo input is not hashed into the block: no rebuild needed.
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn memo_input_rejects() {{
        let (w, full, hash) = base();
        let mut memo = MEMO_0;
        memo[100] ^= 1;
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, memo, w, full, hash);
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn key_of_vector_1_pk_d_rejects() {{
        crate::memo::verify_memo_from_opening(note_0_with_v1_pk_d(), RAW_0_WITH_V1_PK_D, EPK_0, CIPHERTEXT_0, MEMO_0);
    }}
    #[test(should_fail_with = "Memo ciphertext or authentication tag mismatch")]
    fn key_of_other_pk_d_rejects() {{
        crate::memo::verify_memo_from_opening(note_0_with_g_d_as_pk_d(), RAW_0_WITH_G_D_AS_PK_D, EPK_0, CIPHERTEXT_0, MEMO_0);
    }}
    // Digests not rebuilt: a changed memo-region byte or tag byte is caught by
    // the ciphertext digests before any other check.
    #[test(should_fail_with = "Memo ciphertext digest mismatch")]
    fn unrebuilt_memo_digest_rejects() {{
        let (w, mut full, hash) = base();
        full[0].encrypted_note[100] ^= 1;
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
    #[test(should_fail_with = "Noncompact Action digest mismatch")]
    fn unrebuilt_noncompact_digest_rejects() {{
        let (w, mut full, hash) = base();
        full[0].encrypted_note[579] ^= 1;
        let _ = crate::memo::verify_memo_created_in_block(note_0(), RAW_0, MEMO_0, w, full, hash);
    }}
}}
"""
    return s


def main():
    OUT.write_text(render())
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
