#!/usr/bin/env python3
"""Generate ironwood_creation_tests creation tests.

The note opening and its cmx come
from the cached native output (fixtures/ironwood_notes/cached-output.json) and
the native reference vectors (fixtures/ironwood_notes/reference.json). The
Action bytes come from the native transfer bundle
(fixtures/ironwood_transfer/bundle.json). The enclosing V6 transaction, the
block Merkle tree and the header are synthetic; their txid, root and SHA256d
come from an independent hashlib model of ZIP 244 and the block tree, not from
Noir. Execution only; no proof and no mined-chain claim.
"""

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "noir/ironwood_creation_tests/src/creation_tests.nr"
BRANCH = 0x37A5165B
DEPTH = 3


def b2(data, person):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def sha(data):
    return hashlib.sha256(data).digest()


def pair(left, right):
    return sha(sha(left + right))


BUNDLE = json.loads(
    (
        ROOT / "fixtures/ironwood_transfer/bundle.json"
    ).read_text()
)
CACHED = json.loads(
    (
        ROOT
        / "fixtures/ironwood_notes/cached-output.json"
    ).read_text()
)
VECTORS = {
    v["name"]: v
    for v in json.loads(
        (
            ROOT
            / "fixtures/ironwood_notes/reference.json"
        ).read_text()
    )["vectors"]
}
raw = lambda k: bytes.fromhex(BUNDLE[k])
ENC = raw("enc_ciphertext")
COMPACT = raw("nf") + raw("cmx") + raw("epk") + ENC[:52]
assert len(COMPACT) == 148
assert raw("nf").hex() == CACHED["rho_hex"] and raw("cmx").hex() == CACHED["cmx_hex"]
EFFECTS = dict(
    memos=b2(ENC[52:564], b"ZTxIdIrnActMH_v6"),
    noncompact=b2(
        raw("cv_net") + raw("rk") + ENC[564:] + raw("out_ciphertext"),
        b"ZTxIdIrnActNH_v6",
    ),
    flags=int(BUNDLE["flag_byte"]),
    balance=int(BUNDLE["value_balance"]).to_bytes(8, "little", signed=True),
    transparent=b2(b"", b"ZTxIdTranspaHash"),
    sapling=b2(b"", b"ZTxIdSaplingHash"),
    orchard=b2(b"", b"ZTxIdOrchardH_v6"),
    lock=0,
    expiry=3428200,
)


def txid(actions):
    e = EFFECTS
    hd = b2(
        struct.pack("<5I", 0x80000006, 0xD884B698, BRANCH, e["lock"], e["expiry"]),
        b"ZTxIdHeadersHash",
    )
    compact = b2(b"".join(actions), b"ZTxIdIrnActCH_v6")
    iw = b2(
        compact + e["memos"] + e["noncompact"] + bytes([e["flags"]]) + e["balance"],
        b"ZTxIdIronwd_H_v6",
    )
    return b2(
        hd + e["transparent"] + e["sapling"] + e["orchard"] + iw,
        b"ZcashTxHash_" + struct.pack("<I", BRANCH),
    )


def block(actions, count=3, index=2):
    """The transaction at `index` of a `count`-transaction block (Bitcoin tree,
    odd levels duplicate the last node). Returns (siblings, header, hash, txid)."""
    leaf = txid(actions)
    leaves = [sha(bytes([i])) for i in range(count)]
    leaves[index] = leaf
    pos, siblings = index, []
    while len(leaves) > 1:
        siblings.append(leaves[pos ^ 1] if pos ^ 1 < len(leaves) else leaves[pos])
        padded = leaves + [leaves[-1]] if len(leaves) % 2 else leaves
        leaves = [pair(padded[i], padded[i + 1]) for i in range(0, len(padded), 2)]
        pos //= 2
    header = (
        struct.pack("<I", 4)
        + bytes([17]) * 32
        + leaves[0]
        + bytes([19]) * 32
        + struct.pack("<II", 1700000000, 0x1F07FFFF)
        + bytes([23]) * 32
        + b"\xfd\x40\x05"
        + bytes(1344)
    )
    assert len(header) == 1487
    siblings += [bytes(32)] * (DEPTH - len(siblings))
    return siblings, header, sha(sha(header)), leaf


def arr(b):
    return "[" + ", ".join(str(x) for x in b) + "]"


def flip(b, i, mask=1):
    b = bytearray(b)
    b[i] ^= mask
    return bytes(b)


def fq(limbs):
    return "Fq::from_limbs([" + ", ".join(str(int(x)) for x in limbs) + "])"


def point(p):
    return f"Pallas::from_coordinates({fq(p['x'])}, {fq(p['y'])}, false)"


def note(name, n):
    r = n["receiver"]
    return f"""fn {name}() -> NoteOpening {{
    NoteOpening {{
        receiver: ExpandedReceiver {{ g_d: {point(r["g_d"])}, pk_d: {point(r["pk_d"])} }},
        value: {int(n["value"])},
        rho: {fq(n["rho"])},
        rseed: {arr(int(x) for x in n["rseed"])},
    }}
}}
"""


def rho_bytes(n):
    return sum(int(z) << (120 * i) for i, z in enumerate(n["rho"])).to_bytes(
        32, "little"
    )


def case(name, actions, index=0, positive=True):
    """Witness function plus HASH_/TXID_ globals for one synthetic block."""
    siblings, header, h, t = block(actions)
    e = EFFECTS
    n = len(actions)
    up = name.upper()
    txid_global = f"global TXID_{up}: [u8; 32] = {arr(t)};\n" if positive else ""
    return f"""global HASH_{up}: [u8; 32] = {arr(h)};
{txid_global}fn witness_{name}() -> Inclusion<{n}, {DEPTH}> {{
    Inclusion {{
        effects: V6Effects {{
            compact_actions: [{", ".join(arr(a) for a in actions)}],
            memos_digest: {arr(e["memos"])},
            noncompact_digest: {arr(e["noncompact"])},
            flags: {e["flags"]},
            value_balance: {arr(e["balance"])},
            transparent_digest: {arr(e["transparent"])},
            sapling_digest: {arr(e["sapling"])},
            orchard_digest: {arr(e["orchard"])},
            lock_time: {e["lock"]},
            expiry_height: {e["expiry"]},
        }},
        header: {arr(header)},
        siblings: [{", ".join(arr(s) for s in siblings)}],
        action_index: {index},
        tx_index: 2,
        tx_count: 3,
        action_count: {n},
    }}
}}
"""


def vector_action(v):
    return rho_bytes(v["note"]) + bytes.fromhex(v["cmx_hex"]) + COMPACT[64:]


# Two-Action transaction: the cached output is Action 1; Action 0 is another
# (synthetic) Action with a different nullifier and cmx.
OTHER = flip(flip(COMPACT, 0, 2), 32, 3)


def effect_checks(indent, action, var="action"):
    pad = " " * indent
    return (
        f"{pad}assert({var}.nullifier == {arr(action[:32])});\n"
        f"{pad}assert({var}.cmx == {arr(action[32:64])});\n"
        f"{pad}assert({var}.ephemeral_key == {arr(action[64:96])});\n"
        f"{pad}assert({var}.encrypted_note_prefix == {arr(action[96:148])});\n"
    )


def render():
    assert rho_bytes(CACHED["note"]) == raw("nf")
    zero, top = VECTORS["zero-value"], VECTORS["maximum-u64"]
    return f"""// Generated by scripts/generate_creation_tests.py. Do not edit.
// Cached native output (fixtures/ironwood_notes/cached-output.json) in a
// synthetic V6 transaction at index 2 of a synthetic three-transaction block;
// txid, Merkle root and header hash from an independent hashlib model.
// Execution only; no proof and no mined-chain claim.
use bigcurve::{{BigCurve, Pallas}};
use bignum::{{BigNum, Pallas_Fq as Fq}};
use ironwood::notes::{{ExpandedReceiver, NoteOpening}};
use ironwood::transactions::V6Effects;
use ironwood::transactions::effects::Inclusion;
use ironwood::creation::verify_created_in_block;
use std::hint::black_box;
{note("cached_note", CACHED["note"])}{case("base", [COMPACT])}// Action nullifier differs from the note's rho; cmx unchanged and the block
// rebuilt, so only the rho relation fails.
{case("other_nf", [flip(COMPACT, 0)], positive=False)}// Valid boundary openings (native reference vectors) in synthetic Actions
// whose nullifier is the vector's rho; the invented ciphertext need not decrypt.
{note("zero_note", zero["note"])}{note("max_note", top["note"])}{case("zero", [vector_action(zero)])}{case("max", [vector_action(top)])}// The cached output as Action 1 of a two-Action transaction.
{case("second", [OTHER, COMPACT], index=1)}// Action cmx differs from the opening's cmx; block rebuilt.
{case("other_cmx", [flip(COMPACT, 32)], positive=False)}#[test]
fn cached_output_is_created_in_block() {{
    let (action, txid) = verify_created_in_block(cached_note(), witness_base(), HASH_BASE);
    assert(txid == TXID_BASE);
{effect_checks(4, COMPACT)}}}
// The same claim on witness values (std::hint::black_box), so it is not folded
// at compile time.
#[test]
fn cached_output_is_created_in_block_with_witness_inputs() {{
    let (_, txid) = verify_created_in_block(
        black_box(cached_note()),
        black_box(witness_base()),
        black_box(HASH_BASE),
    );
    assert(txid == TXID_BASE);
}}
#[test(should_fail_with = "Output rho must match Action nullifier")]
fn action_nullifier_other_than_rho_rejects() {{
    let _ = verify_created_in_block(cached_note(), witness_other_nf(), HASH_OTHER_NF);
}}
// ironwood verify_output's check, reached through the creation relation.
#[test(should_fail_with = "Output commitment mismatch")]
fn wrong_opening_value_rejects() {{
    let mut note = cached_note();
    note.value += 1;
    let _ = verify_created_in_block(note, witness_base(), HASH_BASE);
}}
#[test(should_fail_with = "Action index outside complete sequence")]
fn action_index_past_count_rejects() {{
    let mut w = witness_base();
    w.action_index = 1;
    let _ = verify_created_in_block(cached_note(), w, HASH_BASE);
}}
#[test(should_fail_with = "Header hash mismatch")]
fn other_accepted_header_hash_rejects() {{
    let mut hash = HASH_BASE;
    hash[0] ^= 1;
    let _ = verify_created_in_block(cached_note(), witness_base(), hash);
}}
mod extended {{
    use super::{{
        cached_note, HASH_BASE, HASH_MAX, HASH_OTHER_CMX, HASH_SECOND, HASH_ZERO, max_note, TXID_MAX,
        TXID_SECOND, TXID_ZERO, witness_base, witness_max, witness_other_cmx, witness_second,
        witness_zero, zero_note,
    }};
    use bignum::{{BigNum, Pallas_Fq as Fq}};
    use ironwood::creation::verify_created_in_block;
    #[test]
    fn zero_value_output_is_created_in_block() {{
        let (action, txid) = verify_created_in_block(zero_note(), witness_zero(), HASH_ZERO);
        assert(txid == TXID_ZERO);
{effect_checks(8, vector_action(zero))}    }}
    #[test]
    fn maximum_value_output_is_created_in_block() {{
        let (action, txid) = verify_created_in_block(max_note(), witness_max(), HASH_MAX);
        assert(txid == TXID_MAX);
{effect_checks(8, vector_action(top))}    }}
    #[test]
    fn output_as_second_of_two_actions_is_created_in_block() {{
        let (action, txid) = verify_created_in_block(cached_note(), witness_second(), HASH_SECOND);
        assert(txid == TXID_SECOND);
{effect_checks(8, COMPACT)}    }}
    #[test(should_fail_with = "Output commitment mismatch")]
    fn wrong_opening_rseed_rejects() {{
        let mut note = cached_note();
        note.rseed[0] ^= 1;
        let _ = verify_created_in_block(note, witness_base(), HASH_BASE);
    }}
    // cmx is checked before the rho relation, so a changed rho fails there.
    #[test(should_fail_with = "Output commitment mismatch")]
    fn wrong_opening_rho_rejects() {{
        let mut note = cached_note();
        let mut limbs = note.rho.get_limbs();
        limbs[0] += 1;
        note.rho = Fq::from_limbs(limbs);
        let _ = verify_created_in_block(note, witness_base(), HASH_BASE);
    }}
    #[test(should_fail_with = "Output commitment mismatch")]
    fn action_cmx_other_than_opening_rejects() {{
        let _ = verify_created_in_block(cached_note(), witness_other_cmx(), HASH_OTHER_CMX);
    }}
    // Input binding: each returned Action field is bound to the accepted header
    // through the txid; a changed byte with the block not rebuilt is rejected.
    // The transaction is the last of three, so the first Merkle step duplicates
    // its own txid and a changed txid is first caught by that sibling check.
    #[test(should_fail_with = "Wrong duplicate-last sibling")]
    fn changed_action_cmx_rejects() {{
        let mut w = witness_base();
        w.effects.compact_actions[0][32] ^= 1;
        let _ = verify_created_in_block(cached_note(), w, HASH_BASE);
    }}
    #[test(should_fail_with = "Wrong duplicate-last sibling")]
    fn changed_ephemeral_key_rejects() {{
        let mut w = witness_base();
        w.effects.compact_actions[0][64] ^= 1;
        let _ = verify_created_in_block(cached_note(), w, HASH_BASE);
    }}
    #[test(should_fail_with = "Wrong duplicate-last sibling")]
    fn changed_ciphertext_prefix_rejects() {{
        let mut w = witness_base();
        w.effects.compact_actions[0][96] ^= 1;
        let _ = verify_created_in_block(cached_note(), w, HASH_BASE);
    }}
}}
"""


def main():
    OUT.write_text(render())
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
