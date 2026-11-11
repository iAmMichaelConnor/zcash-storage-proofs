#!/usr/bin/env python3
"""Generate the ironwood_notes_tests package (tests of ironwood notes,
reduction and Poseidon) through the public API:

- note_tests.nr: encode_nonidentity, psi, rcm_v3, commitment_x,
  reduce512 (Pallas_Fq and Pallas_Fr), verify_viewing, ownership::verify and
  derive_with_commitment (external and internal scope).
- poseidon_tests.nr: poseidon::hash2.

Expected values come from the cached native references
(fixtures/ironwood_notes/*.json, fixtures/poseidon/native-vectors.json)
or from Python integer arithmetic here (compressed encodings, reductions,
aliases, Pallas points). Nothing is taken from running the Noir code.
Each file's `extended` module holds further vectors and repeated rejections.
A negative whose named check is backed by a later check for every input
says so in its comment (REDUNDANT): deleting that check is not detected.
Execution only; no proof.
"""

import json
import re
from pathlib import Path
from noir_format import format_file

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures/ironwood_notes"
CORE = ROOT / "noir/ironwood"
TESTS = ROOT / "noir/ironwood_notes_tests/src"
NOTE_TESTS = TESTS / "note_tests.nr"
POSEIDON_TESTS = TESTS / "poseidon_tests.nr"

P = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
R = 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001
B120 = 2**120


def num(ls):
    return sum(int(x) << (120 * i) for i, x in enumerate(ls))


def limbs(n):
    assert 0 <= n < 2**255 + 2**254
    return [n % B120, (n >> 120) % B120, n >> 240]


def unnormalised(ls):
    """One limb >= 2^120: the same integer (borrowed from the next limb), or
    for a value below 2^120 (rho = 42) the integer + 2^120, still below p."""
    ls = [int(x) for x in ls]
    if ls[1] == ls[2] == 0:
        return [ls[0] + B120, 0, 0]
    i = 1 if ls[1] else 2
    ls[i - 1] += B120
    ls[i] -= 1
    return ls


def alias(ls, m):
    out = limbs(num(ls) + m)
    assert out[2] < 2**15  # passes validate_in_range, fails validate_in_field
    return out


def arr(ls):
    return "[" + ", ".join(str(int(x)) for x in ls) + "]"


def fq(ls):
    return f"Fq::from_limbs_unsafe({arr(ls)})"


def fr(ls):
    return f"Fr::from_limbs_unsafe({arr(ls)})"


# Pallas: y^2 = x^3 + 5 over P; affine, None is the identity.
def on_curve(x, y):
    return (y * y - x * x * x - 5) % P == 0


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        s = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        s = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (s * s - x1 - x2) % P
    return (x3, (s * (x1 - x3) - y1) % P)


def mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = add(out, pt)
        pt = add(pt, pt)
        k >>= 1
    return out


def compressed(p):
    x, y = num(p["x"]), num(p["y"])
    assert not p["is_infinity"] and x < P and y < P and on_curve(x, y)
    return list((x | ((y & 1) << 255)).to_bytes(32, "little"))


def pt(x, y, inf=False):
    return f"Pallas::from_coordinates_unsafe({fq(x)}, {fq(y)}, {str(inf).lower()})"


def point(p):
    return pt(p["x"], p["y"], p["is_infinity"])


def bytes_(bs):
    return "[" + ", ".join(str(int(b)) for b in bs) + "]"


def load(name):
    return json.loads((FIX / name).read_text())["vectors"]


def spend_generator():
    text = (CORE / "src/notes/spend_generator.nr").read_text()
    nums = [int(t) for t in text.replace(",", " ").split() if t.isdigit()]
    assert len(nums) == 6
    return (num(nums[:3]), num(nums[3:]))


def note_fns(tag, v, parts):
    n, o = v["note"], v["ownership"]
    r = n["receiver"]
    out = ""
    if "note" in parts:
        out += f"""fn note_{tag}() -> NoteOpening {{
    NoteOpening {{
        receiver: ExpandedReceiver {{ g_d: {point(r["g_d"])}, pk_d: {point(r["pk_d"])} }},
        value: {int(n["value"])},
        rho: {fq(n["rho"])},
        rseed: {bytes_(n["rseed"])},
    }}
}}
"""
    if "prf" in parts:
        out += f"""fn gd_{tag}() -> [u8; 32] {{
    {bytes_(compressed(r["g_d"]))}
}}
fn pkd_{tag}() -> [u8; 32] {{
    {bytes_(compressed(r["pk_d"]))}
}}
fn psi_{tag}() -> Fq {{
    {fq(v["expected_psi"])}
}}
fn rcm_{tag}() -> Fr {{
    {fr(v["expected_rcm"])}
}}
"""
    if "cmx" in parts:
        out += f"""fn cmx_{tag}() -> Fq {{
    {fq(v["expected_cmx"])}
}}
"""
    if "view" in parts:
        out += f"""fn nf_{tag}() -> Fq {{
    {fq(v["expected_nf"])}
}}
fn view_{tag}() -> ViewingAuthority {{
    ViewingAuthority {{ ak: {point(v["ak"])}, nk: {fq(o["nk"])}, rivk: {fr(o["rivk"])} }}
}}
"""
    if "spend" in parts:
        out += f"""fn spend_{tag}() -> SpendAuthority {{
    SpendAuthority {{ ask: {fr(o["ask"])}, nk: {fq(o["nk"])}, rivk: {fr(o["rivk"])} }}
}}
"""
    return out


def check_fixtures(ref, ext, internal):
    g = spend_generator()
    assert on_curve(*g)
    for vs in (ext, internal):
        for v in vs:
            ak = (num(v["ak"]["x"]), num(v["ak"]["y"]))
            # Cross-check the in-tree generator against the native reference.
            assert mul(num(v["ownership"]["ask"]), g) == ak and ak[1] % 2 == 0
    for i in range(3):
        assert ref[i]["note"] == ext[i]["note"] != internal[i]["note"]
        assert ext[i]["ak"] == internal[i]["ak"]
        for k in ("ask", "nk"):
            assert ext[i]["ownership"][k] == internal[i]["ownership"][k]
        assert ext[i]["ownership"]["rivk"] != internal[i]["ownership"]["rivk"]
    return g


def changed_ask(v, g):
    """Smallest ask + d whose ak has an even y, so verify reaches the receiver check."""
    ask = num(v["ownership"]["ask"])
    for d in range(1, 64):
        ak = mul(ask + d, g)
        if ak[1] % 2 == 0:
            assert ask + d < R
            return d, limbs(ask + d)
    raise AssertionError("no even-y ask")


def flip(ls):
    out = [int(x) for x in ls]
    out[0] ^= 1
    return out


def flip_bytes(bs):
    out = [int(b) for b in bs]
    out[0] ^= 1
    return out


def reduction_values():
    return sorted(
        set(
            [0, 1, P - 1, P, P + 1, R - 1, R, R + 1, 2**512 - 1]
            + [2**k + d for k in [120, 240, 255, 256, 480, 511] for d in [-1, 0, 1]]
        )
    )


def reduction_name(n):
    for base, label in [(P, "p"), (R, "r"), (2**512, "2_pow_512")]:
        for d, suffix in [(-1, "_minus_1"), (0, ""), (1, "_plus_1")]:
            if n == base + d:
                return label + suffix
    for k in [120, 240, 255, 256, 480, 511]:
        for d, suffix in [(-1, "_minus_1"), (0, ""), (1, "_plus_1")]:
            if n == 2**k + d:
                return f"2_pow_{k}{suffix}"
    return str(n)


def reduction_test(n):
    name = "reduce512_of_" + reduction_name(n)
    return f"""    #[test]
    fn {name}_matches_python() {{
        check_reduce512({bytes_(n.to_bytes(64, "little"))}, {arr(limbs(n % P))}, {arr(limbs(n % R))});
    }}
"""


def release_uses(text):
    """Noir has no glob import: import what the release module uses."""
    top, release = text.split("__USES__")
    lib = {
        "bigcurve": ["BigCurve", "Pallas"],
        "bignum": ["BigNum", "Pallas_Fq as Fq", "Pallas_Fr as Fr"],
        "ironwood::notes": ["commitment_x", "NoteOpening", "psi", "rcm_v3"],
        "ironwood::notes::nullifier": ["derive_with_commitment"],
        "ironwood::notes::ownership": ["verify", "verify_viewing"],
        "ironwood::poseidon": ["hash2"],
        "super": re.findall(r"^fn (\w+)", top, re.M),
    }

    def used(item):
        name = item.split()[-1]
        if name == "BigNum":
            return any(
                t in release
                for t in (".get_limbs()", "::zero()", "::from_limbs_unsafe(")
            )
        if name == "BigCurve":
            return "Pallas::" in release
        return re.search(rf"\b{name}\b", release) is not None

    lines = []
    for path, items in lib.items():
        items = [i for i in items if used(i)]
        if items:
            lines.append(f"use {path}::{{{', '.join(items)}}};")
    return top + "\n    ".join(lines) + release


def note_tests():
    ref = load("reference.json")
    ext = load("nullifier-reference.json")
    internal = load("internal-nullifier-reference.json")
    g = check_fixtures(ref, ext, internal)
    v0, o0 = ext[0], ext[0]["ownership"]
    gd, pkd, ak = (
        v0["note"]["receiver"]["g_d"],
        v0["note"]["receiver"]["pk_d"],
        v0["ak"],
    )
    rho = v0["note"]["rho"]
    assert (gd["x"], gd["y"]) != (pkd["x"], pkd["y"])
    ak_neg_y = limbs(P - num(ak["y"]))
    d_ask, ask_changed = changed_ask(v0, g)
    rho_flip = flip(rho)
    assert num(rho_flip) < P
    values = reduction_values()
    fast_n = 2**512 - 1
    every = {"note", "prf", "cmx", "view", "spend"}
    helpers = note_fns(0, ext[0], every)
    helpers += "".join(note_fns(i, ext[i], every - {"spend"}) for i in (1, 2))
    helpers += note_fns("int_0", internal[0], every - {"prf"})
    helpers += "".join(
        note_fns(f"int_{i}", internal[i], {"note", "cmx", "view"}) for i in (1, 2)
    )
    release_reductions = "".join(reduction_test(n) for n in values if n != fast_n)
    return release_uses(f"""// Generated by scripts/generate_note_tests.py from fixtures/ironwood_notes
// (nullifier-reference.json, whose notes equal reference.json, and
// internal-nullifier-reference.json). Do not edit. Execution only. Expected psi, rcm, cmx
// and nf are native reference values; encodings, reductions and aliases are
// computed in Python. Receiver mismatch for derive_owned and membership are
// in ironwood_slow_tests nullifier_tests.nr. Off-curve points die in a BigNum hint
// before the on-curve constraint under honest execution; that rejection is
// checked with a bypassed hint in scripts/check_vendor_hints.py.
// Inputs use from_limbs_unsafe/from_coordinates_unsafe (BigNum::from_limbs
// range-checks), so the library, not the test setup, does every validation.
use bigcurve::{{BigCurve, Pallas}};
use bignum::{{BigNum, Pallas_Fq as Fq, Pallas_Fr as Fr}};
use ironwood::notes::{{
    commitment_x, encode_nonidentity, ExpandedReceiver, NoteOpening, psi, rcm_v3,
    ownership::{{SpendAuthority, verify, verify_viewing, ViewingAuthority}},
    reduction::reduce512,
}};
{helpers}fn check_reduce512(bytes: [u8; 64], expected_p: [u128; 3], expected_r: [u128; 3]) {{
    let p: Fq = reduce512(bytes);
    let r: Fr = reduce512(bytes);
    assert(p.get_limbs() == expected_p);
    assert(r.get_limbs() == expected_r);
}}
fn encode_gd_0(x: [u128; 3], y: [u128; 3], is_infinity: bool) -> [u8; 32] {{
    encode_nonidentity(Pallas::from_coordinates_unsafe(Fq::from_limbs_unsafe(x), Fq::from_limbs_unsafe(y), is_infinity))
}}
fn verify_viewing_0(authority: ViewingAuthority) {{
    verify_viewing(note_0().receiver, authority);
}}
fn verify_0(authority: SpendAuthority) {{
    verify(note_0().receiver, authority);
}}

#[test]
fn encode_nonidentity_matches_compressed_encoding() {{
    assert(encode_nonidentity(note_0().receiver.g_d) == gd_0());
    assert(encode_nonidentity(note_0().receiver.pk_d) == pkd_0());
}}
// canonical(point.x), validate_in_range: same integer, a limb >= 2^120.
// REDUNDANT for this input: validate_in_field in the same canonical() (sinsemilla.nr:29),
// the on-curve check of Pallas::from_coordinates (notes.nr:28) and
// checked.x.to_le_bytes() (ironwood notes.nr:29)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn encode_nonidentity_rejects_unnormalised_x_limb() {{
    let _ = encode_gd_0({arr(unnormalised(gd["x"]))}, {arr(gd["y"])}, false);
}}
// canonical(point.x), validate_in_field: x + p.
// REDUNDANT for this input: checked.x.to_le_bytes() (ironwood notes.nr:29)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn encode_nonidentity_rejects_x_alias() {{
    let _ = encode_gd_0({arr(alias(gd["x"], P))}, {arr(gd["y"])}, false);
}}
// canonical(point.y), validate_in_range: same integer, a limb >= 2^120.
// REDUNDANT for this input: validate_in_field in the same canonical() (sinsemilla.nr:29)
// and the on-curve evaluate_quadratic_expression of Pallas::from_coordinates
// (notes.nr:28), which range-checks y's limbs, also reject it. No input is
// rejected by this check alone, so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn encode_nonidentity_rejects_unnormalised_y_limb() {{
    let _ = encode_gd_0({arr(gd["x"])}, {arr(unnormalised(gd["y"]))}, false);
}}
// canonical(point.y), validate_in_field: y + p.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn encode_nonidentity_rejects_y_alias() {{
    let _ = encode_gd_0({arr(gd["x"])}, {arr(alias(gd["y"], P))}, false);
}}
// On-curve coordinates with the identity flag.
#[test(should_fail_with = "Identity point has no encoding")]
fn encode_nonidentity_rejects_identity() {{
    let _ = encode_gd_0({arr(gd["x"])}, {arr(gd["y"])}, true);
}}

#[test]
fn psi_matches_the_native_reference() {{
    let note = note_0();
    assert(psi(note.rseed, note.rho).get_limbs() == psi_0().get_limbs());
}}
// canonical(rho) in psi, validate_in_range: rho = 42 + 2^120 in the low limb.
// REDUNDANT for this input: rho.to_le_bytes() (ironwood notes.nr:45)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn psi_rejects_unnormalised_rho_limb() {{
    let _ = psi(note_0().rseed, Fq::from_limbs_unsafe({arr(unnormalised(rho))}));
}}
// canonical(rho) in psi, validate_in_field: p + 42, an alias of rho = 42.
// REDUNDANT for this input: rho.to_le_bytes() (ironwood notes.nr:45)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn psi_rejects_rho_alias() {{
    let _ = psi(note_0().rseed, Fq::from_limbs_unsafe({arr(limbs(P + 42))}));
}}

#[test]
fn rcm_v3_matches_the_native_reference() {{
    assert(rcm_v3(note_0(), gd_0(), pkd_0(), psi_0()).get_limbs() == rcm_0().get_limbs());
}}
// canonical(note.rho) in rcm_v3, validate_in_range: 42 + 2^120 in the low limb.
// REDUNDANT for this input: note.rho.to_le_bytes() (ironwood notes.nr:60)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rcm_v3_rejects_unnormalised_rho_limb() {{
    let mut note = note_0();
    note.rho = Fq::from_limbs_unsafe({arr(unnormalised(rho))});
    let _ = rcm_v3(note, gd_0(), pkd_0(), psi_0());
}}
// canonical(note.rho) in rcm_v3, validate_in_field: p + 42.
// REDUNDANT for this input: note.rho.to_le_bytes() (ironwood notes.nr:60)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rcm_v3_rejects_rho_alias() {{
    let mut note = note_0();
    note.rho = Fq::from_limbs_unsafe({arr(limbs(P + 42))});
    let _ = rcm_v3(note, gd_0(), pkd_0(), psi_0());
}}
// canonical(psi_value) in rcm_v3, validate_in_range: same integer, a limb >= 2^120.
// REDUNDANT for this input: psi_value.to_le_bytes() (ironwood notes.nr:61)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rcm_v3_rejects_unnormalised_psi_limb() {{
    let _ = rcm_v3(note_0(), gd_0(), pkd_0(), Fq::from_limbs_unsafe({arr(unnormalised(v0["expected_psi"]))}));
}}
// canonical(psi_value) in rcm_v3, validate_in_field: psi + p.
// REDUNDANT for this input: psi_value.to_le_bytes() (ironwood notes.nr:61)
// also rejects it (BigNum to_le_bytes validates canonical form), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rcm_v3_rejects_psi_alias() {{
    let _ = rcm_v3(note_0(), gd_0(), pkd_0(), Fq::from_limbs_unsafe({arr(alias(v0["expected_psi"], P))}));
}}

#[test]
fn commitment_x_matches_the_native_reference() {{
    assert(commitment_x(note_0()).get_limbs() == cmx_0().get_limbs());
}}

#[test]
fn reduce512_of_2_pow_512_minus_1_matches_python() {{
    check_reduce512({bytes_(fast_n.to_bytes(64, "little"))}, {arr(limbs(fast_n % P))}, {arr(limbs(fast_n % R))});
}}

#[test(should_fail_with = "Noncanonical spend validating key sign")]
fn verify_viewing_rejects_the_opposite_ak() {{
    let mut authority = view_0();
    authority.ak = Pallas::from_coordinates_unsafe(authority.ak.x, Fq::from_limbs_unsafe({arr(ak_neg_y)}), false);
    verify_viewing_0(authority);
}}
// rivk.validate_in_range: same integer, a limb >= 2^120.
// REDUNDANT for this input: scalar_mul(domain_r(1), rivk) (ownership.nr:39) runs
// scalar.validate_in_range() (sinsemilla.nr:276), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn verify_viewing_rejects_unnormalised_rivk_limb() {{
    let mut authority = view_0();
    authority.rivk = Fr::from_limbs_unsafe({arr(unnormalised(o0["rivk"]))});
    verify_viewing_0(authority);
}}
// rivk.validate_in_field: rivk + r.
// REDUNDANT for this input: scalar_mul(domain_r(1), rivk) (ownership.nr:39) runs
// scalar.validate_in_field() (sinsemilla.nr:277), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn verify_viewing_rejects_rivk_alias() {{
    let mut authority = view_0();
    authority.rivk = Fr::from_limbs_unsafe({arr(alias(o0["rivk"], R))});
    verify_viewing_0(authority);
}}
// canonical(nk), validate_in_range: same integer, a limb >= 2^120.
// REDUNDANT for this input: validate_in_field in the same canonical() (sinsemilla.nr:29)
// and field_bits(nk) (ownership.nr:31, canonical at sinsemilla.nr:94), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn verify_viewing_rejects_unnormalised_nk_limb() {{
    let mut authority = view_0();
    authority.nk = Fq::from_limbs_unsafe({arr(unnormalised(o0["nk"]))});
    verify_viewing_0(authority);
}}
// canonical(nk), validate_in_field: nk + p.
// REDUNDANT for this input: field_bits(nk) (ownership.nr:31) calls canonical() again
// (sinsemilla.nr:94), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn verify_viewing_rejects_nk_alias() {{
    let mut authority = view_0();
    authority.nk = Fq::from_limbs_unsafe({arr(alias(o0["nk"], P))});
    verify_viewing_0(authority);
}}

// ask.validate_in_range: same integer, a limb >= 2^120.
// REDUNDANT for this input: scalar_mul(spend generator, ask) (ownership.nr:53) runs
// scalar.validate_in_range() (sinsemilla.nr:276), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn verify_rejects_unnormalised_ask_limb() {{
    let mut authority = spend_0();
    authority.ask = Fr::from_limbs_unsafe({arr(unnormalised(o0["ask"]))});
    verify_0(authority);
}}
// ask.validate_in_field: ask + r.
// REDUNDANT for this input: scalar_mul(spend generator, ask) (ownership.nr:53) runs
// scalar.validate_in_field() (sinsemilla.nr:277), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn verify_rejects_ask_alias() {{
    let mut authority = spend_0();
    authority.ask = Fr::from_limbs_unsafe({arr(alias(o0["ask"], R))});
    verify_0(authority);
}}
#[test(should_fail_with = "Zero spending authority")]
fn verify_rejects_zero_ask() {{
    let mut authority = spend_0();
    authority.ask = Fr::zero();
    verify_0(authority);
}}

// Other vectors, bindings and repeated rejections. The
// positives of ownership::verify (via derive_owned) and of external vector 0
// of derive_with_commitment are in ironwood_slow_tests nullifier_tests.nr.
mod extended {{
    __USES__

    fn check_prfs(note: NoteOpening, gd: [u8; 32], pkd: [u8; 32], expected_psi: Fq, expected_rcm: Fr) {{
        assert(psi(note.rseed, note.rho).get_limbs() == expected_psi.get_limbs());
        assert(rcm_v3(note, gd, pkd, expected_psi).get_limbs() == expected_rcm.get_limbs());
    }}
    #[test]
    fn psi_and_rcm_v3_match_native_vector_1() {{
        check_prfs(note_1(), gd_1(), pkd_1(), psi_1(), rcm_1());
    }}
    #[test]
    fn psi_and_rcm_v3_match_native_vector_2() {{
        check_prfs(note_2(), gd_2(), pkd_2(), psi_2(), rcm_2());
    }}
    #[test]
    fn psi_binds_rseed_and_rho() {{
        let note = note_0();
        assert(psi({bytes_(flip_bytes(v0["note"]["rseed"]))}, note.rho).get_limbs() != psi_0().get_limbs());
        assert(psi(note.rseed, Fq::from_limbs_unsafe({arr(rho_flip)})).get_limbs() != psi_0().get_limbs());
    }}
    #[test]
    fn rcm_v3_binds_every_input() {{
        let expected = rcm_0().get_limbs();
        let mut note = note_0();
        note.rseed[0] ^= 1;
        assert(rcm_v3(note, gd_0(), pkd_0(), psi_0()).get_limbs() != expected);
        let mut gd = gd_0();
        gd[0] ^= 1;
        assert(rcm_v3(note_0(), gd, pkd_0(), psi_0()).get_limbs() != expected);
        let mut pkd = pkd_0();
        pkd[0] ^= 1;
        assert(rcm_v3(note_0(), gd_0(), pkd, psi_0()).get_limbs() != expected);
        let mut note = note_0();
        note.value ^= 1;
        assert(rcm_v3(note, gd_0(), pkd_0(), psi_0()).get_limbs() != expected);
        let mut note = note_0();
        note.rho = Fq::from_limbs_unsafe({arr(rho_flip)});
        assert(rcm_v3(note, gd_0(), pkd_0(), psi_0()).get_limbs() != expected);
        let psi_flip = Fq::from_limbs_unsafe({arr(flip(v0["expected_psi"]))});
        assert(rcm_v3(note_0(), gd_0(), pkd_0(), psi_flip).get_limbs() != expected);
    }}

    #[test]
    fn commitment_x_matches_native_vector_1() {{
        assert(commitment_x(note_1()).get_limbs() == cmx_1().get_limbs());
    }}
    #[test]
    fn commitment_x_matches_native_vector_2() {{
        assert(commitment_x(note_2()).get_limbs() == cmx_2().get_limbs());
    }}
    #[test]
    fn commitment_x_binds_value() {{
        let mut note = note_0();
        note.value ^= 1;
        assert(commitment_x(note).get_limbs() != cmx_0().get_limbs());
    }}
    #[test]
    fn commitment_x_binds_rseed() {{
        let mut note = note_0();
        note.rseed[0] ^= 1;
        assert(commitment_x(note).get_limbs() != cmx_0().get_limbs());
    }}
    #[test]
    fn commitment_x_binds_rho() {{
        let mut note = note_0();
        note.rho = Fq::from_limbs_unsafe({arr(rho_flip)});
        assert(commitment_x(note).get_limbs() != cmx_0().get_limbs());
    }}
    // The opening reaches the receiver and rho checks (old harness cases).
    #[test(should_fail_with = "Identity point has no encoding")]
    fn commitment_x_rejects_identity_g_d() {{
        let mut note = note_0();
        note.receiver.g_d = {pt(gd["x"], gd["y"], True)};
        let _ = commitment_x(note);
    }}
    #[test(should_fail_with = "Identity point has no encoding")]
    fn commitment_x_rejects_identity_pk_d() {{
        let mut note = note_0();
        note.receiver.pk_d = {pt(pkd["x"], pkd["y"], True)};
        let _ = commitment_x(note);
    }}
    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn commitment_x_rejects_g_d_x_limb_2_pow_120() {{
        let mut note = note_0();
        note.receiver.g_d = {pt([B120, *gd["x"][1:]], gd["y"])};
        let _ = commitment_x(note);
    }}
    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn commitment_x_rejects_rho_alias() {{
        let mut note = note_0();
        note.rho = Fq::from_limbs_unsafe({arr(limbs(P + 42))});
        let _ = commitment_x(note);
    }}

{release_reductions}
    #[test]
    fn external_nullifier_matches_native_vector_1() {{
        let (cmx, nf) = derive_with_commitment(note_1(), view_1());
        assert((cmx.get_limbs() == cmx_1().get_limbs()) & (nf.get_limbs() == nf_1().get_limbs()));
    }}
    #[test]
    fn external_nullifier_matches_native_vector_2() {{
        let (cmx, nf) = derive_with_commitment(note_2(), view_2());
        assert((cmx.get_limbs() == cmx_2().get_limbs()) & (nf.get_limbs() == nf_2().get_limbs()));
    }}
    #[test]
    fn internal_nullifier_matches_native_vector_0() {{
        let (cmx, nf) = derive_with_commitment(note_int_0(), view_int_0());
        assert((cmx.get_limbs() == cmx_int_0().get_limbs()) & (nf.get_limbs() == nf_int_0().get_limbs()));
    }}
    #[test]
    fn internal_nullifier_matches_native_vector_1() {{
        let (cmx, nf) = derive_with_commitment(note_int_1(), view_int_1());
        assert((cmx.get_limbs() == cmx_int_1().get_limbs()) & (nf.get_limbs() == nf_int_1().get_limbs()));
    }}
    #[test]
    fn internal_nullifier_matches_native_vector_2() {{
        let (cmx, nf) = derive_with_commitment(note_int_2(), view_int_2());
        assert((cmx.get_limbs() == cmx_int_2().get_limbs()) & (nf.get_limbs() == nf_int_2().get_limbs()));
    }}
    #[test]
    fn nullifier_binds_rho() {{
        let mut note = note_0();
        note.rho = Fq::from_limbs_unsafe({arr(rho_flip)});
        let (_, nf) = derive_with_commitment(note, view_0());
        assert(nf.get_limbs() != nf_0().get_limbs());
    }}
    #[test]
    fn nullifier_binds_rseed() {{
        let mut note = note_0();
        note.rseed[0] ^= 1;
        let (_, nf) = derive_with_commitment(note, view_0());
        assert(nf.get_limbs() != nf_0().get_limbs());
    }}
    #[test]
    fn internal_spending_authority_owns_its_receiver() {{
        verify(note_int_0().receiver, spend_int_0());
    }}
    #[test(should_fail_with = "Note receiver does not match viewing authority")]
    fn verify_viewing_rejects_a_changed_nk() {{
        let mut authority = view_0();
        authority.nk = Fq::from_limbs_unsafe({arr(flip(o0["nk"]))});
        verify_viewing_0(authority);
    }}
    #[test(should_fail_with = "Note receiver does not match viewing authority")]
    fn verify_viewing_rejects_the_external_rivk_for_an_internal_receiver() {{
        let mut authority = view_int_0();
        authority.rivk = view_0().rivk;
        verify_viewing(note_int_0().receiver, authority);
    }}
    // ask + {d_ask}: the smallest increment whose ak has an even y.
    #[test(should_fail_with = "Note receiver does not match viewing authority")]
    fn verify_rejects_a_changed_ask() {{
        let mut authority = spend_0();
        authority.ask = Fr::from_limbs_unsafe({arr(ask_changed)});
        verify_0(authority);
    }}
    #[test(should_fail_with = "Identity point has no encoding")]
    fn verify_viewing_rejects_identity_ak() {{
        let mut authority = view_0();
        authority.ak = {pt(ak["x"], ak["y"], True)};
        verify_viewing_0(authority);
    }}
    #[test(should_fail_with = "Identity point has no encoding")]
    fn verify_rejects_identity_pk_d() {{
        let mut receiver = note_0().receiver;
        receiver.pk_d = {pt(pkd["x"], pkd["y"], True)};
        verify(receiver, spend_0());
    }}
}}
""")


def poseidon_tests():
    vs = json.loads(
        (ROOT / "fixtures/poseidon/native-vectors.json").read_text()
    )
    for v in vs:
        for k in ("a", "b"):
            assert num(v[k]) < P
    v0 = vs[0]
    zero = arr(v0["a"])
    assert num(v0["a"]) == num(v0["b"]) == 0
    others = "".join(
        f"""    #[test]
    fn hash2_matches_native_vector_{i}() {{
        check({arr(v["a"])}, {arr(v["b"])}, {arr(v["expected"])});
    }}
"""
        for i, v in enumerate(vs)
        if i
    )
    return release_uses(f"""// Generated by scripts/generate_note_tests.py from
// fixtures/poseidon/native-vectors.json. Do not edit. Execution only.
// validate_in_range/validate_in_field fail with nargo's assert_max_bit_size message.
// Inputs use from_limbs_unsafe (from_limbs range-checks) so hash2 validates.
use bignum::{{BigNum, Pallas_Fq as Fq}};
use ironwood::poseidon::hash2;
fn check(a: [u128; 3], b: [u128; 3], expected: [u128; 3]) {{
    assert(hash2(Fq::from_limbs_unsafe(a), Fq::from_limbs_unsafe(b)).get_limbs() == expected);
}}
#[test]
fn hash2_matches_native_vector_0() {{
    check({zero}, {zero}, {arr(v0["expected"])});
}}
// a.validate_in_range: low limb 2^120.
// REDUNDANT for this input: evaluate_quadratic_expression in quadratic (poseidon.nr:18,
// reached through pow5_shifted) range-checks its operand limbs
// (assert_max_bit_size), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn hash2_rejects_a_limb_2_pow_120() {{
    let _ = hash2(Fq::from_limbs_unsafe({arr([B120, 0, 0])}), Fq::zero());
}}
// a.validate_in_field: the limbs of p.
#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn hash2_rejects_a_alias() {{
    let _ = hash2(Fq::from_limbs_unsafe({arr(limbs(P))}), Fq::zero());
}}
// b.validate_in_range: low limb 2^120.
// REDUNDANT for this input: evaluate_quadratic_expression in quadratic (poseidon.nr:18)
// range-checks its operand limbs (assert_max_bit_size), so deleting the named check is not detected by this test.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn hash2_rejects_b_limb_2_pow_120() {{
    let _ = hash2(Fq::zero(), Fq::from_limbs_unsafe({arr([B120, 0, 0])}));
}}
// b.validate_in_field: the limbs of p.
#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn hash2_rejects_b_alias() {{
    let _ = hash2(Fq::zero(), Fq::from_limbs_unsafe({arr(limbs(P))}));
}}

// Other native vectors and top-limb range rejections.
mod extended {{
    __USES__
{others}    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn hash2_rejects_a_top_limb_2_pow_15() {{
        let _ = hash2(Fq::from_limbs_unsafe({arr([0, 0, 2**15])}), Fq::zero());
    }}
    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn hash2_rejects_b_top_limb_2_pow_15() {{
        let _ = hash2(Fq::zero(), Fq::from_limbs_unsafe({arr([0, 0, 2**15])}));
    }}
}}
""")


def main():
    NOTE_TESTS.write_text(note_tests())
    POSEIDON_TESTS.write_text(poseidon_tests())
    for path in (NOTE_TESTS, POSEIDON_TESTS):
        format_file(path)
    for p in (NOTE_TESTS, POSEIDON_TESTS):
        print(f"wrote {p.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
