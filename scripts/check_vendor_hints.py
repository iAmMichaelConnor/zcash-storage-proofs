#!/usr/bin/env python3
"""Check that a dishonest BigNum hint cannot change a constrained result.

A Brillig hint is prover-controlled. Each test copies vendor/noir-bignum and
vendor/noir_bigcurve (and, for the last one, ironwood) to a scratch directory,
changes a hint as a malicious prover could, and runs the constrained code with
`nargo execute` or `nargo test` (ACVM execution only; no proof):

- VendorCurveJEqualityHintBinding inverts the BigNum `__eq` hint: CurveJ equality
  of G with 2G must stay false and of G with G true (CurveJ `Eq` is constrained;
  with a hinted `Eq` the inverted hint would flip both).
- VendorInequalityPredication checks that an ABI predicate guards the range and
  modulus checks of `assert_is_not_equal`, not only the inequality.
- VendorDivisionDomains checks Pallas division at the BN254-field aliases of the
  denominator against independent modular inverses, and rejects 0/0.
- VendorQuadraticHintBypass removes the remainder assertion from the quadratic
  expression hint and checks that ironwood's false relations (wrong quotient,
  off-curve point, wrong Sinsemilla record) still fail in the constrained check.

$NARGO names the nargo executable (default `nargo` on PATH).
"""

import os
import re
import shutil
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[1] / "vendor"
HONEST_HINT = "$crate::internal::__eq(&self.get_limbs(), &other.get_limbs())"
INVERTED_HINT = "!$crate::internal::__eq(&self.get_limbs(), &other.get_limbs())"
INTERNAL_EXPORT = "pub use crate::ops::affine::sub_with_hint;\n"

# Pallas (y^2 = x^3 + 5 over Fp): G = (-1, 2) and 2G by the tangent rule.
P = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
NATIVE_FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
G = (P - 1, 2)
_LAMBDA = 3 * G[0] * G[0] * pow(2 * G[1], -1, P) % P
_X2 = (_LAMBDA * _LAMBDA - 2 * G[0]) % P
TWO_G = (_X2, (_LAMBDA * (G[0] - _X2) - G[1]) % P)
for _point in (G, TWO_G):
    assert (_point[1] ** 2 - _point[0] ** 3 - 5) % P == 0

PROBE = """use bignum::{BigNum, Pallas_Fq as Fp};
use bigcurve::{BigCurve, Pallas};
use bigcurve::internal::CurveJ;

fn main(a: [[u128; 3]; 2], b: [[u128; 3]; 2]) -> pub bool {
    let p = Pallas::from_coordinates(Fp::from_limbs(a[0]), Fp::from_limbs(a[1]), false);
    let q = Pallas::from_coordinates(Fp::from_limbs(b[0]), Fp::from_limbs(b[1]), false);
    CurveJ::<Fp, Pallas>::from(p) == CurveJ::<Fp, Pallas>::from(q)
}
"""


def limbs(value):
    return [str((value >> (120 * i)) & ((1 << 120) - 1)) for i in range(3)]


def point_toml(name, point):
    rows = ", ".join("[" + ", ".join(f'"{x}"' for x in limbs(c)) + "]" for c in point)
    return f"{name} = [{rows}]\n"


def patch_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise AssertionError(f"{path}: expected one occurrence of {old!r}")
    path.write_text(text.replace(old, new))


class VendorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nargo = os.environ.get("NARGO", "nargo")


class VendorCurveJEqualityHintBinding(VendorTest):
    def run_probe(self, root, name, p, q):
        (root / "probe" / f"{name}.toml").write_text(
            point_toml("a", p) + point_toml("b", q)
        )
        result = subprocess.run(
            [self.nargo, "execute", "--prover-name", name],
            cwd=root / "probe",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=240,
        )
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        found = re.findall(r"Circuit output: (true|false)", result.stdout)
        self.assertEqual(len(found), 1, result.stdout[-2000:])
        return found[0] == "true"

    def test_inverted_eq_hint_does_not_change_curvej_equality(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for name in ("noir-bignum", "noir_bigcurve"):
                shutil.copytree(
                    VENDOR / name, root / name, ignore=shutil.ignore_patterns("target")
                )
            patch_once(root / "noir-bignum/src/bignum.nr", HONEST_HINT, INVERTED_HINT)
            patch_once(
                root / "noir_bigcurve/src/lib.nr",
                INTERNAL_EXPORT,
                INTERNAL_EXPORT + "    pub use crate::curve_jac::types::CurveJ;\n",
            )
            (root / "probe/src").mkdir(parents=True)
            (root / "probe/Nargo.toml").write_text(
                '[package]\nname = "curvej_eq_probe"\ntype = "bin"\nauthors = [""]\n\n'
                "[dependencies]\n"
                'bignum = { path = "../noir-bignum" }\n'
                'bigcurve = { path = "../noir_bigcurve" }\n'
            )
            (root / "probe/src/main.nr").write_text(PROBE)
            # 2G differs from G in x and in y, so the inverted hint claims
            # both coordinate checks hold.
            self.assertFalse(self.run_probe(root, "distinct", G, TWO_G))
            self.assertTrue(self.run_probe(root, "same", G, G))


class VendorInequalityPredication(VendorTest):
    def test_abi_enabled_and_disabled_calls(self):
        """An ABI predicate must guard range and modulus checks as well as inequality."""
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "src").mkdir()
            (root / "Nargo.toml").write_text(
                '[package]\nname="inequality_predication"\ntype="bin"\nauthors=[]\n'
                "[dependencies]\nbignum={path="
                + json.dumps(str(VENDOR / "noir-bignum"))
                + "}\n"
            )
            (root / "src/main.nr").write_text("""use bignum::params::BigNumParams;
fn main(enabled: bool, modulus: [u128; 4], lhs: [u128; 4], rhs: [u128; 4]) -> pub bool {
    let params: BigNumParams<4, 381> = BigNumParams {
        has_multiplicative_inverse: false, modulus, double_modulus: [0; 4], redc_param: [0; 4]
    };
    if enabled { bignum::internal::assert_is_not_equal(&params, &lhs, &rhs); }
    true
}
""")
            # Canonical BLS12-381 Fq values; the native modulus aliases zero
            # only after the legacy packing into Noir's BN254 scalar Field.
            q = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
            native = NATIVE_FIELD_MODULUS
            modulus = [(q >> (120 * i)) & ((1 << 120) - 1) for i in range(4)]
            alias = [(native >> (120 * i)) & ((1 << 120) - 1) for i in range(4)]
            self.assertLess(native, q)
            cases = [
                (
                    "disabled_invalid",
                    False,
                    [0] * 4,
                    [1 << 127, 0, 0, 0],
                    [0] * 4,
                    True,
                ),
                (
                    "enabled_invalid_modulus",
                    True,
                    [0] * 4,
                    [1, 0, 0, 0],
                    [0] * 4,
                    False,
                ),
                (
                    "enabled_invalid_limb",
                    True,
                    modulus,
                    [1 << 127, 0, 0, 0],
                    [0] * 4,
                    False,
                ),
                ("enabled_valid", True, modulus, [1, 0, 0, 0], [0] * 4, True),
                ("enabled_equal", True, modulus, [0] * 4, [0] * 4, False),
                ("enabled_native_alias", True, modulus, alias, [0] * 4, True),
                ("enabled_native_alias_reversed", True, modulus, [0] * 4, alias, True),
            ]
            for name, enabled, modulus, lhs, rhs, valid in cases:
                with self.subTest(case=name):
                    values = {"modulus": modulus, "lhs": lhs, "rhs": rhs}
                    text = "enabled = " + str(enabled).lower() + "\n"
                    text += "".join(
                        key + " = " + json.dumps([str(x) for x in value]) + "\n"
                        for key, value in values.items()
                    )
                    (root / (name + ".toml")).write_text(text)
                    result = subprocess.run(
                        [self.nargo, "execute", "--prover-name", name],
                        cwd=root,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=120,
                    )
                    if valid:
                        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
                        self.assertIn("Circuit output: true", result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stdout[-2000:])
                        expected = (
                            "assert_is_not_equal fail"
                            if name == "enabled_equal"
                            else "Assertion failed: call to assert_max_bit_size"
                        )
                        self.assertIn(expected, result.stdout)


class VendorDivisionDomains(VendorTest):
    def test_pallas_division_native_aliases_and_zero(self):
        """Validate public division against independent modular inverses at its aliases."""
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "src").mkdir()
            (root / "Nargo.toml").write_text(
                '[package]\nname="division_domains"\ntype="bin"\nauthors=[]\n'
                "[dependencies]\nbignum={path="
                + json.dumps(str(VENDOR / "noir-bignum"))
                + "}\n"
            )
            (root / "src/main.nr").write_text("""use bignum::{BigNum, Pallas_Fq as Fp};
fn main(numerator: [u128; 3], denominator: [u128; 3], expected: [u128; 3]) -> pub bool {
    let a = Fp::from_limbs(numerator);
    let d = Fp::from_limbs(denominator);
    let q = Fp::from_limbs(expected);
    a.validate_in_field();
    d.validate_in_field();
    q.validate_in_field();
    assert(a / d == q, "Quotient differs from integer oracle");
    true
}
""")
            denominators = [
                1,
                NATIVE_FIELD_MODULUS,
                P - NATIVE_FIELD_MODULUS,
                2 * NATIVE_FIELD_MODULUS - P,
            ]
            for i, denominator in enumerate(denominators):
                self.assertGreater(denominator, 0)
                self.assertLess(denominator, P)
                numerator = 1265
                expected = numerator * pow(denominator, -1, P) % P
                self.assertEqual(expected * denominator % P, numerator)
                with self.subTest(denominator=denominator):
                    name = "nonzero_" + str(i)
                    text = "".join(
                        key + " = " + json.dumps(limbs(value)) + "\n"
                        for key, value in [
                            ("numerator", numerator),
                            ("denominator", denominator),
                            ("expected", expected),
                        ]
                    )
                    (root / (name + ".toml")).write_text(text)
                    result = subprocess.run(
                        [self.nargo, "execute", "--prover-name", name],
                        cwd=root,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=120,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout[-2000:])
                    self.assertIn("Circuit output: true", result.stdout)
            # With numerator zero, result*denominator=numerator cannot reject 0/0.
            # The modular nonzero check must reject the zero denominator itself.
            (root / "zero.toml").write_text(
                "".join(
                    key + " = " + json.dumps(limbs(0)) + "\n"
                    for key in ["numerator", "denominator", "expected"]
                )
            )
            result = subprocess.run(
                [self.nargo, "execute", "--prover-name", "zero"],
                cwd=root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout[-2000:])
            self.assertIn("assert_is_not_equal fail", result.stdout)


ROOT = VENDOR.parent
# The hint's remainder assertion, with or without a failure message.
REMAINDER_HINT_ASSERT = re.compile(r"    assert\(__is_zero\(&remainder\)[^\n]*\);\n")
# note_0's pk_d with the low bit of y flipped: canonical, but not on Pallas.
OFF_CURVE_X = (
    224552155349642981271532207037966400,
    61131819454687860702892937560031222,
    11394,
)
OFF_CURVE_Y = (
    1191411021482024585944025894449435875,
    1215616074399697897716650334171713720,
    1348,
)
# Each false relation reaches validate_expression_is_zero once the hint stops
# aborting; its first limb range check is the constraint that fails.
RELATION = '#[test(should_fail_with = "call to assert_max_bit_size")]'
HINT_BYPASS_TESTS = {
    "noir/ironwood/src/memo/diversifier.nr": f"""
{RELATION}
fn hint_bypass_divide_rejects_wrong_quotient() {{
    let numerator = std::hint::black_box(fq(1265));
    let d = bn254_alias_denominators()[0];
    // Safety: the test supplies a wrong quotient to the constrained checker.
    let q = unsafe {{ numerator.__div(&d) }};
    let _ = divide_with_quotient(numerator, d, q + fq(1));
}}
""",
    "noir/ironwood/src/sinsemilla/tests.nr": f"""
{RELATION}
fn hint_bypass_supplied_hint_with_another_final_x_is_rejected() {{
    let message = hint_test_message();
    // The internal-hint hash keeps Brillig codegen within its register limit.
    let internal = hash_to_point(domain_q(0), message);
    assert(!internal.bottom);
    // Safety: the test supplies a wrong record to the constrained checker.
    let mut hints = unsafe {{ hints_for(domain_q(0), message) }};
    hints[1][3][2] = hints[1][3][2] ^ 1;
    let _ = hash_to_point_with_hints(domain_q(0), message, hints);
}}
""",
    "noir/ironwood_notes_tests/src/note_tests.nr": f"""
{RELATION}
fn hint_bypass_encode_nonidentity_rejects_off_curve_point() {{
    let _ = encode_gd_0({list(OFF_CURVE_X)}, {list(OFF_CURVE_Y)}, false);
}}
{RELATION}
fn hint_bypass_commitment_x_rejects_off_curve_pk_d() {{
    let mut note = note_0();
    note.receiver.pk_d = Pallas::from_coordinates_unsafe(
        Fq::from_limbs_unsafe({list(OFF_CURVE_X)}),
        Fq::from_limbs_unsafe({list(OFF_CURVE_Y)}),
        false,
    );
    let _ = commitment_x(note);
}}
""",
}
# (package, test): the bypass tests, and honest controls in the same patched copy.
HINT_BYPASS_RUNS = [
    ("ironwood", "memo::diversifier::hint_bypass_divide_rejects_wrong_quotient"),
    ("ironwood", "memo::diversifier::divide_accepts_bn254_alias_denominators"),
    (
        "ironwood",
        "sinsemilla::tests::hint_bypass_supplied_hint_with_another_final_x_is_rejected",
    ),
    ("ironwood", "sinsemilla::tests::supplied_hints_give_the_same_hash"),
    (
        "ironwood_notes_tests",
        "note_tests::hint_bypass_encode_nonidentity_rejects_off_curve_point",
    ),
    (
        "ironwood_notes_tests",
        "note_tests::hint_bypass_commitment_x_rejects_off_curve_pk_d",
    ),
    (
        "ironwood_notes_tests",
        "note_tests::encode_nonidentity_matches_compressed_encoding",
    ),
]


class VendorQuadraticHintBypass(VendorTest):
    """False BigNum relations are rejected by constraints, not by the hint.

    The quadratic-expression hint asserts that the remainder is zero, so honest
    execution of a false relation (a wrong quotient, an off-curve point, a
    wrong Sinsemilla record) stops in Brillig before any constraint runs. A
    prover controls that hint. This copies the vendor exports, ironwood and its
    notes tests to a scratch directory, removes the hint's assertion and runs
    each rejection: it must fail in the constrained relation check instead.
    """

    def test_false_relations_fail_in_constraints(self):
        x, y = (
            sum(v << (120 * i) for i, v in enumerate(c))
            for c in (OFF_CURVE_X, OFF_CURVE_Y)
        )
        self.assertTrue(x < P and y < P)
        self.assertNotEqual((y * y - x**3 - 5) % P, 0)
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            ignore = shutil.ignore_patterns("target")
            for name in ("noir-bignum", "noir_bigcurve"):
                shutil.copytree(VENDOR / name, root / "vendor" / name, ignore=ignore)
            for package in ("ironwood", "ironwood_notes_tests"):
                (root / "noir" / package).mkdir(parents=True)
                shutil.copy2(
                    ROOT / "noir" / package / "Nargo.toml", root / "noir" / package
                )
                shutil.copytree(
                    ROOT / "noir" / package / "src", root / "noir" / package / "src"
                )
            expressions = root / "vendor/noir-bignum/src/fns/expressions.nr"
            text, count = REMAINDER_HINT_ASSERT.subn("", expressions.read_text())
            self.assertEqual(count, 1, "expected one remainder assertion in the hint")
            expressions.write_text(text)
            for relative, tests in HINT_BYPASS_TESTS.items():
                with (root / relative).open("a") as stream:
                    stream.write(tests)
            for package, test in HINT_BYPASS_RUNS:
                with self.subTest(test=test):
                    result = subprocess.run(
                        [self.nargo, "test", "--exact", test],
                        cwd=root / "noir" / package,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=600,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout[-2000:])
                    self.assertIn("1 test passed", result.stdout, result.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
