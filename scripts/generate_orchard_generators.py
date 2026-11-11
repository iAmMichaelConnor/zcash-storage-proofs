#!/usr/bin/env python3
"""Export the validated Orchard spending and nullifier generators; no proof work.

Usage: generate_orchard_generators.py ORCHARD_DIR

Reads the coordinates from the Orchard source at ORCHARD_DIR (the checkout of the
commit pinned in reference/notes/Cargo.toml; scripts/generate_native_fixtures.py
passes it), checks that they are canonical Pallas base-field elements on
y^2 = x^3 + 5, and writes noir/ironwood/src/notes/{spend,nullifier}_generator.nr
(formatted with nargo fmt) and their provenance files.
"""

import ast, hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from noir_format import format_file  # noqa: E402

ORCHARD = Path(sys.argv[1])
ORCHARD_URL = "https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/"
Q = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
GENERATORS = [
    ("spend_auth_g.rs", "spend_generator.nr", "spend-generator-provenance.json"),
    ("nullifier_k.rs", "nullifier_generator.nr", "nullifier-generator-provenance.json"),
]


def limbs(x):
    return [x % 2**120, (x >> 120) % 2**120, x >> 240]


def export(source_name, noir_name, provenance_name):
    relative = "src/constants/fixed_bases/" + source_name
    p = ORCHARD / relative
    g = re.search(
        r"pub const GENERATOR:.*?=\s*\((\s*\[[^]]+\]),(\s*\[[^]]+\]),?\s*\);",
        p.read_text(),
        re.S,
    )
    assert g
    coords = [
        int.from_bytes(bytes(ast.literal_eval(g[i].strip())), "little") for i in [1, 2]
    ]
    assert (
        all(0 <= c < Q for c in coords)
        and (coords[1] ** 2 - coords[0] ** 3 - 5) % Q == 0
    )
    out = ROOT / "noir/ironwood/src/notes" / noir_name
    out.write_text(
        "use bignum::{BigNum,Pallas_Fq as Fq};\nuse bigcurve::{BigCurve,Pallas};\npub fn generator()->Pallas{comptime{Pallas::from_coordinates(Fq::from_limbs("
        + str(limbs(coords[0]))
        + "),Fq::from_limbs("
        + str(limbs(coords[1]))
        + "),false)}}\n"
    )
    format_file(out)
    (
        ROOT / "fixtures/note-generators" / provenance_name
    ).write_text(
        json.dumps(
            dict(
                source=ORCHARD_URL + relative,
                source_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                coordinates=[str(x) for x in coords],
                canonical_and_on_curve=True,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    for names in GENERATORS:
        export(*names)
