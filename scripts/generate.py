#!/usr/bin/env python3
"""Regenerate every generated test file and Python-derived fixture, or check them.

Usage: python3 scripts/generate.py [--check]

The generators run in order in a scratch copy of the repository. Every generated
Noir file is then formatted with `nargo fmt` ($NARGO, else `nargo` on PATH) and the
repository's noirfmt.toml. Without --check, the outputs are written back only if
every generator succeeded; with --check, nothing is written and the command fails
if a committed file differs.

Inputs that are not regenerated here: the retained synthetic transfer in
fixtures/ironwood_transfer (one spend and output built locally with
zcash/orchard, checked against its provenance.json) and the outputs of the Rust
reference programs, which scripts/generate_native_fixtures.py regenerates
separately because it needs a Rust build. The nullifier-absence note tests need
the Aztec 6.0.0 SDK packages; see scripts/generate_nullifier_absence_note_tests.py.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (generator, outputs it writes), in dependency order.
STEPS = [
    ("synthetic_fixtures.py", ["fixtures/ironwood_headers/header-mainnet.json"]),
    ("generate_note_value_fixture.py", ["examples/note_value/tests/src/fixture.nr"]),
    ("prepare_memo_fixtures.py", ["fixtures/memo/case-0.toml"]),
    (
        "generate_creation_tests.py",
        ["noir/ironwood_creation_tests/src/creation_tests.nr"],
    ),
    (
        "generate_memo_tests.py",
        [
            "noir/ironwood/src/memo/aead_tests.nr",
            "noir/ironwood/src/memo/digest_tests.nr",
            "noir/ironwood/src/memo/native_tests.nr",
            "noir/ironwood/src/memo/claim_tests.nr",
        ],
    ),
    ("generate_memo_negative_tests.py", ["noir/ironwood/src/memo/negative_tests.nr"]),
    (
        "generate_note_tests.py",
        [
            "noir/ironwood_notes_tests/src/note_tests.nr",
            "noir/ironwood_notes_tests/src/poseidon_tests.nr",
        ],
    ),
    ("generate_nullifier_tests.py", ["noir/ironwood_slow_tests/src/nullifier_tests.nr"]),
    (
        "generate_nullifier_absence_tests.py",
        [
            "noir/ironwood/src/transactions/nullifier_absence/nullifier_absence_tests.nr",
            "examples/nullifier_absence_state/tests/src/fixture.nr",
        ],
    ),
    (
        "generate_transaction_tests.py",
        [
            "noir/ironwood_transactions_tests/src/inclusion_tests.nr",
            "noir/ironwood_transactions_tests/src/legacy_tests.nr",
            "noir/ironwood_transactions_tests/src/nullifier_absence_tests.nr",
            "noir/ironwood_transactions_tests/src/hash_tests.nr",
            "noir/ironwood/src/transactions/inclusion_tests.nr",
            "noir/ironwood/src/transactions/legacy_tests.nr",
            "examples/aztec_nullifier_absence/tests/src/fixture.nr",
        ],
    ),
    (
        "generate_header_tests.py",
        [
            "noir/ironwood/src/headers/header_tests.nr",
            "noir/ironwood/src/headers/history_tests.nr",
        ],
    ),
    (
        "generate_nullifier_absence_note_tests.py",
        [
            "examples/nullifier_absence_state/contract/src/nullifier_absence_note_tests.nr"
        ],
    ),
]
# Generators that rewrite part of an existing file instead of writing it whole.
EDITED_IN_PLACE = {"examples/nullifier_absence_state/tests/src/fixture.nr"}
COPY = ["scripts", "fixtures", "noir", "examples", "noirfmt.toml"]
RETAINED = Path("fixtures/ironwood_transfer")
RETAINED_FILES = {"bundle.json", "semantics.json"}


def retained_problems():
    """The retained transfer inputs must match the hashes in their provenance.json."""
    recorded = json.loads((ROOT / RETAINED / "provenance.json").read_text())["files"]
    if set(recorded) != RETAINED_FILES:
        return [f"{RETAINED}/provenance.json must name exactly {sorted(RETAINED_FILES)}"]
    problems = []
    for name, digest in recorded.items():
        data = (ROOT / RETAINED / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            problems.append(f"{RETAINED / name} does not match provenance.json")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if a committed file differs")
    args = parser.parse_args()

    problems = retained_problems()
    outputs = [o for _, outs in STEPS for o in outs]
    with tempfile.TemporaryDirectory(prefix="generate-") as scratch:
        copy = Path(scratch)
        for name in COPY:
            source = ROOT / name
            if source.is_dir():
                shutil.copytree(source, copy / name, ignore=shutil.ignore_patterns("target", "__pycache__"))
            else:
                shutil.copy2(source, copy / name)
        for rel in outputs:
            if rel not in EDITED_IN_PLACE:
                (copy / rel).unlink(missing_ok=True)
        sys.path.insert(0, str(copy / "scripts"))
        from noir_format import format_file

        for script, _ in STEPS:
            result = subprocess.run(
                [sys.executable, "-B", str(copy / "scripts" / script)],
                cwd=copy,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                problems.append(f"{script} failed:\n{result.stdout}{result.stderr}")
        missing = [rel for rel in outputs if not (copy / rel).is_file()]
        problems += [f"{rel} was not generated" for rel in missing]
        for rel in outputs:
            if rel.endswith(".nr") and rel not in missing:
                format_file(copy / rel)

        stale = [
            rel
            for rel in outputs
            if rel not in missing
            and (
                not (ROOT / rel).is_file()
                or (copy / rel).read_bytes() != (ROOT / rel).read_bytes()
            )
        ]
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 1
        if args.check:
            for rel in stale:
                print(f"{rel} differs from its generator's output", file=sys.stderr)
            if stale:
                print("Regenerate with `python3 scripts/generate.py`.", file=sys.stderr)
                return 1
            print("generated files: up to date")
            return 0
        for rel in stale:
            shutil.copyfile(copy / rel, ROOT / rel)
            print(f"wrote {rel}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
