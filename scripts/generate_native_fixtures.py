#!/usr/bin/env python3
"""Regenerate the fixtures that come from the Rust reference programs, or check them.

Usage: python3 scripts/generate_native_fixtures.py [--check]

Builds reference/notes and reference/memo (`cargo build --release --locked`; Orchard
and halo2 at the commits pinned in their Cargo.toml), runs them on the retained
transfer data in fixtures/ironwood_transfer, and writes or compares:
  fixtures/ironwood_notes/{reference,nullifier-reference,internal-nullifier-reference,cached-output}.json
  fixtures/memo/native-vectors.json
  fixtures/poseidon/{native-vectors,provenance}.json and noir/ironwood/src/poseidon/constants.nr
  noir/ironwood/src/notes/{spend,nullifier}_generator.nr and fixtures/note-generators/*-provenance.json
  noir/ironwood/src/sinsemilla/generators.nr
Needs cargo (rustup installs the toolchain named in reference/rust-toolchain.toml),
network access for the first build, and nargo ($NARGO) to format the Noir outputs.
Build output goes to reference/target. No proof or key generation.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = "fixtures/ironwood_transfer/bundle.json"
TARGET = ROOT / "reference/target"
RUST_OUTPUTS = [
    "fixtures/ironwood_notes/reference.json",
    "fixtures/ironwood_notes/nullifier-reference.json",
    "fixtures/ironwood_notes/internal-nullifier-reference.json",
    "fixtures/ironwood_notes/cached-output.json",
    "fixtures/memo/native-vectors.json",
]
SCRIPT_OUTPUTS = [
    "fixtures/poseidon/native-vectors.json",
    "fixtures/poseidon/provenance.json",
    "noir/ironwood/src/poseidon/constants.nr",
    "noir/ironwood/src/notes/spend_generator.nr",
    "noir/ironwood/src/notes/nullifier_generator.nr",
    "fixtures/note-generators/spend-generator-provenance.json",
    "fixtures/note-generators/nullifier-generator-provenance.json",
    "noir/ironwood/src/sinsemilla/generators.nr",
]
# Read by the binaries or hashed into the provenance files.
COPY = ["scripts", "fixtures", "noir/ironwood/src", "reference/notes/src", "noirfmt.toml"]


def cargo(crate, *args, capture=False):
    return subprocess.run(
        ["cargo", *args, "--locked"],
        cwd=ROOT / "reference" / crate,
        check=True,
        capture_output=capture,
        text=capture,
    )


def crate_dir(crate, package):
    """The source directory of a dependency of a reference crate."""
    metadata = json.loads(cargo(crate, "metadata", "--format-version", "1", capture=True).stdout)
    (manifest,) = [p["manifest_path"] for p in metadata["packages"] if p["name"] == package]
    return Path(manifest).parent


def run(binary, *args, cwd):
    return subprocess.run(
        [str(TARGET / "release" / binary), *args], cwd=cwd, check=True, capture_output=True
    ).stdout


def generate(copy):
    """Write every output into the scratch copy `copy`."""
    for crate in ("notes", "memo"):
        cargo(crate, "build", "--release", "--target-dir", str(TARGET))
    files = {
        "fixtures/ironwood_notes/reference.json": run("ironwood-note-fixture", cwd=copy),
        "fixtures/ironwood_notes/nullifier-reference.json": run("nullifier", cwd=copy),
        "fixtures/ironwood_notes/internal-nullifier-reference.json": run(
            "nullifier", "--internal", cwd=copy
        ),
        "fixtures/ironwood_notes/cached-output.json": run("output", BUNDLE, cwd=copy),
    }
    native = json.loads(run("ironwood-memo-fixture", cwd=copy))
    cached = json.loads(run("cached", BUNDLE, cwd=copy))
    native["vectors"] = [cached, *native["vectors"]]
    files["fixtures/memo/native-vectors.json"] = (json.dumps(native, indent=2) + "\n").encode()
    for rel, data in files.items():
        (copy / rel).write_bytes(data)
    for argv in (
        ["generate_poseidon.py", TARGET / "release/poseidon", crate_dir("notes", "halo2_poseidon")],
        ["generate_orchard_generators.py", crate_dir("notes", "orchard")],
        ["generate_sinsemilla_generators.py", TARGET / "release/sinsemilla"],
    ):
        subprocess.run(
            [sys.executable, "-B", str(copy / "scripts" / argv[0]), *map(str, argv[1:])],
            cwd=copy,
            check=True,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if a committed file differs")
    args = parser.parse_args()
    outputs = RUST_OUTPUTS + SCRIPT_OUTPUTS
    with tempfile.TemporaryDirectory(prefix="native-") as scratch:
        copy = Path(scratch)
        for name in COPY:
            source = ROOT / name
            if source.is_dir():
                shutil.copytree(source, copy / name, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                (copy / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, copy / name)
        for rel in outputs:
            (copy / rel).unlink()
        generate(copy)
        stale = [rel for rel in outputs if (copy / rel).read_bytes() != (ROOT / rel).read_bytes()]
        if args.check:
            for rel in stale:
                print(f"{rel} differs from the Rust reference output", file=sys.stderr)
            if stale:
                print("Regenerate with `python3 scripts/generate_native_fixtures.py`.", file=sys.stderr)
                return 1
            print("native fixtures: up to date")
            return 0
        for rel in stale:
            shutil.copyfile(copy / rel, ROOT / rel)
            print(f"wrote {rel}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
