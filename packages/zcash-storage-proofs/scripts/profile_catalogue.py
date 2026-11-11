#!/usr/bin/env python3
"""Check profiles/catalogue.v1.json and write src/profile-catalogue.ts from it.

Usage, from packages/zcash-storage-proofs: python3 scripts/profile_catalogue.py [--check]

With --check, nothing is written and the command fails if src/profile-catalogue.ts
differs from the catalogue. No compilation, source mutation or proving.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "profiles/catalogue.v1.json"
TYPESCRIPT = ROOT / "src/profile-catalogue.ts"

DIMENSIONS = (
    "blocks",
    "transactionsPerBlock",
    "actionsPerTransaction",
    "legacyBytesPerTransaction",
)


def check_capacities(caps):
    """Return (blocks, transactions, actions, raw) of a shape a circuit can accept.

    ironwood asserts B > 0 and TX > 0 in its decoders, and
    merkle::complete_root asserts that TX is a power of two: its pairwise
    reduction would drop the last node of an odd level. Any other capacity
    compiles to a circuit that rejects every input.
    """
    if not isinstance(caps, dict) or set(caps) != set(DIMENSIONS):
        raise ValueError(f"Profile capacities must have exactly {DIMENSIONS}")
    values = tuple(caps[x] for x in DIMENSIONS)
    b, t, a, r = values
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in values):
        raise ValueError("Profile capacities must be integers")
    if b < 1 or t < 1 or a < 1 or r < 0 or max(values) > 0xFFFFFFFF:
        raise ValueError(
            "Profile blocks, transactions and actions must be 1 to 2^32 - 1; raw bytes 0 to 2^32 - 1"
        )
    if t & (t - 1):
        raise ValueError(
            "transactionsPerBlock must be a power of two (merkle::complete_root)"
        )
    if r and r < 70:
        raise ValueError("legacyBytesPerTransaction must be 0 or at least 70")
    return values


def check_profile(profile):
    kind = profile["generationKind"]
    if kind in ("nullifier-absence", "nullifier-absence-state") or profile["capacities"] is not None:
        check_capacities(profile["capacities"])
    validation = profile["validation"]
    if profile["selectable"] and (
        validation.get("status") != "validated-private"
        or not validation.get("sourceGraphSha256")
        or not validation.get("artifactInterfaceSha256")
    ):
        raise ValueError(
            "A selectable profile needs validated-private status and source graph and artifact interface bindings"
        )


def load():
    data = json.loads(PATH.read_text())
    assert data["schemaVersion"] == 1
    ids = [p["id"] for p in data["profiles"]]
    assert len(ids) == len(set(ids))
    for profile in data["profiles"]:
        try:
            check_profile(profile)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                f"Catalogue profile {profile.get('id')}: {error}"
            ) from None
    return data


def typescript():
    return (
        "// Generated from profiles/catalogue.v1.json. Run `npm run catalogue`.\nexport const PROFILE_CATALOGUE = "
        + json.dumps(load(), indent=2)
        + " as const;\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if src/profile-catalogue.ts differs")
    args = parser.parse_args()
    text = typescript()
    current = TYPESCRIPT.read_text() if TYPESCRIPT.is_file() else None
    if args.check:
        if current != text:
            print("src/profile-catalogue.ts differs from profiles/catalogue.v1.json; run `npm run catalogue`.", file=sys.stderr)
            return 1
        print("profile catalogue: up to date")
        return 0
    if current != text:
        TYPESCRIPT.write_text(text)
        print("wrote src/profile-catalogue.ts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
