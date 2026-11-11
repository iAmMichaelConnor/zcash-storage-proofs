"""Write, or with --check compare, the envelope JSON Schemas in src/schemas/.

Usage, from packages/zcash-storage-proofs: python3 scripts/host_schemas.py [--check]

The schemas are structural; semantic field, hash and curve checks remain in the
host validators.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = {}


def obj(properties, required=None):
    return dict(
        type="object",
        properties=properties,
        required=list(properties) if required is None else required,
        additionalProperties=False,
    )


def arr(items, n=None):
    return dict(
        type="array",
        items=items,
        **(dict(minItems=n, maxItems=n) if n is not None else {}),
    )


hex32 = dict(type="string", pattern="^[0-9a-f]{64}$")
rawhex = dict(type="string", pattern="^([0-9a-f]{2})*$")
decimal = dict(type="string", pattern="^(0|[1-9][0-9]*)$")
uint = dict(type="integer", minimum=0, maximum=4294967295)
byte = dict(type="integer", minimum=0, maximum=255)
limbs = arr(decimal, 3)
point = obj(dict(x=limbs, y=limbs))
protocol = obj(
    dict(
        pool={"const": "ironwood-v3"},
        era={"const": "nu6.3"},
        network={"enum": ["mainnet", "testnet"]},
    )
)
checkpoint = obj(
    dict(
        height=uint,
        hashLE=hex32,
        policyId=dict(type="string", minLength=1, maxLength=256),
    )
)
note = obj(
    dict(
        receiver=obj(dict(g_d=point, pk_d=point)),
        value=decimal,
        rho=limbs,
        rseedHex=hex32,
    )
)
common = dict(schemaVersion={"const": 1}, protocol=protocol, checkpoint=checkpoint)


def envelope(kind, **properties):
    return obj(dict(**common, kind={"const": kind}, **properties))


def schema(name, body):
    body = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:zcash-storage-proofs:" + name + ":v1",
        "description": "Structural envelope only. Host validation also checks modulus bounds, canonical encodings, curve and hash bindings. No checkpoint authorization is implied.",
        **body,
    }
    OUTPUTS[f"{name}.v1.json"] = json.dumps(body, indent=2) + "\n"


schema(
    "contents",
    envelope(
        "contents",
        header=obj(
            dict(
                headerHex=dict(type="string", pattern="^[0-9a-f]{2974}$"),
                historyNodeHex=rawhex,
                authRootHex=hex32,
            )
        ),
        note=note,
        membership=obj(dict(position=uint, siblings=arr(limbs, 32))),
    ),
)
effects = obj(
    dict(
        compact_actions=arr(arr(byte, 148)),
        memos_digest=arr(byte, 32),
        noncompact_digest=arr(byte, 32),
        flags=dict(type="integer", minimum=0, maximum=7),
        value_balance=arr(byte, 8),
        transparent_digest=arr(byte, 32),
        sapling_digest=arr(byte, 32),
        orchard_digest=arr(byte, 32),
        lock_time=uint,
        expiry_height=uint,
    )
)
tx = {
    "oneOf": [
        obj(dict(version={"const": 4}, txidLE=hex32, rawHex=rawhex)),
        obj(dict(version={"enum": [5, 6]}, txidLE=hex32, effects=effects)),
    ]
}
schema(
    "complete-blocks",
    envelope(
        "complete-blocks",
        blocks=arr(obj(dict(height=uint, headerHex=rawhex, transactions=arr(tx)))),
    ),
)
schema(
    "raw-blocks",
    envelope("raw-blocks", blocks=arr(obj(dict(height=uint, rawHex=rawhex)))),
)
for kind in ["action-inclusion", "created-in-block"]:
    props = dict(
        headerHex=rawhex,
        transaction=tx,
        actionIndex=uint,
        transactionIndex=uint,
        transactionCount=uint,
        siblings=arr(hex32),
    )
    if kind == "created-in-block":
        props["note"] = note
    schema(kind, envelope(kind, **props))
capsule = obj(
    dict(
        schemaVersion={"const": 1},
        contractAddress=decimal,
        slot=uint,
        scope={"const": "0"},
        fields=arr(decimal),
    )
)
schema(
    "capsules",
    obj(
        dict(
            schemaVersion={"const": 1},
            kind={"const": "capsules"},
            capsules=arr(capsule),
        )
    ),
)
bool_ = {"type": "boolean"}
base = dict(
    **common,
    kind={"const": "prepared-witness"},
    contractAddress=decimal,
    capsules=arr(capsule),
    validation=obj(
        dict(
            structure={"const": True},
            hashBindings={"const": True},
            checkpointAuthorized={"const": False},
            proofVerified={"const": False},
        )
    ),
)
contents_expected = obj(
    dict(
        snapshotHeight=uint,
        rootLE=hex32,
        cmxLE=hex32,
        value=decimal,
        receiver=note["properties"]["receiver"],
        rho=limbs,
        nativeProviderUsed=bool_,
        cmxSource={"const": "native-provider-unverified"},
    ),
    ["snapshotHeight", "rootLE"],
)
prepared_contents = obj(
    dict(
        **base,
        claim={"const": "contents"},
        arguments=obj(
            dict(expected_hash=arr(byte, 32), header_height=uint, is_testnet=bool_)
        ),
        expected=contents_expected,
    )
)
prepared_inclusion = obj(
    dict(
        **base,
        claim={"enum": ["action-inclusion", "created-in-block"]},
        arguments=obj(dict(accepted_header_hash=arr(byte, 32))),
        expected=obj(
            dict(
                txidLE=hex32,
                selectedAction=arr(byte, 148),
                noteCommitmentCheckedByCircuit=bool_,
                actionCount=uint,
                actionCapacity=uint,
            )
        ),
    )
)
scan_args = obj(
    dict(
        queried_nf=arr(byte, 32),
        expected_tip_hash=arr(byte, 32),
        expected_tip_height=uint,
        is_testnet=bool_,
        count=uint,
        prior_height=uint,
    ),
    ["queried_nf", "expected_tip_hash", "expected_tip_height", "is_testnet"],
)
prepared_scan = obj(
    dict(
        **base,
        claim={"enum": ["nullifier-absence-from-activation", "nullifier-absence-window"]},
        profileId={"type": "string"},
        operation={"enum": ["verify", "begin", "extend"]},
        arguments=scan_args,
        authenticatedPriorStateRequired=bool_,
    )
)
schema(
    "prepared-witness",
    {"oneOf": [prepared_contents, prepared_inclusion, prepared_scan]},
)
schema(
    "raw-ironwood-transaction",
    obj(
        dict(
            schemaVersion={"const": 1},
            kind={"const": "raw-ironwood-transaction"},
            protocol=protocol,
            rawTransactionHex=rawhex,
        )
    ),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if a committed schema differs")
    args = parser.parse_args()
    directory = ROOT / "src/schemas"
    stale = [
        name
        for name, text in OUTPUTS.items()
        if not (directory / name).is_file() or (directory / name).read_text() != text
    ]
    extra = sorted(p.name for p in directory.glob("*.json") if p.name not in OUTPUTS)
    if args.check:
        for name in stale:
            print(f"src/schemas/{name} differs from its generated content", file=sys.stderr)
        for name in extra:
            print(f"src/schemas/{name} is not generated by this script", file=sys.stderr)
        if stale or extra:
            print("Regenerate with `npm run schemas`.", file=sys.stderr)
            return 1
        print("schemas: up to date")
        return 0
    for name in stale:
        (directory / name).write_text(OUTPUTS[name])
        print(f"wrote src/schemas/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
