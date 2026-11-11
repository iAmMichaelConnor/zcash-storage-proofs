"""Write, or with --check compare, the host test fixtures.

Fixture conversion only. Production host exports never read these files.

Usage, from packages/zcash-storage-proofs: python3 tests/prepare-fixtures.py [--check]

Inputs are the repository's committed native fixtures (fixtures/ironwood_notes,
fixtures/memo, fixtures/ironwood_headers) and its Python fixture modules in
scripts/. Files that are not regenerated: the public-source files listed in
tests/fixtures/public-source-manifest.json, and raw-v6-transfer.json, the retained raw
transaction of fixtures/ironwood_transfer, which is checked against RAW_TRANSFER_SHA256
and against the transaction effects of that bundle.
"""

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

R = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(R / "scripts"))
from ironwood_transaction_fixtures import block, pair, row, sha, txid
from prepare_memo_fixtures import build as memo_build
from synthetic_fixtures import capsule_oracle, contents_manifest

D = Path(__file__).resolve().parent / "fixtures"
read = lambda p: json.loads((R / p).read_text())

RAW_TRANSFER = "raw-v6-transfer.json"
RAW_TRANSFER_SHA256 = "faab6613e19999d1a4ad3d475c464c3ae92549b777d381e0cb58b47cbddfc255"


def capsule_bytes(oracle):
    return [int.from_bytes(bytes(v), "big") for v in oracle["result"]["values"][1]]


def note_abi(v):
    n = copy.deepcopy(v)
    for p in n["receiver"].values():
        for k in ["x", "y"]:
            p[k] = {"limbs": p[k]}
    n["rho"] = {"limbs": n["rho"]}
    return n


def inclusion(effects, count=3, index=2, action_index=0, depth=3):
    """Merkle witness of the transaction among `count` synthetic siblings, and the
    synthetic header (hash, leaf) that commits to it."""
    leaf = txid(
        dict(effects=effects, version=6, action_count=len(effects["compact_actions"]))
    )
    leaves = [sha(bytes([i])) for i in range(count)]
    leaves[index] = leaf
    pos = index
    siblings = []
    while len(leaves) > 1:
        siblings.append(leaves[pos ^ 1] if pos ^ 1 < len(leaves) else leaves[pos])
        padded = leaves + [leaves[-1]] if len(leaves) % 2 else leaves
        leaves = [pair(padded[i], padded[i + 1]) for i in range(0, len(padded), 2)]
        pos //= 2
    header = (
        (4).to_bytes(4, "little")
        + bytes([17]) * 32
        + leaves[0]
        + bytes([19]) * 32
        + (1700000000).to_bytes(4, "little")
        + (0x1F07FFFF).to_bytes(4, "little")
        + bytes([23]) * 32
        + b"\xfd\x40\x05"
        + bytes(1344)
    )
    return (
        dict(
            effects=effects,
            header=list(header),
            siblings=[list(x) for x in siblings] + [[0] * 32] * (depth - len(siblings)),
            action_index=action_index,
            tx_index=index,
            tx_count=count,
        ),
        list(sha(sha(header))),
        list(leaf),
    )


def inclusion_capsule(w, depth=32):
    e = w["effects"]
    word = lambda x: list(x.to_bytes(4, "little"))
    return (
        w["header"]
        + sum(e["compact_actions"], [])
        + e["memos_digest"]
        + e["noncompact_digest"]
        + [e["flags"]]
        + e["value_balance"]
        + e["transparent_digest"]
        + e["sapling_digest"]
        + e["orchard_digest"]
        + word(e["lock_time"])
        + word(e["expiry_height"])
        + sum(w["siblings"] + [[0] * 32] * (depth - len(w["siblings"])), [])
        + word(w["action_index"])
        + word(w["tx_index"])
        + word(w["tx_count"])
    )


def opening_capsule(n):
    return (
        [
            x
            for key in ["g_d", "pk_d"]
            for coord in ["x", "y"]
            for x in n["receiver"][key][coord]["limbs"]
        ]
        + [n["value"]]
        + n["rho"]["limbs"]
        + n["rseed"]
    )


def created_manifest():
    """The created-in-block claim for the cached native output, inside a synthetic
    one-Action transaction, Merkle path and header."""
    native = read("fixtures/ironwood_notes/cached-output.json")
    effects = row(6, 1, 0)["effects"]
    effects["compact_actions"] = effects["compact_actions"][:1]
    w, header_hash, txid_le = inclusion(effects)
    note = note_abi(native["note"])
    cmx = list(bytes.fromhex(native["cmx_hex"]))
    assert w["effects"]["compact_actions"][0][:32] == list(
        bytes.fromhex(native["rho_hex"])
    )
    assert w["effects"]["compact_actions"][0][32:64] == cmx
    returned = (
        cmx
        + txid_le
        + [note["value"]]
        + [
            z
            for k in ["g_d", "pk_d"]
            for c in ["x", "y"]
            for z in note["receiver"][k][c]["limbs"]
        ]
        + note["rho"]["limbs"]
    )
    return dict(
        parent_inputs={"accepted_header_hash": header_hash},
        parent_returns=list(map(str, returned)),
        parent_prefix_oracles=[
            capsule_oracle(69, opening_capsule(note)),
            capsule_oracle(68, inclusion_capsule(w)),
        ],
    )


def contents_fixtures():
    """The cached note opening under a synthetic header whose history node carries
    the opening's synthetic root."""
    reference = read("fixtures/ironwood_notes/reference.json")["vectors"][0]
    cm = contents_manifest(reference, read("fixtures/ironwood_headers/header-mainnet.json"))
    expected = json.dumps(
        {
            "capsules": [
                [str(x) for x in capsule_bytes(o)] for o in cm["parent_prefix_oracles"]
            ],
            "returns": cm["parent_returns"],
        }
    )
    header_payload = capsule_bytes(cm["parent_prefix_oracles"][0])
    rn = reference["note"]
    point_xy = lambda p: {"x": p["x"], "y": p["y"]}
    envelope = {
        "schemaVersion": 1,
        "kind": "contents",
        "protocol": {"pool": "ironwood-v3", "era": "nu6.3", "network": "mainnet"},
        "checkpoint": {
            "height": cm["parent_inputs"]["header_height"],
            "hashLE": bytes(cm["parent_inputs"]["expected_hash"]).hex(),
            "policyId": "test-only/synthetic-checkpoint",
        },
        "header": {
            "headerHex": bytes(header_payload[:1487]).hex(),
            "historyNodeHex": bytes(header_payload[1487:1804]).hex(),
            "authRootHex": bytes(header_payload[1804:]).hex(),
        },
        "note": {
            "receiver": {
                "g_d": point_xy(rn["receiver"]["g_d"]),
                "pk_d": point_xy(rn["receiver"]["pk_d"]),
            },
            "value": str(rn["value"]),
            "rho": rn["rho"],
            "rseedHex": bytes(rn["rseed"]).hex(),
        },
        "membership": {
            "position": int(reference["position"]),
            "siblings": reference["siblings"],
        },
    }
    return {
        "contents-expected.json": expected,
        "contents.v1.json": json.dumps(envelope, indent=2) + "\n",
    }


def created_fixtures():
    """The cached output in a synthetic one-Action transaction."""
    m = created_manifest()
    raw = capsule_bytes(m["parent_prefix_oracles"][1])
    nraw = capsule_bytes(m["parent_prefix_oracles"][0])
    off = 1487
    fx = {"compact_actions": [raw[off : off + 148]]}
    off += 148
    for key in ["memos_digest", "noncompact_digest"]:
        fx[key] = raw[off : off + 32]
        off += 32
    fx["flags"] = raw[off]
    off += 1
    fx["value_balance"] = raw[off : off + 8]
    off += 8
    for key in ["transparent_digest", "sapling_digest", "orchard_digest"]:
        fx[key] = raw[off : off + 32]
        off += 32
    for key in ["lock_time", "expiry_height"]:
        fx[key] = int.from_bytes(bytes(raw[off : off + 4]), "little")
        off += 4
    siblings = [bytes(raw[off + 32 * i : off + 32 * (i + 1)]).hex() for i in range(32)]
    off += 32 * 32
    indices = [
        int.from_bytes(bytes(raw[off + 4 * i : off + 4 * (i + 1)]), "little")
        for i in range(3)
    ]
    point = lambda i: {
        "x": list(map(str, nraw[i : i + 3])),
        "y": list(map(str, nraw[i + 3 : i + 6])),
    }
    envelope = {
        "schemaVersion": 1,
        "kind": "created-in-block",
        "protocol": {"pool": "ironwood-v3", "era": "nu6.3", "network": "mainnet"},
        "checkpoint": {
            "height": 3428200,
            "hashLE": bytes(m["parent_inputs"]["accepted_header_hash"]).hex(),
            "policyId": "test-only/synthetic-created-block",
        },
        "headerHex": bytes(raw[:1487]).hex(),
        "transaction": {
            "version": 6,
            "effects": fx,
            "txidLE": txid({"version": 6, "action_count": 1, "effects": fx}).hex(),
        },
        "actionIndex": indices[0],
        "transactionIndex": indices[1],
        "transactionCount": indices[2],
        "siblings": siblings,
        "note": {
            "receiver": {"g_d": point(0), "pk_d": point(6)},
            "value": str(nraw[12]),
            "rho": list(map(str, nraw[13:16])),
            "rseedHex": bytes(nraw[16:48]).hex(),
        },
    }
    # The slot-68 layout ends with action_count (u32 LE); this one-Action witness
    # at capacity 1 has action_count 1 and no padding.
    expected = json.dumps(
        {
            "capsules": [list(map(str, raw + [1, 0, 0, 0])), list(map(str, nraw))],
            "returns": m["parent_returns"],
        }
    )
    return {
        "created.v1.json": json.dumps(envelope, indent=2),
        "created-expected.json": expected,
    }


def memo_fixtures():
    """The host input of memo case 0, built from the same native vector as
    fixtures/memo/case-0.toml."""
    vector = read("fixtures/memo/native-vectors.json")["vectors"][0]
    _, host = memo_build(vector)
    return {"memo-host-input.json": json.dumps(host, indent=2) + "\n"}


# The host scan rejects a first block that does not link to the pinned
# pre-activation block (mainnet 3,428,142; testnet 4,133,999) and a testnet tip
# past 4,465,025. The scans start from the pinned predecessor; the one with a
# synthetic predecessor (blocks-synthetic-parent) is the negative case.
PRE_ACTIVATION_DISPLAY = {
    "mainnet": "00000000008b2ffd813f6a09372b4c9da20caad248245086445c19770ac270dd",
    "testnet": "00001c94671d8de17537daf700e1c11eefd22645344d0a0c77065ed621539feb",
}
ACTIVATION = {"mainnet": 3428143, "testnet": 4134000}


def scan_blocks(network, previous):
    first = block([row(5, 0, 1), row(6, 1, 2)], previous, 0)
    last = block(
        [row(5, 0, 3), row(6, 2, 4), row(6, 0, 5)], sha(sha(bytes(first["header"]))), 1
    )
    tip_hash = list(sha(sha(bytes(last["header"]))))
    blocks = []
    for i, b in enumerate([first, last]):
        txs = []
        for r in b["transactions"][: b["transaction_count"]]:
            e = r["effects"].copy()
            e["compact_actions"] = e["compact_actions"][: r["action_count"]]
            txs.append({"version": r["version"], "txidLE": txid(r).hex(), "effects": e})
        blocks.append(
            {
                "height": ACTIVATION[network] + i,
                "headerHex": bytes(b["header"]).hex(),
                "transactions": txs,
            }
        )
    return {
        "schemaVersion": 1,
        "kind": "complete-blocks",
        "protocol": {"pool": "ironwood-v3", "era": "nu6.3", "network": network},
        "checkpoint": {
            "height": ACTIVATION[network] + 1,
            "hashLE": bytes(tip_hash).hex(),
            "policyId": "test-only/synthetic-scan",
        },
        "blocks": blocks,
    }


def scan_fixtures():
    pinned = lambda n: bytes.fromhex(PRE_ACTIVATION_DISPLAY[n])[::-1]
    return {
        name: json.dumps(scan_blocks(network, previous), indent=2)
        for name, network, previous in [
            ("blocks.v1.json", "mainnet", pinned("mainnet")),
            ("blocks-testnet.v1.json", "testnet", pinned("testnet")),
            ("blocks-synthetic-parent.v1.json", "mainnet", bytes([17]) * 32),
        ]
    }


def raw_transfer_problems():
    """The retained raw transaction must match its hash and the bundle's effects.
    Reading it does not verify a transfer proof or signatures."""
    data = (D / RAW_TRANSFER).read_bytes()
    problems = []
    if hashlib.sha256(data).hexdigest() != RAW_TRANSFER_SHA256:
        problems.append(f"{RAW_TRANSFER} does not match RAW_TRANSFER_SHA256")
    if json.loads(data)["expectedTxidLE"] != txid(row(6, 1, 9)).hex():
        problems.append(f"{RAW_TRANSFER} differs from the fixtures/ironwood_transfer effects")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if a committed file differs")
    args = parser.parse_args()

    problems = raw_transfer_problems()
    outputs = {
        **contents_fixtures(),
        **created_fixtures(),
        **memo_fixtures(),
        **scan_fixtures(),
    }
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    stale = [
        name
        for name, text in outputs.items()
        if not (D / name).is_file() or (D / name).read_text() != text
    ]
    if args.check:
        for name in stale:
            print(f"tests/fixtures/{name} differs from its generated content", file=sys.stderr)
        if stale:
            print("Regenerate with `npm run fixtures`.", file=sys.stderr)
            return 1
        print("host fixtures: up to date")
        return 0
    D.mkdir(parents=True, exist_ok=True)
    for name in stale:
        (D / name).write_text(outputs[name])
        print(f"wrote tests/fixtures/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
