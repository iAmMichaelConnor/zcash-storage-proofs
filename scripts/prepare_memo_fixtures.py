#!/usr/bin/env python3
"""Create synthetic accepted-block witnesses around native authenticated notes.

No fixture claims mining, consensus or chain finality. Encryption bytes come from
pinned Rust; Python independently reconstructs transaction digests and headers.
"""

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def h(x, person):
    return hashlib.blake2b(bytes(x), digest_size=32, person=person.encode()).digest()


def sha(x):
    return hashlib.sha256(hashlib.sha256(bytes(x)).digest()).digest()


def limbs_int(xs):
    return sum(int(x) << (120 * i) for i, x in enumerate(xs))


def toml(x):
    if isinstance(x, dict):
        return "{" + ",".join(k + "=" + toml(v) for k, v in x.items()) + "}"
    if isinstance(x, list):
        return "[" + ",".join(toml(v) for v in x) + "]"
    if isinstance(x, bool):
        return str(x).lower()
    return json.dumps(x)


def build(v):
    full = v.get(
        "full_action",
        {
            "encrypted_note": v["ciphertext"],
            "value_commitment": [0] * 32,
            "randomized_key": [0] * 32,
            "outgoing_ciphertext": [0] * 80,
        },
    )
    compact = (
        list(limbs_int(v["note"]["rho"]).to_bytes(32, "little"))
        + v["cmx"]
        + v["ephemeral_key"]
        + v["ciphertext"][:52]
    )
    e = {
        "compact_actions": [compact],
        "memos_digest": list(h(v["ciphertext"][52:564], "ZTxIdIrnActMH_v6")),
        "noncompact_digest": list(
            h(
                full["value_commitment"]
                + full["randomized_key"]
                + v["ciphertext"][564:]
                + full["outgoing_ciphertext"],
                "ZTxIdIrnActNH_v6",
            )
        ),
        "flags": 3,
        "value_balance": [0] * 8,
        "transparent_digest": [0] * 32,
        "sapling_digest": [0] * 32,
        "orchard_digest": [0] * 32,
        "lock_time": 0,
        "expiry_height": 0,
    }
    hdrdigest = h(
        b"".join(
            x.to_bytes(4, "little") for x in [0x80000006, 0xD884B698, 0x37A5165B, 0, 0]
        ),
        "ZTxIdHeadersHash",
    )
    irn = h(
        list(h(compact, "ZTxIdIrnActCH_v6"))
        + e["memos_digest"]
        + e["noncompact_digest"]
        + [e["flags"]]
        + e["value_balance"],
        "ZTxIdIronwd_H_v6",
    )
    txid = hashlib.blake2b(
        hdrdigest + bytes(96) + irn,
        digest_size=32,
        person=b"ZcashTxHash_" + bytes.fromhex("5b16a537"),
    ).digest()
    header = bytearray(1487)
    header[0] = 4
    header[36:68] = txid
    header[140:143] = bytes.fromhex("fd4005")
    note = copy.deepcopy(v["note"])
    for point in note["receiver"].values():
        for xy in ("x", "y"):
            point[xy] = {"limbs": point[xy]}
    note["rho"] = {"limbs": note["rho"]}
    args = {
        "note": note,
        "raw_receiver": v["raw_receiver"],
        "memo": v["memo"],
        "witness": {
            "effects": e,
            "header": list(header),
            "siblings": [[0] * 32 for _ in range(32)],
            "action_index": 0,
            "tx_index": 0,
            "tx_count": 1,
            "action_count": 1,
        },
        "full": [full],
        "accepted_header_hash": list(sha(header)),
        "required_tag": v["memo"][:4],
    }
    hostnote = copy.deepcopy(v["note"])
    hostnote["rseedHex"] = bytes(hostnote.pop("rseed")).hex()
    for point in hostnote["receiver"].values():
        point.pop("is_infinity", None)
    envelope = {
        "schemaVersion": 1,
        "kind": "created-in-block",
        "protocol": {"pool": "ironwood-v3", "era": "nu6.3", "network": "mainnet"},
        "checkpoint": {
            "height": 3428200,
            "hashLE": sha(header).hex(),
            "policyId": "test-only/synthetic-memo-block",
        },
        "headerHex": header.hex(),
        "transaction": {"version": 6, "effects": e, "txidLE": txid.hex()},
        "actionIndex": 0,
        "transactionIndex": 0,
        "transactionCount": 1,
        "siblings": [],
        "note": hostnote,
    }
    return args, {
        "inclusion": envelope,
        "rawReceiverHex": bytes(v["raw_receiver"]).hex(),
        "memoHex": bytes(v["memo"]).hex(),
        "actions": [full],
    }


def main():
    data = json.loads((ROOT / "fixtures/memo/native-vectors.json").read_text())
    out = ROOT / "fixtures/memo"
    # Only case 0 is read (by scripts/generate_memo_tests.py).
    args, _ = build(data["vectors"][0])
    (out / "case-0.toml").write_text(
        "\n".join(k + " = " + toml(val) for k, val in args.items()) + "\n"
    )


if __name__ == "__main__":
    main()
