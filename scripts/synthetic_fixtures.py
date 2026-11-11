#!/usr/bin/env python3
"""Synthetic headers and capsule manifests built from the committed native fixtures.

Everything here is a pure function of fixtures/ironwood_notes/*.json and the
synthetic header fields below. No proof or key generation, and no mined-chain
claim. Run `python3 scripts/synthetic_fixtures.py` to rewrite
fixtures/ironwood_headers/header-mainnet.json; the manifests are built in memory
by scripts/generate_note_value_fixture.py.
"""

import hashlib
import json
from pathlib import Path

from ironwood_transaction_fixtures import sha
from note_inputs import contents_capsule

ROOT = Path(__file__).resolve().parents[1]
NU63 = 0x37A5165B
CAPSULE_SLOT_BASE = 4660


def cs(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 4294967295:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def b2(data, person):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def history_node(start, end, counts=(1, 2, 3)):
    fixed = (
        bytes([7]) * 32
        + b"".join(
            v.to_bytes(4, "little")
            for v in [1700000000, 1700000001, 0x1F07FFFF, 0x1F07FFFF]
        )
        + bytes([8]) * 32
        + bytes([9]) * 32
        + (12345).to_bytes(32, "little")
    )
    return (
        fixed
        + cs(start)
        + cs(end)
        + cs(counts[0])
        + bytes([10]) * 32
        + bytes([11]) * 32
        + cs(counts[1])
        + (42).to_bytes(32, "little")
        + (43).to_bytes(32, "little")
        + cs(counts[2])
    )


def header_fixture(start=3428143, end=3428150, testnet=False):
    """The synthetic header-opening witness (not a mined header): a NU6.3 history
    node covering [start, end] committed in a 1,487-byte header at height end + 1."""
    raw = history_node(start, end)
    auth = bytes([12]) * 32
    history = b2(raw, b"ZcashHistory" + NU63.to_bytes(4, "little"))
    commitment = b2(history + auth + bytes(32), b"ZcashBlockCommit")
    header = (
        (4).to_bytes(4, "little")
        + bytes([13]) * 32
        + bytes([14]) * 32
        + commitment
        + (1700000002).to_bytes(4, "little")
        + (0x1F07FFFF).to_bytes(4, "little")
        + bytes([15]) * 32
        + cs(1344)
        + bytes(i % 251 for i in range(1344))
    )
    assert len(header) == 1487 and len(raw) <= 317
    return dict(
        header=list(header),
        node=list(raw + bytes(317 - len(raw))),
        auth_root=list(auth),
        expected_hash=list(sha(sha(header))),
        header_height=end + 1,
        is_testnet=testnet,
        expected_root=list((43).to_bytes(32, "little")),
    )


def field(x):
    return list(int(x).to_bytes(32, "big"))


def capsule_oracle(slot, payload):
    """The aztec_utl_getCapsule oracle call and result that deliver one capsule."""
    return dict(
        call=dict(
            function="aztec_utl_getCapsule",
            inputs=[
                field(CAPSULE_SLOT_BASE),
                field(slot),
                field(len(payload)),
                field(0),
            ],
        ),
        result=dict(values=[field(1), [field(x) for x in payload]]),
    )


def contents_manifest(vector, header):
    """Key-free contents witness: the note opening of `vector` under a synthetic header
    checkpoint whose history node carries the vector's synthetic root."""
    node = bytearray(header["node"])

    def read_cs(p):
        tag = node[p]
        n = 1 if tag < 253 else {253: 3, 254: 5, 255: 9}[tag]
        value = tag if n == 1 else int.from_bytes(node[p + 1 : p + n], "little")
        return value, p + n

    pos = 144
    for _ in range(3):
        _, pos = read_cs(pos)
    pos += 64
    _, pos = read_cs(pos)
    node[pos + 32 : pos + 64] = bytes.fromhex(vector["root_hex"])
    _, length = read_cs(pos + 64)
    auth = bytes(header["auth_root"])
    history = b2(node[:length], b"ZcashHistory" + NU63.to_bytes(4, "little"))
    commitment = b2(history + auth + bytes(32), b"ZcashBlockCommit")
    raw = bytearray(header["header"])
    raw[68:100] = commitment
    expected_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    header_payload = list(raw) + list(node) + list(auth)
    note_payload = contents_capsule(vector)
    note = vector["note"]
    returns = [*bytes.fromhex(vector["cmx_hex"]), note["value"]]
    for name in ["g_d", "pk_d"]:
        for axis in ["x", "y"]:
            returns.extend(note["receiver"][name][axis])
    returns.extend(note["rho"])
    returns.append(header["header_height"] - 1)
    assert len(returns) == 49
    return dict(
        scope="Actual upstream Ironwood V3 note opening, synthetic history/header checkpoint. No wallet keys in circuit inputs/capsules; no mined block, chain acceptance or kernel proof claim.",
        parent_inputs=dict(
            expected_hash=list(expected_hash),
            header_height=header["header_height"],
            is_testnet=False,
        ),
        parent_returns=[str(int(x)) for x in returns],
        children=[],
        parent_prefix_oracles=[
            capsule_oracle(60, header_payload),
            capsule_oracle(61, note_payload),
        ],
        provenance=dict(
            native_note_reference_sha256=hashlib.sha256(
                (
                    ROOT / "fixtures/ironwood_notes/reference.json"
                ).read_bytes()
            ).hexdigest(),
            cached_transfer_input_matches=True,
            note_capsule_fields=145,
            header_capsule_fields=1836,
            spending_key_passed=False,
            viewing_key_passed=False,
            checkpoint_hash=expected_hash.hex(),
        ),
    )


def main():
    out = ROOT / "fixtures/ironwood_headers/header-mainnet.json"
    out.write_text(json.dumps(header_fixture()))
    print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
