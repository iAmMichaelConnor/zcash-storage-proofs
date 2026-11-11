"""Independent native digest fixtures; synthetic outer transactions and headers."""

import copy, hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sha = lambda x: hashlib.sha256(x).digest()
pair = lambda l, r: sha(sha(l + r))
b2 = lambda x, p: hashlib.blake2b(x, digest_size=32, person=p).digest()
word = lambda x: int(x).to_bytes(4, "little")
b = json.loads(
    (
        ROOT / "fixtures/ironwood_transfer/bundle.json"
    ).read_text()
)
raw = lambda k: bytes.fromhex(b[k])
enc = raw("enc_ciphertext")
compact = raw("nf") + raw("cmx") + raw("epk") + enc[:52]
second = bytearray(compact)
second[0] ^= 2


def row(version, count, nonce):
    actions = [list(compact), list(second)][:count] + [[0] * 148] * (2 - count)
    e = dict(
        compact_actions=actions,
        memos_digest=list(b2(enc[52:564], b"ZTxIdIrnActMH_v6")),
        noncompact_digest=list(
            b2(
                raw("cv_net") + raw("rk") + enc[564:] + raw("out_ciphertext"),
                b"ZTxIdIrnActNH_v6",
            )
        ),
        flags=b["flag_byte"],
        value_balance=list(b["value_balance"].to_bytes(8, "little", signed=True)),
        transparent_digest=list(b2(b"", b"ZTxIdTranspaHash")),
        sapling_digest=list(b2(b"", b"ZTxIdSaplingHash")),
        orchard_digest=list(
            b2(b"", b"ZTxIdOrchardH_v6" if version == 6 else b"ZTxIdOrchardHash")
        ),
        lock_time=nonce,
        expiry_height=3428200,
    )
    return dict(effects=e, version=version, action_count=count)


def txid(r):
    e = r["effects"]
    v = r["version"]
    h = b"".join(
        word(x)
        for x in [
            0x80000000 | v,
            0xD884B698 if v == 6 else 0x26A7270A,
            0x37A5165B,
            e["lock_time"],
            e["expiry_height"],
        ]
    )
    digests = b2(h, b"ZTxIdHeadersHash") + b"".join(
        bytes(e[k]) for k in ["transparent_digest", "sapling_digest", "orchard_digest"]
    )
    if v == 6:
        component = b""
        if r["action_count"]:
            component = (
                b2(
                    b"".join(
                        bytes(x) for x in e["compact_actions"][: r["action_count"]]
                    ),
                    b"ZTxIdIrnActCH_v6",
                )
                + bytes(e["memos_digest"])
                + bytes(e["noncompact_digest"])
                + bytes([e["flags"]])
                + bytes(e["value_balance"])
            )
        digests += b2(component, b"ZTxIdIronwd_H_v6")
    return b2(digests, b"ZcashTxHash_" + word(0x37A5165B))


def root(leaves):
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves = leaves + [leaves[-1]]
        leaves = [pair(leaves[i], leaves[i + 1]) for i in range(0, len(leaves), 2)]
    return leaves[0]


def block(rows, previous, nonce):
    tree = root([txid(r) for r in rows])
    header = (
        word(4)
        + previous
        + tree
        + bytes([19]) * 32
        + word(1700000000 + nonce)
        + word(0x1F07FFFF)
        + bytes([23]) * 32
        + b"\xfd\x40\x05"
        + bytes(1344)
    )
    assert len(header) == 1487
    return dict(
        header=list(header),
        transactions=rows + [row(5, 0, 100)] * (4 - len(rows)),
        transaction_count=len(rows),
    )


def fixture(testnet=False):
    first = block([row(5, 0, 1), row(6, 1, 2)], bytes([17]) * 32, 0)
    last = block(
        [row(5, 0, 3), row(6, 2, 4), row(6, 0, 5)], sha(sha(bytes(first["header"]))), 1
    )
    return dict(
        blocks=[first, last],
        queried_nf=list(bytes([5]) + bytes(31)),
        expected_tip_hash=list(sha(sha(bytes(last["header"])))),
        expected_tip_height=(4134000 if testnet else 3428143) + 1,
        is_testnet=testnet,
    )
