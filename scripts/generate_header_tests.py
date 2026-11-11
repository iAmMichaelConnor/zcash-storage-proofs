#!/usr/bin/env python3
"""Generate ironwood header, history, hash-tail and CompactSize tests.

Writes noir/ironwood/src/headers/header_tests.nr and history_tests.nr (the
history-epoch boundary: the testnet NU7 activation header 4,465,026 still opens
NU6.3 history; 4,465,027 is outside the supported epoch). Synthetic headers and NU6.3 history nodes are
built and hashed here with hashlib (SHA256d, ZIP 221 BLAKE2b personalisations).
No mining, proof or key generation.

Each negative changes one relation and recomputes every hash and commitment the
change touches, so exactly one guard rejects it, asserted with
`should_fail_with` on its message.
CompactSize aliases call compact_size::read directly: no harness comparison.
"""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "noir/ironwood/src/headers/header_tests.nr"
HISTORY_OUT = ROOT / "noir/ironwood/src/headers/history_tests.nr"
NU63 = 0x37A5165B
MAINNET_ACTIVATION = 3428143
TESTNET_ACTIVATION = 4134000
AUTH = bytes([12]) * 32
ROOT_43 = (43).to_bytes(32, "little")
NL = "\n"


def sha(b):
    return hashlib.sha256(b).digest()


def b2(data, person):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def cs(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def node_bytes(start, end, counts=(1, 2, 3)):
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
        + ROOT_43
        + cs(counts[2])
    )


def header(commitment):
    out = (
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
    assert len(out) == 1487
    return out


def arr(b):
    return "[" + ", ".join(str(x) for x in b) + "]"


definitions = [
    f"global HEADER_BASE: [u8; 1487] = {arr(header(bytes(32)))};",
    f"global AUTH: [u8; 32] = {arr(AUTH)};",
    f"global ROOT_43: [u8; 32] = {arr(ROOT_43)};",
]


def define(name, raw, branch=NU63, opened=True):
    """Padded node and, if opened, its block commitment and header hash."""
    assert len(raw) <= 317
    history = b2(raw, b"ZcashHistory" + branch.to_bytes(4, "little"))
    commit = b2(history + AUTH + bytes(32), b"ZcashBlockCommit")
    definitions.append(
        f"global {name}_NODE: [u8; 317] = {arr(raw + bytes(317 - len(raw)))};"
    )
    if not opened:
        return commit
    definitions.append(f"global {name}_COMMIT: [u8; 32] = {arr(commit)};")
    definitions.append(
        f"global {name}_HASH: [u8; 32] = {arr(sha(sha(header(commit))))};"
    )
    return commit


M_END = MAINNET_ACTIVATION + 7
mainnet_commit = define("MAINNET", node_bytes(MAINNET_ACTIVATION, M_END))
define("TESTNET", node_bytes(TESTNET_ACTIVATION, TESTNET_ACTIVATION))
define("LARGE", node_bytes(MAINNET_ACTIVATION, M_END, (253, 65536, 2**32)))
define("EPOCH", node_bytes(MAINNET_ACTIVATION + 1, M_END))
define("BRANCH", node_bytes(MAINNET_ACTIVATION, M_END), branch=0x12345678)
define("ACTIVATION", node_bytes(MAINNET_ACTIVATION, MAINNET_ACTIVATION))
define("DESCENDING", node_bytes(M_END + 1, M_END))
define("EQUAL", node_bytes(M_END, M_END), opened=False)
# Canonical five-byte epoch start replaced by a nine-byte u64 alias of the same
# value; the commitment and header hash are recomputed over the aliased node.
plain = node_bytes(MAINNET_ACTIVATION, M_END)
assert plain[144:149] == cs(MAINNET_ACTIVATION)
define(
    "ALIAS",
    plain[:144] + b"\xff" + MAINNET_ACTIVATION.to_bytes(8, "little") + plain[149:],
)

# Equihash solution-length prefix (bytes 140..142 = fd 40 05), one byte changed.
EQUIHASH = [(140, 254), (141, 65), (142, 6)]
for index, value in EQUIHASH:
    h = bytearray(header(mainnet_commit))
    h[index] = value
    definitions.append(
        f"global EQUIHASH_{index}_HASH: [u8; 32] = {arr(sha(sha(bytes(h))))};"
    )

# hash_variable_last_block::<317, 32> accepts lengths 257..=317.
personal = b"ZcashHistory" + NU63.to_bytes(4, "little")
definitions.append(f"global PERSONAL: [u8; 16] = {arr(personal)};")
tail_tests = []
for length in [257, 277, 285, 309, 317]:
    message = bytes((i * 19 + 3) % 256 for i in range(length))
    definitions.append(
        f"global TAIL_{length}: [u8; 317] = {arr(message + bytes(317 - length))};"
    )
    definitions.append(
        f"global TAIL_{length}_DIGEST: [u8; 32] = {arr(b2(message, personal))};"
    )
    tail_tests.append(f"""#[test]
fn hash_tail_accepts_length_{length}() {{
    assert(tail(TAIL_{length}, {length}) == TAIL_{length}_DIGEST);
}}""")
definitions.append(
    f"global ZERO_277_DIGEST: [u8; 32] = {arr(b2(bytes(277), personal))};"
)


def u8s(raw):
    return f"black_box::<[u8; {len(raw)}]>({arr(raw)})"


compact_tests = []
for n in [0, 252, 253, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1]:
    raw = cs(n)
    compact_tests.append(f"""#[test]
fn compact_size_reads_{n}() {{
    let (value, end) = compact_size::read({u8s(raw + bytes(9 - len(raw)))}, black_box(0));
    assert(value == {n});
    assert(end == {len(raw)});
}}""")
for width, raw, value in [
    ("u16", b"\xfd\xfc\x00", 252),
    ("u32", b"\xfe\xff\xff\x00\x00", 65535),
    ("u64", b"\xff" + (2**32 - 1).to_bytes(8, "little"), 2**32 - 1),
]:
    assert cs(value) != raw
    compact_tests.append(f"""// {value} in the {width} form; the canonical form is compact_size_reads_{value}.
#[test(should_fail_with = "Noncanonical CompactSize {width}")]
fn compact_size_rejects_{width}_alias() {{
    let _ = compact_size::read({u8s(raw + bytes(9 - len(raw)))}, black_box(0));
}}""")
fits = bytes([0]) + cs(2**32)
assert len(fits) == 10

equihash_companion = NL.join(
    f"""    let mut h{i} = header(MAINNET_COMMIT);
    h{i}[{i}] = {v};
    assert(sha256::digest(sha256::digest(black_box(h{i}))) == EQUIHASH_{i}_HASH);"""
    for i, v in EQUIHASH
)
EQUIHASH_BYTE = {140: "0xfd", 141: "0x40", 142: "0x05"}
equihash_tests = NL.join(
    f"""#[test(should_fail_with = "Equihash solution size byte {i} is not {EQUIHASH_BYTE[i]}")]
fn equihash_prefix_byte_{i}_rejects() {{
    let mut h = header(MAINNET_COMMIT);
    h[{i}] = {v};
    let _ = open(h, EQUIHASH_{i}_HASH, {M_END + 1}, false, MAINNET_NODE, AUTH);
}}"""
    for i, v in EQUIHASH
)

TESTS = f"""// Generated by scripts/generate_header_tests.py. Do not edit.
// Synthetic headers and NU6.3 history nodes hashed with hashlib; no mined block,
// PoW or chain claim. Each negative recomputes every hash and commitment its
// change touches, so only the named guard rejects it. Inputs pass through
// black_box so the constraints execute instead of folding at compile time.
// The testnet NU7 epoch bound is tested in history_tests.nr.
use crate::hashes::hash_variable_last_block;
use crate::headers::{{compact_size, header::verify_header_latest, history::{{LatestSnapshot, parse_v3}}}};
use std::hint::black_box;

{NL.join(definitions)}

fn header(commit: [u8; 32]) -> [u8; 1487] {{
    let mut out = HEADER_BASE;
    for i in 0..32 {{
        out[68 + i] = commit[i];
    }}
    out
}}

fn open(
    bytes: [u8; 1487],
    hash: [u8; 32],
    height: u32,
    is_testnet: bool,
    node: [u8; 317],
    auth: [u8; 32],
) -> LatestSnapshot {{
    verify_header_latest(
        black_box(bytes),
        black_box(hash),
        black_box(height),
        black_box(is_testnet),
        black_box(node),
        black_box(auth),
    )
}}

fn tail(message: [u8; 317], length: u32) -> [u8; 32] {{
    hash_variable_last_block::<317, 32>(black_box(message), black_box(length), PERSONAL)
}}

// Positive controls. Every negative below starts from one of these inputs.
#[test]
fn mainnet_header_opens_history() {{
    let s = open(header(MAINNET_COMMIT), MAINNET_HASH, {M_END + 1}, false, MAINNET_NODE, AUTH);
    assert(s.root == ROOT_43);
    assert(s.height == {M_END});
}}
#[test]
fn testnet_first_post_activation_header_opens_history() {{
    let s = open(header(TESTNET_COMMIT), TESTNET_HASH, {TESTNET_ACTIVATION + 1}, true, TESTNET_NODE, AUTH);
    assert(s.root == ROOT_43);
    assert(s.height == {TESTNET_ACTIVATION});
}}
#[test]
fn mainnet_first_post_activation_header_opens_history() {{
    let s = open(header(ACTIVATION_COMMIT), ACTIVATION_HASH, {MAINNET_ACTIVATION + 1}, false, ACTIVATION_NODE, AUTH);
    assert(s.height == {MAINNET_ACTIVATION});
}}
#[test]
fn large_compact_counts_open_history() {{
    let s = open(header(LARGE_COMMIT), LARGE_HASH, {M_END + 1}, false, LARGE_NODE, AUTH);
    assert(s.root == ROOT_43);
}}
#[test]
fn equal_history_range_parses() {{
    let m = parse_v3(black_box(EQUAL_NODE));
    assert(m.start_height == m.end_height);
}}
// Companion of the Equihash prefix tests: the changed headers hash to the
// supplied values, so header_hash's prefix asserts are the only failure.
#[test]
fn equihash_prefix_variants_hash_as_supplied() {{
{equihash_companion}
}}

#[test(should_fail_with = "Header hash mismatch")]
fn changed_header_byte_rejects() {{
    let mut h = header(MAINNET_COMMIT);
    h[0] = h[0] ^ 1;
    let _ = open(h, MAINNET_HASH, {M_END + 1}, false, MAINNET_NODE, AUTH);
}}
#[test(should_fail_with = "Header hash mismatch")]
fn changed_expected_hash_rejects() {{
    let mut hash = MAINNET_HASH;
    hash[0] = hash[0] ^ 1;
    let _ = open(header(MAINNET_COMMIT), hash, {M_END + 1}, false, MAINNET_NODE, AUTH);
}}
#[test(should_fail_with = "Block commitment opening mismatch")]
fn changed_history_node_rejects() {{
    let mut node = MAINNET_NODE;
    node[0] = node[0] ^ 1;
    let _ = open(header(MAINNET_COMMIT), MAINNET_HASH, {M_END + 1}, false, node, AUTH);
}}
#[test(should_fail_with = "Block commitment opening mismatch")]
fn changed_auth_root_rejects() {{
    let mut auth = AUTH;
    auth[0] = auth[0] ^ 1;
    let _ = open(header(MAINNET_COMMIT), MAINNET_HASH, {M_END + 1}, false, MAINNET_NODE, auth);
}}
// The header commits to the mainnet node digested under another branch id.
#[test(should_fail_with = "Block commitment opening mismatch")]
fn wrong_branch_personalisation_rejects() {{
    let _ = open(header(BRANCH_COMMIT), BRANCH_HASH, {M_END + 1}, false, BRANCH_NODE, AUTH);
}}
#[test(should_fail_with = "History height does not precede header")]
fn wrong_header_height_rejects() {{
    let _ = open(header(MAINNET_COMMIT), MAINNET_HASH, {M_END + 2}, false, MAINNET_NODE, AUTH);
}}
#[test(should_fail_with = "Wrong history epoch start")]
fn wrong_epoch_start_rejects() {{
    let _ = open(header(EPOCH_COMMIT), EPOCH_HASH, {M_END + 1}, false, EPOCH_NODE, AUTH);
}}
#[test(should_fail_with = "Wrong history epoch start")]
fn testnet_history_as_mainnet_rejects() {{
    let _ = open(header(TESTNET_COMMIT), TESTNET_HASH, {TESTNET_ACTIVATION + 1}, false, TESTNET_NODE, AUTH);
}}
// The activation assert is implied by the later ones (start == activation,
// end == height - 1, start <= end). Deleting it changes only which message
// rejects these inputs; no input's accept/reject outcome can detect it.
#[test(should_fail_with = "NU6.3 history starts after activation header")]
fn mainnet_history_as_testnet_rejects() {{
    let _ = open(header(MAINNET_COMMIT), MAINNET_HASH, {M_END + 1}, true, MAINNET_NODE, AUTH);
}}
#[test(should_fail_with = "NU6.3 history starts after activation header")]
fn activation_header_itself_rejects() {{
    let _ = open(header(ACTIVATION_COMMIT), ACTIVATION_HASH, {MAINNET_ACTIVATION}, false, ACTIVATION_NODE, AUTH);
}}
#[test(should_fail_with = "Descending history range")]
fn descending_history_range_rejects() {{
    let _ = parse_v3(black_box(DESCENDING_NODE));
}}
#[test(should_fail_with = "Descending history range")]
fn descending_history_range_rejects_in_header_opening() {{
    let _ = open(header(DESCENDING_COMMIT), DESCENDING_HASH, {M_END + 1}, false, DESCENDING_NODE, AUTH);
}}
// The nonzero byte is after the node length, so the commitment still matches.
// hash_variable_last_block's "Nonzero hash padding" is a second, later guard.
#[test(should_fail_with = "Nonzero history padding")]
fn nonzero_history_padding_rejects() {{
    let mut node = MAINNET_NODE;
    node[316] = 1;
    let _ = open(header(MAINNET_COMMIT), MAINNET_HASH, {M_END + 1}, false, node, AUTH);
}}
#[test(should_fail_with = "Noncanonical CompactSize u64")]
fn aliased_epoch_start_with_matching_hashes_rejects() {{
    let _ = open(header(ALIAS_COMMIT), ALIAS_HASH, {M_END + 1}, false, ALIAS_NODE, AUTH);
}}
// Each changed header's hash is supplied (see the companion test) and the
// history is the mainnet control, so only header_hash's prefix assert fails.
{equihash_tests}
// parse_v3's messageless `end >= 277` and `end <= 317` follow from the parse
// itself (minimum and maximum CompactSize widths; read checks the buffer
// bound), so no input reaches them and they have no test.

{NL.join(tail_tests)}
#[test]
fn hash_tail_accepts_zero_message_277() {{
    assert(tail([0; 317], 277) == ZERO_277_DIGEST);
}}
#[test(should_fail_with = "Length changes final block index")]
fn hash_tail_rejects_length_256() {{
    let _ = tail(TAIL_257, 256);
}}
#[test(should_fail_with = "Length exceeds buffer")]
fn hash_tail_rejects_length_318() {{
    let _ = tail(TAIL_317, 318);
}}
#[test(should_fail_with = "Nonzero hash padding")]
fn hash_tail_rejects_nonzero_padding() {{
    let mut message = [0; 317];
    message[300] = 1;
    let _ = tail(message, 277);
}}

{NL.join(compact_tests)}
#[test]
fn compact_size_reads_last_offset() {{
    let (value, end) = compact_size::read({u8s(bytes(9))}, black_box(8));
    assert(value == 0);
    assert(end == 9);
}}
#[test(should_fail_with = "CompactSize offset outside input")]
fn compact_size_rejects_offset_outside_input() {{
    let _ = compact_size::read({u8s(bytes(9))}, black_box(9));
}}
#[test]
fn compact_size_reads_u64_ending_at_buffer_end() {{
    let (value, end) = compact_size::read({u8s(fits)}, black_box(1));
    assert(value == {2**32});
    assert(end == 10);
}}
// The same u64 with its last byte missing.
#[test(should_fail_with = "Truncated CompactSize")]
fn compact_size_rejects_truncated_u64() {{
    let _ = compact_size::read({u8s(fits[:9])}, black_box(1));
}}
"""


def history_case(start, end):
    raw = node_bytes(start, end)
    history = b2(raw, b"ZcashHistory" + NU63.to_bytes(4, "little"))
    commit = b2(history + AUTH + bytes(32), b"ZcashBlockCommit")
    return raw + bytes(317 - len(raw)), AUTH, commit


last = history_case(4134000, 4465025)
past = history_case(4134000, 4465026)
HISTORY_TESTS = f"""// Generated by scripts/generate_header_tests.py. Do not edit. Execution only.
use crate::headers::history::verify_latest;
global AUTH: [u8; 32] = {arr(last[1])};
global LAST_NODE: [u8; 317] = {arr(last[0])};
global LAST_COMMIT: [u8; 32] = {arr(last[2])};
global PAST_NODE: [u8; 317] = {arr(past[0])};
global PAST_COMMIT: [u8; 32] = {arr(past[2])};
#[test]
fn testnet_nu7_activation_header_opens_the_last_nu63_history() {{
    let snapshot = verify_latest(LAST_NODE, AUTH, LAST_COMMIT, 4465026, true);
    assert(snapshot.height == 4465025);
}}
#[test(should_fail_with = "Testnet header is in the unsupported NU7 epoch")]
fn testnet_header_after_nu7_activation_rejects() {{
    let _ = verify_latest(PAST_NODE, AUTH, PAST_COMMIT, 4465027, true);
}}
"""

for path, text in [(OUT, TESTS), (HISTORY_OUT, HISTORY_TESTS)]:
    path.write_text(text)
    print(f"wrote {path.relative_to(ROOT)}")
