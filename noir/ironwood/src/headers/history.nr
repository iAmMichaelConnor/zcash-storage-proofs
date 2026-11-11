use crate::headers::compact_size;
// NU6.3 branch. Later epochs require an explicit protocol update, not a caller override.
global NU63_BRANCH: u32 = 0x37a5165b;
global MAINNET_ACTIVATION: u32 = 3428143;
global TESTNET_ACTIVATION: u32 = 4134000;
// Testnet NU7 activation (vendored zcash_protocol consensus.rs). From the next
// header on, history uses the NU7 personalisation, which this code does not
// implement. Mainnet has no NU7 height, so mainnet stays open-ended.
global TESTNET_NU7_ACTIVATION: u32 = 4465026;

pub struct LatestSnapshot {
    pub root: [u8; 32],
    pub height: u32,
}
pub struct V3Metadata {
    pub start_height: u64,
    pub end_height: u64,
    pub latest_ironwood_root: [u8; 32],
    pub length: u32,
}
// Padding is checked so capsules have one fixed ABI without unconstrained suffixes.
pub fn parse_v3(node: [u8; 317]) -> V3Metadata {
    let (start_height, p1) = compact_size::read(node, 144);
    let (end_height, p2) = compact_size::read(node, p1);
    assert(start_height <= end_height, "Descending history range");
    // Canonical fields are parsed even where the requested relation does not use their value.
    let (_, p3) = compact_size::read(node, p2);
    let (_, p4) = compact_size::read(node, p3 + 64);
    let mut root = [0u8; 32];
    for i in 0..32 {
        root[i] = node[p4 + 32 + i];
    }
    let (_, end) = compact_size::read(node, p4 + 64);
    // Both bounds follow from the parse: five one-byte CompactSizes give 277,
    // and read() keeps end <= 317. No input reaches them (header_tests.nr).
    assert(end >= 277);
    assert(end <= 317);
    for i in 0..317 {
        if i >= end {
            assert(node[i] == 0, "Nonzero history padding");
        }
    }
    V3Metadata { start_height, end_height, latest_ironwood_root: root, length: end }
}
pub fn history_digest(node: [u8; 317], length: u32) -> [u8; 32] {
    let mut personal = [0u8; 16];
    let domain = "ZcashHistory".as_bytes();
    for i in 0..12 {
        personal[i] = domain[i];
    }
    for i in 0..4 {
        personal[12 + i] = (NU63_BRANCH >> ((8 * i) as u32)) as u8;
    }
    crate::hashes::hash_variable_last_block::<317, 32>(node, length, personal)
}
pub fn commitment(history_root: [u8; 32], auth_root: [u8; 32]) -> [u8; 32] {
    let mut message = [0u8; 96];
    for i in 0..32 {
        message[i] = history_root[i];
        message[32 + i] = auth_root[i];
    }
    crate::hashes::hash::<96, 32>(message, "ZcashBlockCommit".as_bytes())
}
// AUTHENTICATION BOUNDARY: expected_block_commitments and header_height must come
// from the same accepted checkpoint. A caller-chosen pair proves no chain claim.
// This API handles the NU6.3 epoch and the latest previous block only.
// Supported header heights: mainnet > 3,428,143; testnet 4,134,001..=4,465,026.
pub fn verify_latest(
    node: [u8; 317],
    auth_root: [u8; 32],
    expected_block_commitments: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> LatestSnapshot {
    if is_testnet {
        assert(
            header_height <= TESTNET_NU7_ACTIVATION,
            "Testnet header is in the unsupported NU7 epoch",
        );
    }
    let metadata = parse_v3(node);
    let activation = if is_testnet {
        TESTNET_ACTIVATION
    } else {
        MAINNET_ACTIVATION
    };
    // Implied by the next two asserts and parse_v3's start <= end; deleting it
    // changes only the rejecting message, never an accept/reject outcome.
    assert(header_height > activation, "NU6.3 history starts after activation header");
    assert(metadata.start_height == activation as u64, "Wrong history epoch start");
    assert(
        metadata.end_height == (header_height - 1) as u64,
        "History height does not precede header",
    );
    assert(
        commitment(history_digest(node, metadata.length), auth_root) == expected_block_commitments,
        "Block commitment opening mismatch",
    );
    LatestSnapshot { root: metadata.latest_ironwood_root, height: header_height - 1 }
}
