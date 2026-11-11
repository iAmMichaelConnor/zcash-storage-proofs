use crate::transactions::digest::{NullifierAbsenceEffects, txid_asserting_nullifier_absence};
mod nullifier_absence_tests;

pub struct BlockEffects<let TX: u32, let A: u32> {
    pub header: [u8; 1487],
    pub transactions: [NullifierAbsenceEffects<A>; TX],
    pub transaction_count: u32,
}
// Every active transaction is opened. Version5 authenticates absence of an
// Ironwood component; version6 authenticates every compact Action and its nf.
// There is deliberately no opaque-txid skip branch for unsupported versions.
pub fn complete_block<let TX: u32, let A: u32>(
    block: BlockEffects<TX, A>,
    queried_nf: [u8; 32],
) -> [u8; 32] {
    assert(block.transaction_count > 0, "V5/V6 scan block has no transactions");
    assert(block.transaction_count <= TX, "V5/V6 scan block exceeds transaction capacity");
    let mut leaves = [[0u8; 32]; TX];
    for i in 0..TX {
        if i < block.transaction_count {
            leaves[i] = txid_asserting_nullifier_absence(block.transactions[i], queried_nf);
        }
    }
    let root = crate::transactions::merkle::complete_root(leaves, block.transaction_count);
    for i in 0..32 {
        assert(block.header[36 + i] == root[i], "Incomplete transaction coverage");
    }
    crate::headers::header_hash(block.header)
}
// SHA256d (internal byte order, not the reversed display hex) of the block just
// before Ironwood (NU6.3) activation. Every scan from activation must link to it.
// Mainnet block 3,428,142: display hash 00000000008b2ffd813f6a09372b4c9d
// a20caad248245086445c19770ac270dd. Testnet block 4,133,999: display hash
// 00001c94671d8de17537daf700e1c11eefd22645344d0a0c77065ed621539feb.
// Provenance: the mainnet raw header from api.blockchair.com hashes
// to this value, and block 3,428,143 links to it and has a V6 coinbase with
// branch 0x37a5165b; api.mainnet.cipherscan.app agrees. The testnet value is
// from api.testnet.cipherscan.app and testnet.zcashexplorer.app (they agree;
// block 4,134,000 links to it). See docs/API.md#pinned-pre-activation-block.
pub global MAINNET_PRE_ACTIVATION_HASH: [u8; 32] = [
    221, 112, 194, 10, 119, 25, 92, 68, 134, 80, 36, 72, 210, 170, 12, 162, 157, 76, 43, 55, 9, 106,
    63, 129, 253, 47, 139, 0, 0, 0, 0, 0,
];
pub global TESTNET_PRE_ACTIVATION_HASH: [u8; 32] = [
    235, 159, 83, 33, 214, 94, 6, 119, 12, 10, 77, 52, 69, 38, 210, 239, 30, 193, 225, 0, 247, 218,
    55, 117, 225, 141, 29, 103, 148, 28, 0, 0,
];
// Testnet NU7 activates at 4,465,026 (vendored zcash_protocol consensus.rs).
// NU7 transactions use another branch ID, so this NU6.3 scan cannot open them.
// Mainnet NU7 is unscheduled; a later epoch needs a protocol update here.
pub global TESTNET_LAST_NU63_HEIGHT: u32 = 4465025;
// Pallas base modulus p, little-endian.
global PALLAS_P_LE: [u8; 32] = [
    1, 0, 0, 0, 237, 48, 45, 153, 27, 249, 76, 9, 252, 152, 70, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 64,
];

pub fn activation(is_testnet: bool) -> u32 {
    if is_testnet {
        4134000
    } else {
        3428143
    }
}
pub fn pinned_prev(is_testnet: bool) -> [u8; 32] {
    if is_testnet {
        TESTNET_PRE_ACTIVATION_HASH
    } else {
        MAINNET_PRE_ACTIVATION_HASH
    }
}
// On-chain Ironwood nullifiers are canonical little-endian encodings below p.
// Since 2p < 2^256, nf + p is another 32-byte string for the same field value
// that never occurs on chain, so every complete scan would prove it absent.
// Reject such aliases; never reduce mod p silently.
pub fn assert_canonical_nf(nf: [u8; 32]) {
    let mut decided = false;
    let mut below = false;
    for k in 0..32 {
        let i = 31 - k;
        if !decided & (nf[i] != PALLAS_P_LE[i]) {
            decided = true;
            below = nf[i] < PALLAS_P_LE[i];
        }
    }
    assert(below, "Noncanonical queried nullifier");
}
pub fn assert_supported_tip(tip_height: u32, is_testnet: bool) {
    assert(
        !is_testnet | (tip_height <= TESTNET_LAST_NU63_HEIGHT),
        "Testnet scan past NU6.3 epoch end",
    );
}
// Checks shared by every scan that starts at activation: canonical nullifier,
// supported epoch, and a first block that links to the pinned predecessor.
pub fn assert_activation_start(
    first_header: [u8; 1487],
    queried_nf: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
) {
    assert_canonical_nf(queried_nf);
    assert_supported_tip(expected_tip_height, is_testnet);
    let pin = pinned_prev(is_testnet);
    for j in 0..32 {
        assert(first_header[4 + j] == pin[j], "Scan must link to pinned pre-activation block");
    }
}
// Continuation relation from a TRUSTED prior. It binds no network, activation or
// nullifier to the prior, so a caller-supplied (hash, height) proves nothing:
// any block after a spend gives "absence" over the last B blocks only. Hence it
// is not public. Stateful continuation uses nullifier_absence_state::advance on a note-backed State.
pub(crate) fn continue_from_trusted_prior<let B: u32, let TX: u32, let A: u32>(
    blocks: [BlockEffects<TX, A>; B],
    queried_nf: [u8; 32],
    trusted_prior_hash: [u8; 32],
    trusted_prior_height: u32,
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
) {
    assert(B > 0);
    assert(
        (trusted_prior_height as u64) + (B as u64) == expected_tip_height as u64,
        "Scan height discontinuity",
    );
    let mut previous = trusted_prior_hash;
    for i in 0..B {
        for j in 0..32 {
            assert(blocks[i].header[4 + j] == previous[j], "Broken scanned block link");
        }
        previous = complete_block(blocks[i], queried_nf);
    }
    assert(previous == expected_tip_hash, "Scan tip does not match accepted checkpoint");
}
// Full bounded absence from the protocol's empty Ironwood nullifier state.
// The first block must link to the pinned pre-activation block, so the B linked
// blocks are exactly heights activation..activation+B-1 of the chosen network.
// The tip hash itself is NOT authenticated here: the caller must take
// (expected_tip_hash, expected_tip_height, is_testnet) from its own accepted
// checkpoint. A fabricated chain from the pin to an unaccepted tip still solves.
// expected_tip_height is the height of the tip block itself. The contents, owned
// and nullifier adapters return a snapshot height h-1 for a header at h; that
// value is not a scan tip height.
pub fn from_activation<let B: u32, let TX: u32, let A: u32>(
    blocks: [BlockEffects<TX, A>; B],
    queried_nf: [u8; 32],
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
) {
    assert(B > 0);
    let start = activation(is_testnet);
    assert(
        (start as u64) + (B as u64) - 1 == expected_tip_height as u64,
        "Scan must begin at Ironwood activation",
    );
    assert_activation_start(
        blocks[0].header,
        queried_nf,
        expected_tip_height,
        is_testnet,
    );
    continue_from_trusted_prior(
        blocks,
        queried_nf,
        pinned_prev(is_testnet),
        start - 1,
        expected_tip_hash,
        expected_tip_height,
    );
}
