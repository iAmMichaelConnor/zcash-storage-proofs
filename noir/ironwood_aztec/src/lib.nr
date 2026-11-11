//! Capsule transport for the pure `ironwood` relations: `verify_contents`,
//! `verify_contents_capsules`, `verify_owned`, `verify_nullifier`, `creation` and
//! `memo` load untrusted witnesses from capsules at the given address and call the
//! shared constrained checks. Applications supply the checkpoint policy and pin the
//! adapter address. Take every field of a claim from one call's return values: a
//! second capsule load is a new unconstrained witness. Capsule layouts:
//! docs/API.md#capsule-slots. Example contracts, each with TXE tests: examples/.
pub mod creation;
use aztec::protocol::address::AztecAddress;
use bignum::{BigNum, Pallas_Fq as Fq};
use bigcurve::{BigCurve, Pallas};
use ironwood::notes::{NoteOpening, ExpandedReceiver};
// Capsule slot table. One slot has one layout, at scope zero, for every
// Ironwood claim at one contract address. The scan contracts use 63 (scan),
// 66 (legacy scan) and 67 (scan state). Claim k of a
// transaction reads slot + CLAIM_STRIDE * k: claim 0 uses the slots below, and
// the ranges of different claims are disjoint (every slot is below 256). A PXE
// returns the first capsule that matches (address, slot, scope), so two claims
// at one address with one claim index read the same witness. Each loaded
// field is an untrusted witness; the claim index selects a witness only and
// adds no constraint. Scope zero is global to every account of a PXE: deliver
// the authority capsules (64, 65) per transaction, never as persistent capsules.
pub global CLAIM_STRIDE: Field = 256;
pub global HEADER_SLOT: Field = 60; // 1836: header1487 || history node317 || auth32
pub global NOTE_SLOT: Field = 61; // 145: opening48 || position || 32 siblings
pub global VIEWING_SLOT: Field = 64; // 12: ak6 || nk3 || rivk3
pub global SPENDING_SLOT: Field = 65; // 9: ask3 || nk3 || rivk3
pub global INCLUSION_SLOT: Field = 68; // 1680 + 148N + 32DEPTH bytes (creation.nr)
pub global OPENING_SLOT: Field = 69; // 48: key-free note opening
pub global MERKLE_HINT_SLOT: Field = 70; // 70 + level, levels 0..31: 52 records
pub global NOTE_HASH_HINT_SLOT: Field = 102; // 109 records
pub global MEMO_SLOT: Field = 103; // 555 + 724N bytes (memo.nr)
// The slot of `slot` for claim `claim` at one address.
pub fn claim_slot(slot: Field, claim: u32) -> Field {
    slot + CLAIM_STRIDE * (claim as Field)
}
unconstrained fn load<let N: u32>(address: AztecAddress, slot: Field) -> [Field; N] {
    aztec::oracle::capsules::load(address, slot, AztecAddress::zero()).expect(
        f"Missing Ironwood witness capsule",
    )
}
pub fn header_snapshot(
    address: AztecAddress,
    claim: u32,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ironwood::headers::LatestSnapshot {
    // Safety: byte ranges and all header/history hash bindings are checked below.
    let raw = unsafe { load::<1836>(address, claim_slot(HEADER_SLOT, claim)) };
    for i in 0..1836 {
        raw[i].assert_max_bit_size::<8>();
    }
    let mut header = [0u8; 1487];
    let mut node = [0u8; 317];
    let mut auth = [0u8; 32];
    for i in 0..1487 {
        header[i] = raw[i] as u8;
    }
    for i in 0..317 {
        node[i] = raw[1487 + i] as u8;
    }
    for i in 0..32 {
        auth[i] = raw[1804 + i] as u8;
    }
    ironwood::headers::verify_header_latest(
        header,
        expected_hash,
        header_height,
        is_testnet,
        node,
        auth,
    )
}
fn field(raw: [Field; 3]) -> Fq {
    for i in 0..2 {
        raw[i].assert_max_bit_size::<120>();
    }
    raw[2].assert_max_bit_size::<15>();
    Fq::from_limbs_unsafe(raw.map(|x| x as u128))
}
fn decode_opening(raw: [Field; 48]) -> NoteOpening {
    let gd = Pallas::from_coordinates_unsafe(
        field([raw[0], raw[1], raw[2]]),
        field([raw[3], raw[4], raw[5]]),
        false,
    );
    let pkd = Pallas::from_coordinates_unsafe(
        field([raw[6], raw[7], raw[8]]),
        field([raw[9], raw[10], raw[11]]),
        false,
    );
    raw[12].assert_max_bit_size::<64>();
    let rho = field([raw[13], raw[14], raw[15]]);
    let mut rseed = [0u8; 32];
    for i in 0..32 {
        raw[16 + i].assert_max_bit_size::<8>();
        rseed[i] = raw[16 + i] as u8;
    }
    NoteOpening {
        receiver: ExpandedReceiver { g_d: gd, pk_d: pkd },
        value: raw[12] as u64,
        rho,
        rseed,
    }
}
pub fn note_opening(address: AztecAddress, claim: u32) -> (NoteOpening, u32, [Fq; 32]) {
    // Safety: decode_opening bounds every opening field; open_v3 checks points.
    let raw = unsafe { load::<145>(address, claim_slot(NOTE_SLOT, claim)) };
    let mut encoded = [0; 48];
    for i in 0..48 {
        encoded[i] = raw[i];
    }
    let note = decode_opening(encoded);
    raw[48].assert_max_bit_size::<32>();
    let mut siblings = [Fq::zero(); 32];
    for i in 0..32 {
        siblings[i] = field([raw[49 + 3 * i], raw[50 + 3 * i], raw[51 + 3 * i]]);
    }
    (note, raw[48] as u32, siblings)
}
// Caller must obtain the checkpoint from its authenticated chain policy.
// This proves cumulative membership by header_height-1, not creation in that block.
// It does not prove that the receiver can decrypt or spend the note.
// Return fields: cmx, value, expanded receiver coordinates, rho, snapshot height.
pub fn verify_contents(
    address: AztecAddress,
    claim: u32,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    verify_contents_inner::<0>(address, claim, expected_hash, header_height, is_testnet)
}
// Optional native hints: NOTE_HASH_HINT_SLOT and MERKLE_HINT_SLOT + level.
pub fn verify_contents_capsules(
    address: AztecAddress,
    claim: u32,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    verify_contents_inner::<1>(address, claim, expected_hash, header_height, is_testnet)
}
fn verify_contents_inner<let SUPPLIED: u32>(
    address: AztecAddress,
    claim: u32,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    assert(SUPPLIED <= 1);
    let snapshot = header_snapshot(address, claim, expected_hash, header_height, is_testnet);
    let (note, position, siblings) = note_opening(address, claim);
    let cmx = if SUPPLIED == 1 {
        // Safety: the pure hash checker constrains every supplied affine record.
        let hints = unsafe {
            crate::sinsemilla::load::<109>(address, claim_slot(NOTE_HASH_HINT_SLOT, claim))
        };
        ironwood::notes::commitment_x_with_hints(note, hints)
    } else {
        ironwood::notes::commitment_x(note)
    };
    if SUPPLIED == 1 {
        let root = crate::sinsemilla::merkle_root_from_capsules(
            address,
            claim_slot(MERKLE_HINT_SLOT, claim),
            cmx,
            position,
            siblings,
        );
        let expected = Fq::from_le_bytes(snapshot.root);
        assert(root.get_limbs() == expected.get_limbs(), "Ironwood note membership failed");
    } else {
        check_membership(cmx, position, siblings, snapshot.root);
    }
    contents(note, cmx, snapshot.height)
}
fn check_membership(cmx: Fq, position: u32, siblings: [Fq; 32], expected_root: [u8; 32]) {
    let root = ironwood::sinsemilla::merkle_root(cmx, position, siblings);
    let expected = Fq::from_le_bytes(expected_root);
    assert(root.get_limbs() == expected.get_limbs(), "Ironwood note membership failed");
}
fn contents(
    note: NoteOpening,
    cmx: Fq,
    height: u32,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    (
        cmx.to_le_bytes(), note.value,
        [
            [note.receiver.g_d.x.get_limbs(), note.receiver.g_d.y.get_limbs()],
            [note.receiver.pk_d.x.get_limbs(), note.receiver.pk_d.y.get_limbs()],
        ], note.rho.get_limbs(), height,
    )
}
pub fn viewing_authority(
    address: AztecAddress,
    claim: u32,
) -> ironwood::notes::ownership::ViewingAuthority {
    // Safety: bounds below; verify_viewing checks canonicality, the point, sign
    // and the complete relation to the note receiver before any nullifier claim.
    let raw = unsafe { load::<12>(address, claim_slot(VIEWING_SLOT, claim)) };
    let ak = Pallas::from_coordinates_unsafe(
        field([raw[0], raw[1], raw[2]]),
        field([raw[3], raw[4], raw[5]]),
        false,
    );
    let nk = field([raw[6], raw[7], raw[8]]);
    let rivk = scalar([raw[9], raw[10], raw[11]]);
    ironwood::notes::ownership::ViewingAuthority { ak, nk, rivk }
}
fn scalar(raw: [Field; 3]) -> bignum::Pallas_Fr {
    for i in 0..2 {
        raw[i].assert_max_bit_size::<120>();
    }
    raw[2].assert_max_bit_size::<15>();
    bignum::Pallas_Fr::from_limbs_unsafe(raw.map(|x| x as u128))
}
pub fn spending_authority(
    address: AztecAddress,
    claim: u32,
) -> ironwood::notes::ownership::SpendAuthority {
    // Safety: limb bounds below; ownership::verify constrains canonicality and
    // the nonzero spending scalar's complete relation to the note receiver.
    let raw = unsafe { load::<9>(address, claim_slot(SPENDING_SLOT, claim)) };
    ironwood::notes::ownership::SpendAuthority {
        ask: scalar([raw[0], raw[1], raw[2]]),
        nk: field([raw[3], raw[4], raw[5]]),
        rivk: scalar([raw[6], raw[7], raw[8]]),
    }
}
// Separate opt-in API: this consumes sensitive spending-authority components.
// One opening gives ownership, membership and the nullifier, so a consumer
// needs no second adapter for "owned unspent note": it scans the returned nf.
// Return fields: cmx, value, expanded receiver coordinates, rho, nf, snapshot
// height. The snapshot height is header_height - 1 (the root covers notes
// through it); it is not the scan tip height.
pub fn verify_owned(
    address: AztecAddress,
    claim: u32,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], [u8; 32], u32) {
    let snapshot = header_snapshot(address, claim, expected_hash, header_height, is_testnet);
    let (note, position, siblings) = note_opening(address, claim);
    let (cmx, nf) =
        ironwood::notes::nullifier::derive_owned(note, spending_authority(address, claim));
    check_membership(cmx, position, siblings, snapshot.root);
    let (cmx_bytes, value, receiver, rho, height) = contents(note, cmx, snapshot.height);
    (cmx_bytes, value, receiver, rho, nf.to_le_bytes(), height)
}
// Separate opt-in API: a viewing authority links this nullifier to this note.
// Does not assert that the nullifier is absent or that the caller can spend.
// Composing this with another adapter (Contents, Created, Owned, memo) is
// sound only if the consumer asserts that both returned cmx values are equal:
// each adapter loads its own capsules, which a PXE can fill with another note.
pub fn verify_nullifier(
    address: AztecAddress,
    claim: u32,
    expected_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], [u8; 32], u32) {
    let snapshot = header_snapshot(address, claim, expected_hash, header_height, is_testnet);
    let (note, position, siblings) = note_opening(address, claim);
    let (cmx, nf) =
        ironwood::notes::nullifier::derive_with_commitment(note, viewing_authority(address, claim));
    check_membership(cmx, position, siblings, snapshot.root);
    (cmx.to_le_bytes(), nf.to_le_bytes(), snapshot.height)
}

pub mod sinsemilla;
// Each slot of one claim has one layout, the Merkle hint levels do not overlap
// another slot, and every slot is below CLAIM_STRIDE, so claims are disjoint.
#[test]
fn slot_table_is_unambiguous() {
    let merkle = MERKLE_HINT_SLOT as u32;
    let single = [
        HEADER_SLOT,
        NOTE_SLOT,
        63,
        VIEWING_SLOT,
        SPENDING_SLOT,
        66,
        67,
        INCLUSION_SLOT,
        OPENING_SLOT,
        NOTE_HASH_HINT_SLOT,
        MEMO_SLOT,
    ];
    for i in 0..single.len() {
        let slot = single[i] as u32;
        assert((slot < merkle) | (slot >= merkle + 32), "Slot overlaps the Merkle hints");
        assert(slot < CLAIM_STRIDE as u32, "Slot reaches the next claim");
        for j in 0..i {
            assert(single[j] != single[i], "Two layouts share one slot");
        }
    }
    assert(merkle + 32 <= CLAIM_STRIDE as u32);
    assert(claim_slot(MEMO_SLOT, 0) == 103);
    assert(claim_slot(HEADER_SLOT, 2) == 572);
}

pub mod memo;
