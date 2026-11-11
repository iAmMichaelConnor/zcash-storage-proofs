pub mod nullifier;
mod nullifier_generator;
pub mod ownership;
mod spend_generator;
pub mod reduction;
use bignum::{BigNum, Pallas_Fq as Fq, Pallas_Fr as Fr};
use bigcurve::{BigCurve, Pallas};
use crate::sinsemilla::{canonical, field_bits, hash, domain_r, scalar_mul, complete_add};
// Expanded receiver, not the raw11-byte diversifier/address encoding. The note
// commitment binds these points. DiversifyHash(address.d) is a separate claim.
pub struct ExpandedReceiver {
    pub g_d: Pallas,
    pub pk_d: Pallas,
}
// No wallet spending key or viewing key is part of this opening.
pub struct NoteOpening {
    pub receiver: ExpandedReceiver,
    pub value: u64,
    pub rho: Fq,
    pub rseed: [u8; 32],
}

pub fn encode_nonidentity(point: Pallas) -> [u8; 32] {
    canonical(point.x);
    canonical(point.y);
    assert(!point.is_infinity(), "Identity point has no encoding");
    let checked = Pallas::from_coordinates(point.x, point.y, false);
    let mut bytes = checked.x.to_le_bytes();
    bytes[31] = bytes[31] | (((checked.y.get_limbs()[0] & 1) as u8) << 7);
    bytes
}
fn byte_bits<let N: u32>(bytes: [u8; N]) -> [bool; N * 8] {
    let mut bits = [false; N * 8];
    for i in 0..N {
        let b = (bytes[i] as Field).to_le_bits::<8>();
        for j in 0..8 {
            bits[8 * i + j] = b[j];
        }
    }
    bits
}
pub fn psi(rseed: [u8; 32], rho: Fq) -> Fq {
    canonical(rho);
    let rho = rho.to_le_bytes();
    let mut input = [0u8; 65];
    for i in 0..32 {
        input[i] = rseed[i];
        input[i + 33] = rho[i];
    }
    input[32] = 9;
    reduction::reduce512(crate::hashes::hash::<65, 64>(
        input,
        [90, 99, 97, 115, 104, 95, 69, 120, 112, 97, 110, 100, 83, 101, 101, 100],
    ))
}
pub fn rcm_v3(note: NoteOpening, gd: [u8; 32], pkd: [u8; 32], psi_value: Fq) -> Fr {
    canonical(note.rho);
    canonical(psi_value);
    let rho = note.rho.to_le_bytes();
    let psi_bytes = psi_value.to_le_bytes();
    let mut input = [0u8; 169];
    for i in 0..32 {
        input[i] = note.rseed[i];
        input[33 + i] = gd[i];
        input[65 + i] = pkd[i];
        input[105 + i] = rho[i];
        input[137 + i] = psi_bytes[i];
    }
    input[32] = 11;
    for i in 0..8 {
        input[97 + i] = (note.value >> ((8 * i) as u64)) as u8;
    }
    reduction::reduce512(crate::hashes::hash::<169, 64>(
        input,
        [90, 99, 97, 115, 104, 95, 69, 120, 112, 97, 110, 100, 83, 101, 101, 100],
    ))
}
// Opens the note commitment. Does not claim ownership, unspent status, memo
// contents or chain membership. Identity commitments map to cmx0 as upstream.
#[no_predicates]
pub fn open_v3(note: NoteOpening) -> Pallas {
    open_v3_inner::<0>(note, [[[0u128; 3]; 5]; 109])
}
pub fn open_v3_with_hints(note: NoteOpening, hints: [[[u128; 3]; 5]; 109]) -> Pallas {
    open_v3_inner::<1>(note, hints)
}
#[no_predicates]
fn open_v3_inner<let SUPPLIED: u32>(note: NoteOpening, hints: [[[u128; 3]; 5]; 109]) -> Pallas {
    assert(SUPPLIED <= 1);
    let gd = encode_nonidentity(note.receiver.g_d);
    let pkd = encode_nonidentity(note.receiver.pk_d);
    let psi_value = psi(note.rseed, note.rho);
    let rcm = rcm_v3(note, gd, pkd, psi_value);
    let gd_bits = byte_bits(gd);
    let pkd_bits = byte_bits(pkd);
    let rho_bits = field_bits(note.rho);
    let psi_bits = field_bits(psi_value);
    let value_bits = (note.value as Field).to_le_bits::<64>();
    let mut message = [false; 1086];
    for i in 0..256 {
        message[i] = gd_bits[i];
        message[256 + i] = pkd_bits[i];
    }
    for i in 0..64 {
        message[512 + i] = value_bits[i];
    }
    for i in 0..255 {
        message[576 + i] = rho_bits[i];
        message[831 + i] = psi_bits[i];
    }
    let unblinded = if SUPPLIED == 1 {
        crate::sinsemilla::hash_to_point_with_hints(crate::sinsemilla::domain_q(1), message, hints)
    } else {
        hash(1, message)
    };
    assert(!unblinded.bottom, "Invalid note Sinsemilla commitment");
    complete_add(unblinded.point, scalar_mul(domain_r(0), rcm))
}
pub fn commitment_x(note: NoteOpening) -> Fq {
    let cm = open_v3(note);
    if cm.is_infinity() {
        Fq::zero()
    } else {
        cm.x
    }
}
// DEPTH<32 is only a subtree/diagnostic API. Actual Ironwood anchors use32.
pub fn root_from_opening<let DEPTH: u32>(
    note: NoteOpening,
    position: u32,
    siblings: [Fq; DEPTH],
) -> Fq {
    crate::sinsemilla::merkle_root(commitment_x(note), position, siblings)
}
pub fn verify_contents_membership(
    note: NoteOpening,
    position: u32,
    siblings: [Fq; 32],
    accepted_root: Fq,
) {
    canonical(accepted_root);
    let root = root_from_opening(note, position, siblings);
    assert(root.get_limbs() == accepted_root.get_limbs(), "Ironwood note membership failed");
}

// Optional stronger variant; the key-free entry point is independent.
pub fn verify_owned_membership(
    note: NoteOpening,
    authority: ownership::SpendAuthority,
    position: u32,
    siblings: [Fq; 32],
    accepted_root: Fq,
) {
    verify_contents_membership(note, position, siblings, accepted_root);
    ownership::verify(note.receiver, authority);
}

// Optional untrusted hint source; all opening checks remain in the shared body.
pub fn commitment_x_with_hints(note: NoteOpening, hints: [[[u128; 3]; 5]; 109]) -> Fq {
    let cm = open_v3_with_hints(note, hints);
    if cm.is_infinity() {
        Fq::zero()
    } else {
        cm.x
    }
}
