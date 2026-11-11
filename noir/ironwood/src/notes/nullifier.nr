//! Optional nullifier linkage. Unlike contents-only membership, this needs
//! sensitive full-viewing-key components, but no spending scalar or PLUME.
//! A nullifier alone proves nothing about note existence: the nullifier of an
//! invented opening never occurs on chain, so an absence scan of it succeeds.
//! An "unspent note" claim needs membership (or creation) of the SAME opening
//! under the accepted checkpoint: use derive_member, or compare the cmx that
//! derive_with_commitment returns with a membership claim's cmx.
use bignum::{BigNum, Pallas_Fq as Fq, Pallas_Fr as Fr};
use bigcurve::BigCurve;
use crate::sinsemilla::{complete_add, scalar_mul};
use crate::notes::{
    NoteOpening,
    open_v3,
    psi,
    ownership::{SpendAuthority, ViewingAuthority, verify_viewing},
};
// nk must already be bound to this note's receiver by the caller.
fn derive_for_bound_nk(note: NoteOpening, nk: Fq) -> (Fq, Fq) {
    let cm = open_v3(note);
    let scalar_base = crate::poseidon::hash2(nk, note.rho) + psi(note.rseed, note.rho);
    scalar_base.validate_in_field();
    // mod_r_p is an integer injection because Pallas base p < scalar r.
    let scalar = Fr::from_limbs(scalar_base.get_limbs());
    let nf_point = complete_add(
        scalar_mul(crate::notes::nullifier_generator::generator(), scalar),
        cm,
    );
    let cmx = if cm.is_infinity() { Fq::zero() } else { cm.x };
    let nf = if nf_point.is_infinity() {
        Fq::zero()
    } else {
        nf_point.x
    };
    (cmx, nf)
}
// Link only: returns (cmx, nf) of this opening. No note existence is implied.
#[no_predicates]
pub fn derive_with_commitment(note: NoteOpening, authority: ViewingAuthority) -> (Fq, Fq) {
    // Arbitrary nk is insufficient: bind it to this note's receiver first.
    verify_viewing(note.receiver, authority);
    derive_for_bound_nk(note, authority.nk)
}

pub fn derive(note: NoteOpening, authority: ViewingAuthority) -> Fq {
    derive_with_commitment(note, authority).1
}
// Ownership and nullifier of ONE opening: the spending authority proves
// knowledge of ask for this receiver, and its nk derives the nullifier.
// Returns (cmx, nf). No note existence is implied.
#[no_predicates]
pub fn derive_owned(note: NoteOpening, authority: SpendAuthority) -> (Fq, Fq) {
    crate::notes::ownership::verify(note.receiver, authority);
    derive_for_bound_nk(note, authority.nk)
}
// Existence and nullifier of ONE opening: membership of its cmx under
// accepted_root plus the viewing-authority link. Returns (cmx, nf). The caller
// authenticates accepted_root (a header root at height h covers notes through
// h - 1). Unspent status still needs a complete absence scan of nf through
// the same checkpoint.
pub fn derive_member(
    note: NoteOpening,
    authority: ViewingAuthority,
    position: u32,
    siblings: [Fq; 32],
    accepted_root: Fq,
) -> (Fq, Fq) {
    let (cmx, nf) = derive_with_commitment(note, authority);
    crate::sinsemilla::canonical(accepted_root);
    let root = crate::sinsemilla::merkle_root(cmx, position, siblings);
    assert(root.get_limbs() == accepted_root.get_limbs(), "Ironwood note membership failed");
    (cmx, nf)
}
