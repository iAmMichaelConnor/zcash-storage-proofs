// Optional authority proofs. Contents-only entry points never call these.
use bignum::{BigNum, Pallas_Fq as Fq, Pallas_Fr as Fr};
use bigcurve::{BigCurve, Pallas};
use crate::sinsemilla::{canonical, field_bits, hash, domain_r, scalar_mul, complete_add};
use crate::notes::{ExpandedReceiver, encode_nonidentity};
// ask is the normalized SpendAuthorizingKey scalar. rivk is scope-adjusted;
// internal notes use rivk_internal, not the external FVK serialization value.
pub struct SpendAuthority {
    pub ask: Fr,
    pub nk: Fq,
    pub rivk: Fr,
}
// These full-viewing-key components are sensitive wallet data. They link a
// note's nullifier but do not prove knowledge of its spending scalar.
// rivk is scope-adjusted; serialized FVK/seed derivation is a separate claim.
pub struct ViewingAuthority {
    pub ak: Pallas,
    pub nk: Fq,
    pub rivk: Fr,
}
#[no_predicates]
pub fn verify_viewing(receiver: ExpandedReceiver, authority: ViewingAuthority) {
    let _gd = encode_nonidentity(receiver.g_d);
    let expected = encode_nonidentity(receiver.pk_d);
    let _ak = encode_nonidentity(authority.ak);
    assert((authority.ak.y.get_limbs()[0] & 1) == 0, "Noncanonical spend validating key sign");
    authority.rivk.validate_in_range();
    authority.rivk.validate_in_field();
    canonical(authority.nk);
    let ak_bits = field_bits(authority.ak.x);
    let nk_bits = field_bits(authority.nk);
    let mut message = [false; 510];
    for i in 0..255 {
        message[i] = ak_bits[i];
        message[255 + i] = nk_bits[i];
    }
    let unblinded = hash(2, message);
    assert(!unblinded.bottom, "Invalid incoming viewing key");
    let committed = complete_add(unblinded.point, scalar_mul(domain_r(1), authority.rivk));
    assert(!committed.is_infinity(), "Zero incoming viewing key");
    // Pallas base modulus is smaller than scalar modulus. Preserve integer ivk;
    // never cast the 255-bit value into one native Field.
    let ivk = Fr::from_limbs(committed.x.get_limbs());
    assert(ivk.get_limbs() != [0; 3]);
    let owned = scalar_mul(receiver.g_d, ivk);
    assert(encode_nonidentity(owned) == expected, "Note receiver does not match viewing authority");
}
#[no_predicates]
pub fn verify(receiver: ExpandedReceiver, authority: SpendAuthority) {
    authority.ask.validate_in_range();
    authority.ask.validate_in_field();
    assert(authority.ask.get_limbs() != [0; 3], "Zero spending authority");
    let ak = scalar_mul(crate::notes::spend_generator::generator(), authority.ask);
    verify_viewing(
        receiver,
        ViewingAuthority { ak, nk: authority.nk, rivk: authority.rivk },
    );
}
