// Capsule transport policy only; all arithmetic lives in the shared pure core.
// The constrained functions below are #[no_predicates]: a caller's runtime branch
// condition does not stop their capsule loads or constraints. Call them unconditionally with
// valid inputs (a valid dummy for an unused slot) and select the result afterwards.
use bignum::{BigNum, Pallas_Fq as Fq};
use aztec::protocol::address::AztecAddress;
// Record order is lambda1,xR,lambda2,xFinal,yFinal; each has120/120/15-bit limbs.
pub unconstrained fn load<let N: u32>(address: AztecAddress, slot: Field) -> [[[u128; 3]; 5]; N] {
    aztec::oracle::capsules::load(address, slot, AztecAddress::zero()).expect(
        f"Missing Sinsemilla hint capsule",
    )
}
// Sinsemilla hash in a pinned domain (see ironwood::sinsemilla::domain_q).
#[no_predicates]
pub fn hash_from_capsule<let N: u32>(
    address: AztecAddress,
    slot: Field,
    domain: u8,
    message: [bool; N],
) -> ironwood::sinsemilla::HashPoint {
    // Safety: the shared checked step constrains every supplied hint and relation.
    let hints = unsafe { load::<(N + 9) / 10>(address, slot) };
    ironwood::sinsemilla::hash_to_point_with_hints(
        ironwood::sinsemilla::domain_q(domain),
        message,
        hints,
    )
}
#[no_predicates]
pub fn merkle_combine_from_capsule(
    address: AztecAddress,
    slot: Field,
    level: u8,
    left: Fq,
    right: Fq,
) -> Fq {
    left.validate_in_range();
    right.validate_in_range();
    assert(level < 32);
    // Safety: the shared checked step constrains every supplied hint and relation.
    let hints = unsafe { load::<52>(address, slot) };
    ironwood::sinsemilla::merkle_combine_with_hints(level, left, right, hints)
}
#[no_predicates]
pub fn merkle_root_from_capsules<let DEPTH: u32>(
    address: AztecAddress,
    slot_base: Field,
    leaf: Fq,
    position: u32,
    siblings: [Fq; DEPTH],
) -> Fq {
    assert(DEPTH <= 32);
    (position as Field).assert_max_bit_size::<DEPTH>();
    ironwood::sinsemilla::canonical(leaf);
    for i in 0..DEPTH {
        siblings[i].validate_in_range();
    }
    let mut node = leaf;
    for level in 0..DEPTH {
        let right = ((position >> level) & 1) == 1;
        let left_node = if right { siblings[level] } else { node };
        let right_node = if right { node } else { siblings[level] };
        node = merkle_combine_from_capsule(
            address,
            slot_base + level as Field,
            level as u8,
            left_node,
            right_node,
        );
    }
    node
}
