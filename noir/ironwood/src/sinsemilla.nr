// Pinned Orchard Sinsemilla: K=10, at most 2530 message bits.
// Pallas Fq is 2^254 + 45560315531419706090280762371685220353.
// APIs use canonical field encodings. Bottom is distinct from curve infinity.
//
// The public entry points check their own inputs: checked_point, hash*,
// merkle_* and scalar_mul. The group-operation helpers below assume valid
// curve points and are crate-private; reach them only through those entry points.
//
// Most functions here are #[no_predicates]: a caller's runtime branch condition
// does not reach their constraints or Brillig hints. In
// `if c { merkle_combine(..) } else { .. }` the call is still enforced when c is
// false, so invalid inputs are rejected even on the branch not taken. Call these
// functions unconditionally with valid inputs (a valid dummy for an unused slot)
// and select the result afterwards. This rejects valid witnesses only; it never
// accepts an invalid one.
use bignum::{BigNum, Pallas_Fq as Fq};
use bigcurve::{BigCurve, Pallas};
use bignum::bignum::{evaluate_quadratic_expression_prechecked as eq, RangeChecked};
mod generators;
mod tests;

pub struct HashPoint {
    pub point: Pallas,
    pub bottom: bool,
}

pub fn canonical(x: Fq) {
    x.validate_in_range();
    x.validate_in_field();
}

// Checked public entrypoint. The internal addition preserves this invariant.
pub fn checked_point(p: Pallas) -> HashPoint {
    canonical(p.x);
    canonical(p.y);
    p.validate_on_curve();
    HashPoint { point: p, bottom: false }
}

pub fn domain_q(domain: u8) -> Pallas {
    generators::domain_q(domain)
}

#[no_predicates]
pub fn hash_to_point<let N: u32>(q: Pallas, message: [bool; N]) -> HashPoint {
    hash_inner::<N, 0>(q, message, [[[0u128; 3]; 5]; (N + 9) / 10])
}
pub fn hash_to_point_with_hints<let N: u32>(
    q: Pallas,
    message: [bool; N],
    hints: [[[u128; 3]; 5]; (N + 9) / 10],
) -> HashPoint {
    hash_inner::<N, 1>(q, message, hints)
}
#[no_predicates]
fn hash_inner<let N: u32, let SUPPLIED: u32>(
    q: Pallas,
    message: [bool; N],
    hints: [[[u128; 3]; 5]; (N + 9) / 10],
) -> HashPoint {
    assert(SUPPLIED <= 1);
    assert(N <= 2530);
    let mut acc = checked_point(q);
    for i in 0..(N + 9) / 10 {
        let mut index: Field = 0;
        for b in 0..10 {
            if i * 10 + b < N {
                index = index + (message[i * 10 + b] as Field) * ((1u32 << b) as Field);
            }
        }
        index.assert_max_bit_size::<10>();
        let s = HashPoint { point: generators::s(index as u16), bottom: false };
        acc = if SUPPLIED == 1 {
            check_fused_step(acc, s, hints[i].map(|v| Fq::from_limbs_unsafe(v)))
        } else {
            fused_step(acc, s)
        };
    }
    acc
}

pub fn extract_or_zero(p: HashPoint) -> Fq {
    if p.bottom | p.point.is_infinity() {
        Fq::zero()
    } else {
        p.point.x
    }
}
pub fn hash<let N: u32>(domain: u8, message: [bool; N]) -> HashPoint {
    hash_to_point(domain_q(domain), message)
}

pub fn field_bits(value: Fq) -> [bool; 255] {
    canonical(value);
    let limbs = value.get_limbs();
    let low = (limbs[0] as Field).to_le_bits::<120>();
    let middle = (limbs[1] as Field).to_le_bits::<120>();
    let high = (limbs[2] as Field).to_le_bits::<15>();
    let mut bits = [false; 255];
    for i in 0..120 {
        bits[i] = low[i];
        bits[120 + i] = middle[i];
    }
    for i in 0..15 {
        bits[240 + i] = high[i];
    }
    bits
}
#[no_predicates]
pub fn merkle_combine(level: u8, left: Fq, right: Fq) -> Fq {
    merkle_combine_inner::<0>(level, left, right, [[[0u128; 3]; 5]; 52])
}
pub fn merkle_combine_with_hints(
    level: u8,
    left: Fq,
    right: Fq,
    hints: [[[u128; 3]; 5]; 52],
) -> Fq {
    merkle_combine_inner::<1>(level, left, right, hints)
}
#[no_predicates]
fn merkle_combine_inner<let SUPPLIED: u32>(
    level: u8,
    left: Fq,
    right: Fq,
    hints: [[[u128; 3]; 5]; 52],
) -> Fq {
    assert(SUPPLIED <= 1);
    assert(level < 32);
    let l = field_bits(left);
    let r = field_bits(right);
    let mut message = [false; 520];
    let level_bits = (level as Field).to_le_bits::<5>();
    for i in 0..5 {
        message[i] = level_bits[i];
    }
    for i in 0..255 {
        message[10 + i] = l[i];
        message[265 + i] = r[i];
    }
    extract_or_zero(hash_inner::<520, SUPPLIED>(domain_q(0), message, hints))
}

// The position is checked against the chosen depth; depth32 accepts every u32.
#[no_predicates]
pub fn merkle_root<let DEPTH: u32>(leaf: Fq, position: u32, siblings: [Fq; DEPTH]) -> Fq {
    assert(DEPTH <= 32);
    (position as Field).assert_max_bit_size::<DEPTH>();
    canonical(leaf);
    let mut node = leaf;
    for level in 0..DEPTH {
        let right = ((position >> level) & 1) == 1;
        let left_node = if right { siblings[level] } else { node };
        let right_node = if right { node } else { siblings[level] };
        node = merkle_combine(level as u8, left_node, right_node);
    }
    node
}

// Complete Pallas addition for Sinsemilla commitment randomizers and scalar
// multiplication. Crate-private. Preconditions: valid curve points with
// canonical coordinates (checked_point, scalar_mul or Sinsemilla outputs).
// Identity, equal and opposite points are accepted. Pallas has odd prime order,
// so a finite valid point cannot have y=0; the doubling branch enforces y1 != 0,
// which removes the only free slope, (0,0)+(0,0). The largest signed quadratic
// product cost is 14: convolution <28*2^240+9*2^120 <2^245 and quotient <2^260.
// These bounds hold for this explicit 255-bit Pallas modulus; no BN254 shortcut.
#[no_predicates]
pub(crate) fn complete_add(p: Pallas, q: Pallas) -> Pallas {
    canonical(p.x);
    canonical(p.y);
    canonical(q.x);
    canonical(q.y);
    // Safety: complete_add_with_hint binds all three canonical hint values.
    let h = unsafe { complete_add_hint(p, q) };
    complete_add_with_hint(p, q, h)
}
#[no_predicates]
pub(crate) fn complete_add_with_hint(p: Pallas, q: Pallas, h: [Fq; 3]) -> Pallas {
    let px = RangeChecked::canonical(p.x);
    let py = RangeChecked::canonical(p.y);
    let qx = RangeChecked::canonical(q.x);
    let qy = RangeChecked::canonical(q.y);
    let hb = h.map(|v| RangeChecked::canonical(v));
    let l = hb[0];
    let same_x = p.x.get_limbs() == q.x.get_limbs();
    let same_y = p.y.get_limbs() == q.y.get_limbs();
    let active = !p.is_infinity() & !q.is_infinity() & (!same_x | same_y);
    let zero = RangeChecked::zero();
    let x1 = if active { px } else { zero };
    let y1 = if active { py } else { zero };
    let x2 = if active { qx } else { zero };
    let y2 = if active { qy } else { zero };
    let x3 = if active { hb[1] } else { zero };
    let y3 = if active { hb[2] } else { zero };
    // y1 is canonical, so its limb sum (<2^122, no wraparound) is zero exactly
    // when y1 = 0. The inverse exists only for y1 != 0.
    let doubling = active & same_x;
    let y_limbs = p.y.get_limbs();
    let y_sum = y_limbs[0] as Field + y_limbs[1] as Field + y_limbs[2] as Field;
    // Safety: the assertion below checks the inverse.
    let y_inverse = unsafe { inverse_or_zero(y_sum, doubling) };
    assert(y_sum * y_inverse == doubling as Field, "Doubling requires y != 0");
    let a = if same_x { y1 } else { x2 };
    let b = if same_x { y1 } else { zero };
    let c = if same_x { zero } else { x1 };
    let t = if same_x { x1 } else { RangeChecked::one() };
    let u = if same_x { x1 } else { y2 };
    let v = if same_x { x1 } else { zero };
    let z = if same_x { zero } else { y1 };
    eq(
        [[l], [t]],
        [[false], [false]],
        [[a, b, c], [u, v, v]],
        [[false, false, true], [true, true, true]],
        [z],
        [false],
    );
    let masked_l = if active { l } else { zero };
    eq(
        [[masked_l]],
        [[false]],
        [[masked_l]],
        [[false]],
        [x3, x1, x2],
        [true, true, true],
    );
    eq(
        [[masked_l]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );
    if p.is_infinity() {
        q
    } else if q.is_infinity() {
        p
    } else if same_x & !same_y {
        Pallas::point_at_infinity()
    } else {
        Pallas::from_coordinates_unsafe(h[1], h[2], false)
    }
}
unconstrained fn inverse_or_zero(value: Field, wanted: bool) -> Field {
    if wanted & (value != 0) {
        1 / value
    } else {
        0
    }
}
unconstrained fn complete_add_hint(p: Pallas, q: Pallas) -> [Fq; 3] {
    if p.is_infinity() | q.is_infinity() | ((p.x == q.x) & (p.y != q.y)) {
        [Fq::zero(); 3]
    } else {
        let l = if p.x == q.x {
            p.x * p.x * Fq::from(3) * (p.y + p.y).__invmod()
        } else {
            (q.y - p.y) * (q.x - p.x).__invmod()
        };
        let x = l * l - p.x - q.x;
        [l, x, l * (p.x - x) - p.y]
    }
}

// Commit domain 0 is NoteCommit, 1 is CommitIvk.
pub fn domain_r(domain: u8) -> Pallas {
    generators::domain_r(domain)
}

// Naive complete baseline. Scalars must have canonical Pallas_Fr encoding.
#[no_predicates]
pub fn scalar_mul(base: Pallas, scalar: bignum::Pallas_Fr) -> Pallas {
    let base = checked_point(base).point;
    scalar.validate_in_range();
    scalar.validate_in_field();
    let bytes = scalar.to_le_bytes();
    let mut acc = Pallas::point_at_infinity();
    for i in 0..255 {
        acc = complete_add(acc, acc);
        let bit = 254 - i;
        let candidate = complete_add(acc, base);
        acc = if ((bytes[bit / 8] >> (bit % 8) as u8) & 1) == 1 {
            candidate
        } else {
            acc
        };
    }
    acc
}

// Fused Sinsemilla step (P+S)+P. The two incomplete additions have separate
// active masks; neither failure condition is omitted. First compute xR from
// lambda1. Eliminate yR in the second slope using
// (lambda2+lambda1)*(xR-xP)+2*yP=0. The final y relation is based at P.
// Crate-private. Preconditions: p comes from checked_point or a previous step,
// s is a fixed generator; the steps never check that a point is on the curve.
#[no_predicates]
pub(crate) fn fused_step(p: HashPoint, s: HashPoint) -> HashPoint {
    canonical(p.point.x);
    canonical(p.point.y);
    canonical(s.point.x);
    canonical(s.point.y);
    // Safety: check_fused_step constrains all five canonical values and equations.
    let h = unsafe { fused_step_hint(p, s) };
    check_fused_step(p, s, h)
}
#[no_predicates]
pub(crate) fn check_fused_step(p: HashPoint, s: HashPoint, h: [Fq; 5]) -> HashPoint {
    let a = p.point;
    let b = s.point;
    let pax = RangeChecked::canonical(a.x);
    let pay = RangeChecked::canonical(a.y);
    let sbx = RangeChecked::canonical(b.x);
    let sby = RangeChecked::canonical(b.y);
    // Slopes enter only modular equations, never canonical limb comparisons.
    // Keep the full 255-bit limb ranges; coordinate canonicality remains required.
    let h0 = RangeChecked::new(h[0]);
    let h1 = RangeChecked::canonical(h[1]);
    let h2 = RangeChecked::new(h[2]);
    let h3 = RangeChecked::canonical(h[3]);
    let h4 = RangeChecked::canonical(h[4]);
    let first = !p.bottom
        & !s.bottom
        & !a.is_infinity()
        & !b.is_infinity()
        & (a.x.get_limbs() != b.x.get_limbs());
    let second = first & (h[1].get_limbs() != a.x.get_limbs());
    let z = RangeChecked::zero();
    let ax = if first { pax } else { z };
    let ay = if first { pay } else { z };
    let bx = if first { sbx } else { z };
    let by = if first { sby } else { z };
    let l1 = if first { h0 } else { z };
    let rx = if first { h1 } else { z };
    eq(
        [[l1]],
        [[false]],
        [[bx, ax]],
        [[false, true]],
        [by, ay],
        [true, false],
    );
    eq(
        [[l1]],
        [[false]],
        [[l1]],
        [[false]],
        [rx, ax, bx],
        [true, true, true],
    );
    let px = if second { pax } else { z };
    let py = if second { pay } else { z };
    let middle = if second { h1 } else { z };
    let slope1 = if second { h0 } else { z };
    let slope2 = if second { h2 } else { z };
    let x = if second { h3 } else { z };
    let y = if second { h4 } else { z };
    // Largest signed product cost=8: convolution<16*2^240+small<2^245,
    // quotient<8*2^256+small<2^260. All operands are RangeChecked values.
    eq(
        [[slope2, slope1]],
        [[false, false]],
        [[middle, px]],
        [[false, true]],
        [py, py],
        [false, false],
    );
    eq(
        [[slope2]],
        [[false]],
        [[slope2]],
        [[false]],
        [x, middle, px],
        [true, true, true],
    );
    eq(
        [[slope2]],
        [[false]],
        [[x, px]],
        [[false, true]],
        [y, py],
        [false, false],
    );
    HashPoint {
        point: if second {
            Pallas::from_coordinates_unsafe(x.value(), y.value(), false)
        } else {
            Pallas::point_at_infinity()
        },
        bottom: !second,
    }
}
unconstrained fn fused_step_hint(p: HashPoint, s: HashPoint) -> [Fq; 5] {
    let a = p.point;
    let b = s.point;
    if p.bottom | s.bottom | a.is_infinity() | b.is_infinity() | (a.x == b.x) {
        [Fq::zero(); 5]
    } else {
        let l1 = (b.y - a.y) * (b.x - a.x).__invmod();
        let rx = l1 * l1 - a.x - b.x;
        if rx == a.x {
            [l1, rx, Fq::zero(), Fq::zero(), Fq::zero()]
        } else {
            let l2 = Fq::zero() - l1 - (a.y + a.y) * (rx - a.x).__invmod();
            let x = l2 * l2 - rx - a.x;
            let y = l2 * (a.x - x) - a.y;
            [l1, rx, l2, x, y]
        }
    }
}
