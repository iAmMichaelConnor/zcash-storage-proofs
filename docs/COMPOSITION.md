# Security and composition requirements

The [claims and Noir API](API.md) define each relation's accepted input
and statement. Applications authenticate the checkpoint hash, network and relevant
height. These circuits authenticate openings against that policy; they do not
establish chain consensus or finality.

## Bind one application claim

Creation binds an opened note to an included output. Receiver decryptability,
spendability, block height and checkpoint ancestry are separate obligations.
For recipient and memo binding use `ironwood::memo` or `ironwood_aztec::memo`.
The memo adapter returns memo, transaction ID, commitment, value and raw receiver
from one witness load: use those returned values instead of reloading capsules.

Compose membership, ownership, linked nullifier and absence using the same note
commitment and appropriate checkpoint. An unspent claim requires existence and
the corresponding nullifier's complete absence. Membership-free nullifier
derivation cannot establish existence. Scan initialization binds the activation
predecessor and checks canonical nullifiers. Continuation requires an
authenticated prior state; padding is not additional authenticated history.
Honest private-state lookup alone does not establish freshness against an
adversarial witness.

Authenticate deployed adapter addresses or classes. One-time application effects
need an application nullifier bound to the note commitment or nullifier, rather
than to an adapter address or claim index. Deliver authority material only within
the intended transaction.

## Input preparation and capacity

Witness preparation outside the circuit is never trusted: every capsule value
is range checked and every relation is constrained, so a prepared input can
only be rejected, not accepted wrongly. [Capsule slots](API.md#capsule-slots)
defines slots and claim indices. Native hints are untrusted witnesses
constrained by the same arithmetic checks.

Capacities (Action counts, transactions, paths and history windows) are generic
parameters fixed by the consumer at compile time; inputs that exceed them are
rejected, never truncated. Re-measure a circuit after changing any capacity or
dependency. Tests execute constraints; executing them is not proof verification
or an Aztec network transaction.

## Arithmetic call contracts

- **Checked entry points.** The public `ironwood::sinsemilla` functions check
  their own inputs: `checked_point` (canonical and on the curve), `hash*`,
  `merkle_*` and `scalar_mul`. The group-operation helpers (`complete_add`,
  `complete_add_with_hint`, `fused_step`, `check_fused_step`) assume valid curve
  points and are crate-private. Complete addition also rejects doubling a point
  with `y = 0`; no valid Pallas point has one.
- **Runtime branches.** Most Sinsemilla, Merkle, note-opening and capsule
  functions are `#[no_predicates]`. A caller's runtime branch condition does not
  reach their constraints, Brillig hints or capsule loads. In
  `if c { f(x) } else { ... }` the call `f(x)` is still enforced when `c` is
  false, so an invalid `x` rejects the witness. The same holds for the functions
  that call them, for example `commitment_x`, `root_from_opening` and
  `verify_contents_membership`. Call these functions unconditionally, give an
  unused slot a valid dummy input (for example a zero leaf or a pinned
  generator), and select the result afterwards. This rule never makes an
  invalid witness pass.
- **Prechecked quadratic relations.** `patches/bignum-prechecked.patch` is a
  local addition to the vendored BigNum; it is not part of upstream noir-bignum.
  It adds `evaluate_quadratic_expression_prechecked`, which is the checked
  BigNum relation without its input range checks: the quotient, carry and
  relation checks are the same code. Its terms have the type `RangeChecked<T>`,
  whose field is private: `RangeChecked::new` and `RangeChecked::canonical`
  constrain the value, `zero` and `one` are constants, and a Boolean selection
  keeps the bound. A value returned by an unconstrained function or oracle, or
  passed as a circuit or contract parameter, is not checked; never use
  `RangeChecked` there.
- **Vendored arithmetic.** `vendor/` holds BigNum and BigCurve at pinned
  commits of the noir-lang repositories, BigNum with the one local patch
  above; `scripts/vendor.sh --check` rebuilds them from upstream and compares
  every file. At these commits BigNum `cmp` (`<`, `>`, `<=`, `>=`) decides
  `Equal` from the range-checked difference, so two limb encodings of one
  integer compare `Equal`. BigCurve's CurveJ `Eq` is constrained, and affine
  `+` and `-` return the finite operand when the other input is at infinity,
  also when the raw x coordinates are equal (otherwise `O + Q` with `Q.x = 0`
  would be the off-curve point (0, 0); Pallas and Vesta have no point with
  x = 0, but a non-canonical infinity input could select the same branch).
  BigNum `==` and `assert_is_not_equal` are exact modular comparisons for
  operands below `2^(MOD_BITS + 1)`: the prover supplies the residue of the
  difference and a quotient, and the circuit checks the integer identity, so
  distinct values that alias in the native field are distinct and wider
  operands are rejected. BigCurve's incomplete add/subtract distinct-x guard
  uses that `assert_is_not_equal`. `is_zero` remains a separate helper that
  recognizes only the zero limb vector and `MOD`. Its input contract excludes
  other zero representatives: checked `MOD_BITS`-bounded inputs with a
  normalized modulus, or canonical values plus one modulus, are below
  `2*MOD`. Reduce wider raw runtime values before using `is_zero`.
- **Division.** BigNum `/` constrains `quotient * denominator = numerator`
  modulo the field modulus and calls `assert_is_not_zero`, which uses the exact
  modular inequality check above. In Pallas it accepts the nonzero canonical
  denominators `r`, `p - r` and `2r - p`, where `r` is the native BN254 scalar
  modulus and `p` is the Pallas base modulus. Division requires an invertible
  denominator; use canonical inputs for its inversion hint. The wider comparison
  bounds do not extend the inversion hint's contract. The diversifier retains
  its separate exact `divide` in `ironwood/src/memo/diversifier.nr`: it checks
  a canonical denominator's limbs for zero and constrains the quotient relation.

## Pasta representations and exceptional cases

Pallas/Vesta values use 120/120/15-bit limbs. A 255-bit Pasta value must not be
packed into one smaller native Noir field. Where bounded aliases are admitted,
modular comparison must distinguish differences zero, plus the modulus and
minus the modulus under the actual limb bounds. Canonical external encodings
remain canonical; integer ordering and modular equality are different operations.

Complete arithmetic must preserve equal/opposite points, infinity, zero scalars
and equivalent admitted residues. Reduce alias operands before canonical-only
hint subtraction. Check honest hint execution separately from acceptance of
independently supplied witnesses. No BN254-specific carry bound transfers to
Pasta without substituting the actual moduli, widths and expression shape.

Canonical scalar decomposition uses 120/120/15 Boolean bits, with bit 255 zero.
Weighted sums replace integer OR only for disjoint bits with a proven bound
before conversion. Do not silently truncate a scalar's high bit. Generic BigNum
division's packed nonzero test is unsuitable for every Pasta denominator; the
memo diversifier's exact canonical-limb division pattern retains valid native-
field aliases. The Division bullet above states this boundary.

## Hashing and note commitments

`hash_variable_last_block<N,OUT>` requires a length strictly after the start of
its final block and at most N, with all unused bytes zero. Ironwood history
metadata is 277–317 bytes and uses three BLAKE2b blocks; hash the true length,
not its padded capacity. This is not general streaming hashing.

`hash_bounded<N,OUT>` accepts 0..=N including empty input and exact 128-byte
endpoints, requires a zero tail, and finalizes the actual last active block.
BLAKE2b digest length belongs in initialization; a 256-bit digest is not a
truncated 512-bit digest. Selecting left/right Merkle inputs before one hash
preserves ordering; hashing only the selected digest would not.

`reduce512<T>` is restricted to the two actual 255-bit Pasta moduli. It splits
512 bits into 240/240/32-bit chunks and binds a canonical result through its
quadratic relation. Nullifier P128Pow5T3 Poseidon is distinct from Aztec Poseidon2:
preserve ConstantLength<2>, 8 full/56 partial rounds, constants and canonical inputs.

Shared Sinsemilla/note-opening checks retain personalized PRFs, complete
randomizer addition, canonical coordinates and both incomplete-add failure
branches. Slopes used only in modular equations may remain bounded aliases.
Native hints never replace these relations or BigNum's carry/quotient checks.

## Capsule witnesses

Capsules are untrusted witnesses, not private ABI authorization. The transport
layer owns addresses/slots; arithmetic owns equations and bounds. Consume every
required record exactly once and check lengths, widths and complete consumption.
A native oracle matching an upstream result is not a constrained rejection test.

## Backend and compiler premises

BLAKE2b (`noir/ironwood/src/hashes/blake2b.nr`) range checks each hinted 64-bit
word (`rotr` output, `add` sum) to 64 bits. Where that word feeds a 64-bit XOR,
the compiler's range optimiser deletes the explicit check, because it treats
both operands and the output of an XOR or AND as already bounded to the
operation width. Soundness then rests on the backend: bb constrains each XOR
operand to its width by 32-bit table chunks and a reconstruction assertion.
The explicit checks stay in the source so that a word not consumed by an XOR
is still bounded. In Noir 1.0.0 the range optimiser records both operands and
the output of an XOR or AND as bounded (`redundant_range.rs`); bb 6.0.0 splits
each operand into 32-bit chunks read through the `UINT32_XOR` or `UINT32_AND`
table, range checks a shorter last chunk and asserts that the chunks reconstruct
the operand (`stdlib/primitives/logic/logic.cpp`). Re-check this premise for any
other backend.
