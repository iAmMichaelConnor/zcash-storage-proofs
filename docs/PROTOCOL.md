# Ironwood note, ownership, and spend-state proofs

The opening circuits recompute a note commitment, its tree path and the relevant key relations directly. They need no Halo2 transfer proof. The claim definitions below state what each composition establishes and which application policy it requires.

The cryptographic reference is the project's pinned Orchard source, commit `616a669df8c9a59c33d47064d3ce04b25d026b2e`, with `NoteVersion::V3` and the Ironwood pool selected. The Noir and Aztec versions are those in the README's version-compatibility section and [`.aztecrc`](../.aztecrc). Header semantics follow the referenced ZIPs for the pinned protocol profile. The history serializer and transaction reader are read at librustzcash commit `8672a4b2d60f432664780e6a4e85f49a36805a2a` ([zcash_history](https://github.com/zcash/librustzcash/blob/8672a4b2d60f432664780e6a4e85f49a36805a2a/zcash_history/src/node_data.rs), [transaction reader](https://github.com/zcash/librustzcash/blob/8672a4b2d60f432664780e6a4e85f49a36805a2a/zcash_primitives/src/transaction/mod.rs)).

## What each claim means

| Claim | Necessary constrained relation | What it does not establish alone |
| --- | --- | --- |
| Note contents | Recompute the commitment from the private note opening | Tree inclusion or ownership |
| Note exists by block h | Opening plus membership in the final Ironwood tree at h, authenticated to an accepted chain commitment | The note was created in h, or remains unspent |
| Note created in block h | Open the output Action's cmx inside an authenticated transaction in block h | Ownership or later spend state |
| Viewing authority | `pk_d = [ivk] g_d`, with a nonzero private ivk | Ability to authorize a spend |
| Spending authority | Private ask, nk, rivk satisfy the spend-key and address relations below | That the note remains unspent |
| Spent by h | Derive this note's nf and authenticate an Ironwood Action containing nf at height <= h on the accepted chain | A transfer of ownership to the Aztec caller |
| Unspent at h | Existence of the same opening (membership under the checkpoint, or creation in an authenticated ancestor block), its nf with the same cmx, and complete absence of nf from Ironwood spends through h | Anything from a note-tree path alone; absence of a nullifier whose note is not shown to exist |

A public statement or application commitment must bind the network, pool, target height, accepted header hash/checkpoint, recipient/Aztec consumer, and application nonce or action. Note values and addresses may stay private, with only predicates exposed. A note can be spent on Zcash after a historical unspent proof; the application must choose freshness and replay rules.

The primary contents-and-membership API requires **no spending key and no viewing key**. A per-note rseed and opening are sufficient. Ownership and nullifier derivation are separate opt-in calls. This deliberately supports callers who receive an opening from the note sender or recipient without wallet-key disclosure. No new signing flow or PLUME support is required.

## Note commitment and V3 opening

All curve operations here are **Pallas**, unlike the Vesta points used by the Halo2 IPA verifier. Let q be the Pallas base-field modulus and r its scalar modulus. The note opening contains the expanded receiver `(g_d, pk_d)`, value v, rho, psi, and rcm. The points must be valid and nonidentity. v is an unsigned 64-bit integer; base/scalar encodings are canonical.

The commitment computation in [src/note/commitment.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/commitment.rs) is:

```
m = repr_P(g_d)[256 bits]
 || repr_P(pk_d)[256 bits]
 || I2LEBSP_64(v)
 || I2LEBSP_255(rho)
 || I2LEBSP_255(psi)
cm = SinsemillaCommit("z.cash:Orchard-NoteCommit", m, rcm)
cmx = Extract_P(cm)
```

The 1,086-bit message is padded with four zero bits to 109 ten-bit Sinsemilla chunks. Pallas compressed point encodings are 32 bytes: canonical x in little-endian with the y parity bit at bit255. These are **not** uncompressed coordinates. Identity extraction returns zero. The note commitment may have a valid identity result after the final blinding addition; do not reject it merely because this is unusual. A Sinsemilla bottom result is different and is rejected for note commitments.

For a full V3 seed opening, derive psi and rcm inside the circuit rather than trusting them as unrelated witnesses. [src/note.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note.rs) implements:

```
psi = LE_integer(BLAKE2b-512(
    personal = "Zcash_ExpandSeed",
    message = rseed[32] || 0x09 || rho_le[32])) mod q

rcm = LE_integer(BLAKE2b-512(
    personal = "Zcash_ExpandSeed",
    message = rseed[32] || 0x0b || repr_P(g_d)[32]
           || repr_P(pk_d)[32] || v_le[8] || rho_le[32] || psi_le[32])) mod r
```

This is ordinary personalized BLAKE2b with rseed prepended to the message, **not** the BLAKE2 keyed mode. The messages are 65 and 169 bytes, hence one and two BLAKE2b compression blocks. Both 512-bit outputs are reduced as little-endian integers into the proper Pasta field; the two moduli must not be swapped. V3 follows [ZIP 2005](https://zips.z.cash/zip-2005), with `0x0b` binding all the listed note components. Supplying independent psi and rcm is a lower-level commitment-opening API, not proof that the rseed derives a V3 plaintext.

The commitment does not include the memo. A memo-content claim requires an authenticated transaction ciphertext and the appropriate decryption relation. Similarly, the commitment binds g_d, not the raw 11-byte diversifier d. To claim a particular encoded receiver, additionally check `g_d = DiversifyHash(d)`. The pinned implementation uses `pallas::Point::hash_to_curve("z.cash:Orchard-gd")(d)`, substituting the hash of the empty byte string if the first result is identity; see [src/spec.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/spec.rs). A first library API may explicitly accept the expanded receiver without claiming that it opened an 11-byte diversifier.

## Sinsemilla and the note tree

The reference implementation is the locked `sinsemilla 0.2.0` crate, particularly `src/lib.rs` and `src/addition.rs`, plus [src/constants/sinsemilla.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/constants/sinsemilla.rs). It has 1,024 fixed Pallas message generators S[j]. Starting at a domain-specific Q, each ten-bit little-endian chunk j updates:

```
acc_next = (acc incomplete_add S[j]) incomplete_add acc
```

Incomplete addition returns bottom when either input is identity, either is already bottom, or the inputs have equal x coordinates (equal or opposite points). Bottom is sticky. A complete-curve implementation must **preserve that validity bit**; silently replacing these operations with unrestricted complete addition changes the hash. Domain constants can be generated once natively and checked into the circuit. The message S table is shared across domains. For commitments the message domain suffix is `-M`; the blinding base R is obtained with the `-r` hash-to-curve domain and an empty message. The final addition of `[rcm]R` is complete, not incomplete.

The Ironwood note commitment tree has exactly 32 levels. It reuses the Orchard hash while maintaining distinct pool state. The empty leaf is base-field element 2. At level l, counting from zero immediately above the leaves:

```
MerkleCRH(l, left, right) =
    SinsemillaHash("z.cash:Orchard-MerkleCRH",
        I2LEBSP_10(l) || I2LEBSP_255(left) || I2LEBSP_255(right))
```

There are 520 bits and 52 chunks per level. The u32 position's bit l chooses the ordering. See [src/tree.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/tree.rs), `merkle_crh_message`, `Hashable::combine`, and `MerklePath::root`. **The tree maps a bottom hash to field zero.** This differs from the note commitment's rejection rule and must remain accepted in a domain-preserving implementation. Real paths are unlikely to hit exceptional cases, but this is not a proof that such cases can be excluded. A reusable Sinsemilla function should return a point/result plus validity rather than hardwiring one consumer's policy.

The path must always be verified, including for value-zero notes. Copying the transaction Action circuit's dummy-spend bypass would permit false membership claims. Canonical leaf/sibling encodings, exact bit widths, all 32 position bits, and the supplied anchor must be constrained.

This costs 1,664 Sinsemilla rounds (3,328 incomplete additions) per path, before note opening and keys. Shared constant tables, batched quadratic constraints, and constrained native hints are the first implementation targets. Generics should share Pallas arithmetic and Sinsemilla chunk loops while using compile-time message lengths and domain constants. They should not erase the distinct bottom policies.

## Spending authority and nullifier binding

Knowledge of an incoming viewing scalar proves only viewing capability. Ownership is an opt-in API: when requested, its statement should prove spend authority. A witness of `(ask, nk, rivk)` is enough; proving a ZIP32 derivation from a seed is a different, stronger provenance claim. The relations in [src/keys.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs), [spec.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/spec.rs), and [circuit.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs) are:

```
ask in [1, r-1]
ak_P = [ask] SpendAuthG
repr_P(ak_P).bit255 = 0
ak = Extract_P(ak_P)
ivk = SinsemillaShortCommit("z.cash:Orchard-CommitIvk",
                           I2LEBSP_255(ak) || I2LEBSP_255(nk), rivk)
ivk is not bottom and ivk != 0
pk_d = [integer(ivk)] g_d
```

CommitIvk uses 510 bits and 51 chunks. Since q < r, converting canonical ivk from the base field to a scalar requires no modular reduction. Internal and external receiver scopes are both covered by witnessing the applicable rivk. Checking that rivk came from a particular wallet seed or external/internal derivation is optional provenance, not necessary to demonstrate ability to authorize a spend for the opened note. Proving ask knowledge is unsuitable for threshold holders who do not individually know the full scalar; a separately specified signature-authorization API can support that use case.

The nullifier MUST use the same nk, note fields, and full cm as the opening and ownership checks. In [src/note/nullifier.rs](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs):

```
t = (Poseidon_Pallas_P128Pow5T3_ConstantLength2(nk, rho) + psi) mod q
nf = Extract_P([integer(t)] K + cm)
K = PallasHashToCurve("z.cash:Orchard", "K")
```

This Poseidon uses the Orchard/Pasta constants, width3/rate2 and the two-element constant-length domain. It is neither Aztec's native Poseidon2 nor a Sinsemilla invocation. The addition is complete and zero extraction at identity is valid. No note position enters this nullifier formula. Do not accept a caller-supplied nf without the derivation relation, or use only cmx while forgetting which signed full commitment the opening produced.

## Binding an anchor to a block header

A block header does not contain a standalone Ironwood note root. [ZIP 244](https://zips.z.cash/zip-0244#block-header-changes) defines:

```
hashBlockCommitments = BLAKE2b-256("ZcashBlockCommit",
    hashChainHistoryRoot || hashAuthDataRoot || zero32)
```

The transaction Merkle root is a separate field. SHA256d of the exact serialized block header authenticates these fields to an accepted block hash. Checking that hash alone does not establish canonical-chain selection or sufficient work; an Aztec application must bind it to an accepted checkpoint/header policy.

The history MMR commits previous blocks of the consensus epoch, through height H-1 for a header at H. Its hash is BLAKE2b-256 personalized by `"ZcashHistory" || LE32(consensusBranchId)`. Nodes hash canonical serialization, and internal subtree commitments hash the **full serialized child metadata**, not merely the two child hashes. Peaks are bagged left-to-right. See [ZIP 221](https://zips.z.cash/zip-0221) and [zcash_history/src/version.rs](https://github.com/zcash/librustzcash/blob/8672a4b2d60f432664780e6a4e85f49a36805a2a/zcash_history/src/version.rs) at the pinned librustzcash commit.

[ZIP 258](https://zips.z.cash/zip-0258#changes-to-zip-221) adds the final Ironwood roots of the earliest and latest blocks in each node's range, and the number of Ironwood-bearing transactions. V3 nodes are 277–317 bytes. NU6.3 uses branch `0x37A5165B`; mainnet activation is 3428143 and testnet activation is 4134000. The activation/epoch boundary needs explicit handling: the activation header still summarizes the preceding epoch; the next header can summarize the new activation block. Later epoch transitions likewise change history interpretation. Supported header heights are therefore mainnet above 3,428,143 (open while mainnet NU7 is unscheduled) and testnet 4,134,001 to 4,465,026: testnet NU7 activates at 4,465,026, and later testnet headers commit to NU7 history under another personalization. `verify_latest` rejects testnet heights above 4,465,026, and testnet scans end at 4,465,025. NU7 support is a separate protocol update.

For a **latest-state** proof, a particularly cheap opening supplies the canonical V3 root-node serialization itself. Verify its digest under `hashBlockCommitments`; parse `end_height` and `end_ironwood_root`; assert `end_height = target_height = header_height-1`. Root metadata already commits the latest tree root, so this case needs no MMR path. For an older target in that epoch, verify a leaf or range-node path and the metadata aggregation rules. For a target in another epoch, use a suitable accepted historical header or a chain authentication proof, not an MMR path across a reset.

The V3 serializer in [`zcash_history/src/node_data.rs`](https://github.com/zcash/librustzcash/blob/8672a4b2d60f432664780e6a4e85f49a36805a2a/zcash_history/src/node_data.rs) writes:

```
subtree_commitment32
start_time_u32, end_time_u32, start_target_u32, end_target_u32
start_sapling_root32, end_sapling_root32, subtree_work_u256
CompactSize(start_height), CompactSize(end_height), CompactSize(sapling_tx)
start_orchard_root32, end_orchard_root32, CompactSize(orchard_tx)
start_ironwood_root32, end_ironwood_root32, CompactSize(ironwood_tx)
```

Fixed integers use little-endian. The branch ID is not serialized inside the node; it selects the personalization. Reject noncanonical CompactSize aliases and trailing junk; the variable-width integers mean there is no universal fixed offset for the Ironwood roots. Header bytes, displayed block hashes, and field encodings must use explicit internal-byte-order conventions. A final tree root proves cumulative membership **by** the target height, not creation **in** that block.

## Spent and unspent statements

Ironwood has a separate nullifier set, but the existing header/history formats above contain no authenticated nullifier-set root. This follows from the complete commitment layouts, not from the absence of a conveniently named API. Zebra persists nullifiers as a database map; that map's root is not a consensus field. [The Zebra database description](https://zebra.zfnd.org/dev/state-db-upgrades.html) distinguishes that map from the note tree and history tree.

A **spent** proof can authenticate a matching nf in an Ironwood Action, using the transaction's v6 digest and its transaction Merkle path under a trusted block header. Derive nf from the private note and owner key first. Match the Ironwood component, not the Orchard component. Bind the spend height and accepted chain; header bytes alone have no height field, so height needs an authenticated chain/history/coinbase relation or a trusted `(hash,height)` checkpoint.

The v6 txid commits the Ironwood Actions using pool-specific personalized BLAKE2b digests. Its compact Actions digest is a hash of a **concatenation**, not an Action Merkle tree: authenticating one nf generally requires the whole compact-data sequence for that transaction. Other digest children may be supplied as hashes. Anchors moved to authorizing data in v6, so a txid inclusion proof alone does not authenticate a supplied anchor. These distinctions follow [ZIP 229](https://zips.z.cash/zip-0229).

A **not-spent** proof cannot use a nonexistent native nullifier-tree path. Sound implementations can instead prove complete scanning from Ironwood activation (or from a separately authenticated complete accumulator checkpoint) to h, or maintain a derived accumulator whose updates are themselves proved to include every nullifier in each authenticated block. A bare server-generated sparse-tree root or a list of selected transactions is insufficient.

For a complete scan, bind every block and all transaction effect data, reconstruct each full transaction Merkle root, parse every Ironwood component, and constrain all its nullifiers unequal to the target. Include all supported transaction versions that can carry Ironwood at the chosen protocol pin. A generalized deployment must handle future versions explicitly. Checking only "some transactions at every height" is not completeness. Bitcoin-style duplicate-last Merkle trees also make the transaction count subtle: use canonical block parsing/count rules and authenticated coverage rather than assuming an arbitrary list of Merkle paths proves enumeration. A recursive scan or proved accumulator can amortize work, but that is an additional proof system and state pipeline, not a different opening of the current Zcash header.

The library can expose an exact bounded-range scan primitive with its range in the public statement. It may claim global unspent-at-h only when that range starts at activation, or when its initial complete nullifier state is authenticated. It can also support an explicitly named attested-state adapter if an application chooses an external trust assumption; that is not the default cryptographic claim.

## Correctness boundaries for optimization

The primitive layer should distinguish canonical field inputs, curve points, valid Sinsemilla results, and authenticated anchors. Native hints and capsules are untrusted witnesses. The consumer must constrain their coordinates, boolean/infinity flags, arithmetic equations, transcript-independent scheduling, and exact count.

Test positive exceptional cases as well as rejection: complete addition with equal/opposite/identity inputs, commitment identity after blinding, Sinsemilla bottom propagation, Merkle bottom-to-zero, zero-value membership, canonical values at q/r boundaries, private position endpoints, and CompactSize transitions 252/253, 65535/65536, and 2^32-1/2^32. Malicious seed-derived psi/rcm, owner keys, supplied nf, siblings, domain constants, network/epoch IDs, target heights, and mismatched public note predicates must reject. Whole-path fixtures should be checked against the pinned native Orchard implementation before circuit cost comparisons.

Use the existing BigNum batched quadratic evaluation where its operand bounds are proved for **Pallas**. A Vesta or BN254 range argument does not automatically transfer. Preserve a measured naive snapshot and compare identical accepted inputs and composed statements when optimizing. Passing the native generator or a successful honest witness is not sufficient evidence that externally supplied hints are constrained.

## Authority and nullifier relations

The expanded authority interfaces intentionally prove a receiver relation, not derivation of a wallet seed or validity of every field in a serialized wallet key. `ironwood::notes::ownership::verify_viewing` uses canonical nonidentity `ak`, with even affine y so its encoding is exactly the x-coordinate used by upstream `SpendValidatingKey::to_bytes`. It computes `CommitIvk(ak_x,nk;rivk)`, rejects Sinsemilla bottom and zero extracted ivk, injects the Pallas-base integer into the larger scalar field, and checks `pk_d=[ivk]g_d`. This matches Orchard's `src/keys.rs:656` and `src/spec.rs:250` at the pinned commit. The arithmetic keeps the full 255-bit integer in three BigNum limbs rather than reducing it into Noir's native field.

`rivk` is **scope-adjusted randomness**. An internal/change receiver requires the internally derived value from `FullViewingKey::rivk(Scope::Internal)` (`keys.rs:424-434`), which hashes the external rivk with ak and nk through `ORCHARD_RIVK_INTERNAL`. The circuit accepts that expanded value directly; it does not derive it or prove its relationship to an external FVK. Both choices of scope remain supported by supplying their appropriate expanded components. Likewise, the spending variant accepts the normalized `SpendAuthorizingKey` scalar: upstream negates the raw spending-key-derived scalar when necessary to make ak's sign bit zero (`keys.rs:200-216`). It is not a raw 32-byte wallet spending key API.

The stronger spending variant proves knowledge of that nonzero scalar through `ak=[ask]SpendAuthG`; the viewing variant never claims knowledge of ask. Checking the receiver relation is necessary before using nk in a note-nullifier proof; an unrelated caller-chosen nk would produce a meaningless different nullifier. `nullifier::derive_with_commitment` does this binding before calculating the opened commitment and `extract_P([mod_r_p(Poseidon(nk,rho)+psi)]K+cm)`. The addition is modulo the Pallas base field, the scalar conversion is an integer injection because the base modulus is smaller, and point infinity extracts to zero as in `note/nullifier.rs:81`.

The implementation does not validate a second unused receiver scope as upstream serialized-FVK parsing does. Its claim is possession of expanded components satisfying the particular note's receiver, so this does not weaken that relation; consumers must not relabel it as a proof of canonical wallet-seed/FVK serialization. Similarly, the expanded receiver commits g_d and pk_d but does not prove a raw 11-byte diversifier hashes to g_d. The contents-only path stays independent of all authority routines and consumes neither a viewing key nor a spending key.

## Full V4 bodies and Merkle leaf/internal separation

NU6.3 permits legacy V4 transactions, which have no Ironwood component. Their transaction ID is SHA256d of the complete raw serialization, so an opaque txid alone cannot establish their version. The optional `ironwood::transactions::legacy` path hashes every supplied raw byte, checks the exact V4/Overwintered prefix and version-group ID `0x892f2085`, and rejects nonzero unused buffer tails. It relies on the same application premise as the other openings: the accepted checkpoint belongs to a valid Zcash chain; it does not revalidate the transaction's signatures or every serialization rule.

Raw SHA256d leaves introduce a potential ambiguity with the 64-byte concatenations hashed for internal transaction-Merkle nodes. The V4 path explicitly excludes that overlap without losing any valid V4 transaction: the fixed fields and minimum CompactSize counts total 29 bytes; consensus requires at least one transparent input, Sapling spend or JoinSplit. A transparent input contributes at least 41 bytes (36-byte outpoint, one-byte script length, four-byte sequence), a Sapling spend at least 384 bytes, and a JoinSplit at least 1,698 bytes. Therefore every valid V4 body has length at least 70 bytes. Requiring `70 <= length <= RAW` preserves all valid inputs within the configured capacity and prevents reinterpreting an internal-node preimage as a complete V4 body. See [protocol §7.1](https://zips.z.cash/protocol/protocol.pdf#txnencoding), especially the V4 encoding table and nonempty input rule, and the [transaction reader](https://github.com/zcash/librustzcash/blob/8672a4b2d60f432664780e6a4e85f49a36805a2a/zcash_primitives/src/transaction/mod.rs) at the pinned commit.

Raw V4 bodies are bounded by the compile-time `RAW` capacity; larger V4 transactions require a larger instantiation. This is a stated resource bound, not a claim that all Sapling/Sprout V4 transactions fit. V5/V6 retain their separate personalized BLAKE2b leaf domains, and every active leaf in the complete block remains opened and duplicate checked.
