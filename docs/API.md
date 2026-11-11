# Claims and Noir API

The circuits **open Zcash chain data** for the pinned Ironwood V3 / transaction V6
/ NU6.3 profile: note openings, header/history checkpoints, transaction effects,
memos, authority, nullifiers and complete scans. No circuit here verifies an
Ironwood bundle (Halo2) proof, signatures or consensus. The protocol details
behind each relation are in [PROTOCOL.md](PROTOCOL.md); arithmetic and composition
contracts in [COMPOSITION.md](COMPOSITION.md); capsule layouts in
[Capsule slots](#capsule-slots) below.

`ironwood` is the pure Noir package (no Aztec dependency; headline verifiers and
input types are re-exported at the crate root). `ironwood_aztec` loads capsule
witnesses and calls the same checks. Byte strings use internal digest order, not
reversed display hex.

## Claims and evidence

Every claim has positive tests on reference vectors (Orchard's Rust implementation
or independent Python models; see [CONTRIBUTING.md](../CONTRIBUTING.md#generated-files))
and a negative test for each named check. Tests execute the constraints; no test
creates a proof, and the checkpoint fixtures are synthetic.

| Claim | Statement | Tests |
| --- | --- | --- |
| Note under an accepted note-tree root | Opening, position and 32 siblings; the recomputed commitment is in the root and binds value, expanded receiver and rho | `ironwood_slow_tests` `nullifier_tests`, `ironwood_notes_tests` |
| Note under an accepted header/history checkpoint | The same plus the header/history opening; a header at height h authenticates membership through h-1 | `ironwood` `headers`, `ironwood_aztec`, `examples/note_value` (TXE) |
| Output created in an exact block | Opening plus selected Action and block path; cmx and rho match the selected output, in a transaction of 1 to N Actions in the block whose SHA256d is the supplied hash | `ironwood_creation_tests` |
| Selected Action effects occurred | Transaction digest data, selected Action and block path, same block statement | `ironwood` `transactions`, `ironwood_transactions_tests` |
| Spending authority for an included note | Opening/membership plus normalized authority; secret scalar and full receiver relation match; the adapter also returns the nullifier | `ironwood_notes_tests`, `ironwood_slow_tests` `nullifier_tests` |
| Included note linked to its nullifier | Opening/membership plus viewing components; receiver relation and nullifier match | the same |
| Supplied nullifier occurred | The nullifier is in a selected Action of a transaction in the block whose SHA256d is the supplied hash. Linking it to a note is a separate composition | `ironwood` `transactions::inclusion_tests` |
| Nullifier absent over complete history | Every supported transaction of every block from activation to an accepted tip; no Ironwood Action contains the canonical nullifier | `ironwood` `transactions::nullifier_absence`, `ironwood_transactions_tests`, `examples/nullifier_absence_state` (TXE) |
| Memo and raw recipient of a note created in a block | Raw receiver, rseed-derived key, full ChaCha20-Poly1305 ciphertext and tag, all ordered Action digest preimages, note commitment, block inclusion. **The deposit claim** | `ironwood` `memo` |
| Header/history metadata | The encoded metadata and roots match the checked commitments under an accepted checkpoint | `ironwood` `headers` |

Block-hash claims (created, Action, nullifier inclusion) do not bind the block's
height, network or ancestry.

## Notes

`ironwood::notes` implements the V3 note commitment; `sinsemilla`, `hashes` and
`poseidon` are the shared arithmetic modules.

| Need | Pure API | Aztec adapter |
| --- | --- | --- |
| Contents and membership in a known root | `notes::verify_contents_membership` (exactly 32 siblings) | |
| Contents and membership under a header checkpoint | | `ironwood_aztec::verify_contents` (capsules 60, 61) |
| Same, with native Sinsemilla hints | | `ironwood_aztec::verify_contents_capsules` (adds 70 to 102) |
| Spending authority, membership and nullifier of one opening | `notes::nullifier::derive_owned` with membership; `verify_owned_membership` | `ironwood_aztec::verify_owned` (adds 65) |
| Existence and nullifier of one opening | `notes::nullifier::derive_member` | `ironwood_aztec::verify_nullifier` (adds 64) |
| Nullifier link only, no existence | `notes::nullifier::derive_with_commitment` | |

```rust
use ironwood::notes::{NoteOpening, verify_contents_membership};
// accepted_root comes from application policy; note holds per-note randomness, no wallet key.
verify_contents_membership(note, position, siblings, accepted_root);
```

The key-free opening is the expanded receiver `(g_d, pk_d)`, value, rho and
per-note rseed; it holds no spending or viewing key, and knowing it is not
spending authority (the sender and holders of an incoming viewing key know it
too). The result binds the commitment, value, expanded receiver, rho and the
snapshot height h-1 (not a scan tip height). Membership proves existence by h-1,
not creation in a block. The commitment does not bind the memo; a raw
address/diversifier claim needs the memo route.

Native hints change witness generation, not the claim: every hint record passes
the same range and quadratic checks, including both incomplete-add failure
branches. Slot 102 holds 109 note-hash records and slots 70 to 101 hold 52 records
per Merkle level; each record is `lambda1, xR, lambda2, xFinal, yFinal` in
120/120/15-bit limbs (26,595 extra fields).

**Authority.** `ownership::verify` proves knowledge of a nonzero spending scalar
and the complete receiver relation; `ownership::verify_viewing` proves only the
receiver relation to full viewing components. `derive_with_commitment` binds nk
through that viewing relation before deriving the nullifier (a caller-supplied nk
would not establish the link), but proves no existence: the nullifier of an
invented opening never occurs on chain. `derive_owned` derives the nullifier from
the same opening and nk as the authority check; `derive_member` adds membership.
Inputs are the already normalized SpendAuthorizingKey scalar and the scope-adjusted
CommitIvk randomness: internal change notes need `rivk_internal`. Derivation from
a seed or serialized FVK is not claimed. Authority capsules 64 and 65 are secret:
deliver them only as transient capsules of one transaction, and note that the
claims do not bind `msg_sender` ([capsule slots](#capsule-slots)).
A linked nullifier is not itself a spent or unspent proof.

## Headers and history

```text
verify_header_latest(header: [u8; 1487], expected_hash: [u8; 32], header_height: u32,
    is_testnet: bool, node: [u8; 317], auth_root: [u8; 32]) -> LatestSnapshot { root, height }
```

The standard header at h+1 authenticates the **final note-tree root at height h**:
the function parses the V3 history-root metadata, hashes it with the consensus
personalization, opens `hashBlockCommitments` and checks SHA256d of the header.
Compose the root with `ironwood::sinsemilla::merkle_root::<32>` and a note opening.
The header is a 140-byte prefix, canonical `fd4005` (solution length 1344) and the
Equihash solution; mainnet and testnet formats only, no regtest. `verify_latest`
takes an already authenticated `hashBlockCommitments` and height of the same block.
`parse_v3` checks canonical CompactSize encodings, ordered heights, the exact
endpoint and zero padding to 317 bytes; only the parsed length (277 to 317 bytes,
three BLAKE2b blocks) is hashed.

The history root must start at the network's NU6.3 activation, the header must be
later than the activation block, and its preceding height must equal the
metadata's last height. Supported header heights: mainnet above 3,428,143;
testnet 4,134,001 to 4,465,026. Testnet NU7 activates at 4,465,026: that header
still opens NU6.3 history and later ones reject ("Testnet header is in the
unsupported NU7 epoch"). Older targets in the epoch would need a general MMR
proof, which is not offered. The function proves no membership, contents,
ownership, absence, proof of work or chain selection.

## Transaction effects and creation

`transactions::effects::verify_action` authenticates a selected Ironwood Action's
compact effect bytes in a V6 transaction (ZIP 229/244 digests, branch
`0x37a5165b`, personalized BLAKE2b-256 txids, SHA256d transaction tree and
header). It returns `ActionEffect { nullifier, cmx, ephemeral_key,
encrypted_note_prefix }` and the txid; `verify_output` also binds an expected cmx.
`verify_nullifier_inclusion` selects an Action's nullifier. These are occurrence
claims: neither ownership nor memo plaintext is implied, and a genuine block
transaction proves the nullifier appeared by that block.

`Inclusion<N,DEPTH>` holds `effects: V6Effects<N>`, `header: [u8; 1487]`,
`siblings: [[u8; 32]; DEPTH]`, `action_index`, `tx_index`, `tx_count` and
`action_count`. **N is the Action capacity; the transaction has exactly
`action_count` Actions, 1 to N**, in the first slots with zero slots after. The
compact digest hashes exactly `148 * action_count` bytes, so the txid fixes the
count and every Action, and one transaction has one encoding;
`action_index < action_count` is constrained. Compact Actions are
`nf || cmx || ephemeral_key || encrypted_note_prefix52`. Unused siblings must be
zero and odd terminal nodes duplicate as upstream. `tx_count` is a path-shape
witness, not an authenticated block count: inclusion proves occurrence, not a
unique position or complete coverage. Memo, noncompact and other-pool digests stay
opaque children bound by the txid; a V6 anchor cannot be recovered from it.

`creation::verify_created_in_block` composes the key-free opening with selected
output inclusion and checks `NoteCommit(note).x == action.cmx` (with the upstream
identity-to-zero extraction) and canonical `note.rho == action.nullifier`, the
output-construction rule of [`src/builder.rs`](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs) (`Rho::from_nf_old`)
in the `orchard` 0.16.0 crate pinned at git rev `616a669df8c9a59c33d47064d3ce04b25d026b2e`
(`reference/notes/Cargo.toml`).

```rust
use ironwood::{notes::NoteOpening, transactions::effects::Inclusion};
fn check<let N: u32, let DEPTH: u32>(note: NoteOpening, witness: Inclusion<N, DEPTH>, accepted_block_hash: [u8; 32]) {
    let (action, txid) = ironwood::creation::verify_created_in_block(note, witness, accepted_block_hash);
    // Bind action.cmx, txid and predicates to the application's request.
}
```

**Not a deposit claim.** Creation proves "an output with this opening was
committed in the block whose SHA256d is this hash", not that the receiver can
decrypt or spend it. The ephemeral key and ciphertext are opaque txid inputs,
consensus does not check that a non-coinbase output decrypts, and the Ironwood
builder pairs each spend with a zero-value output whose ciphertext is random on
purpose. A sender can pay the right receiver with garbage ciphertext and keep
`rseed`. Deposits use the [memo](#memo) route. Zero-value outputs are in the
accepted domain; apply your own amount predicate.

The Aztec adapter `ironwood_aztec::creation` exports `inclusion<N,DEPTH>`,
`verify_action<N,DEPTH>`, returning `(action, txid)`, and `verify_created<N,DEPTH>`,
returning `(cmx, txid, value, expanded_receiver_limbs, rho_limbs)`; they read
capsules 68 and 69.

## Memo

`ironwood::memo::verify_memo_created_in_block` (adapter `ironwood_aztec::memo::verify<N, DEPTH>(address, claim, accepted_header_hash)`)
proves the chain:

1. The raw recipient's diversifier maps to the note's `g_d` (pinned XMD/SWU/isogeny
   map, identity mapped to hash(empty)); its canonical nonidentity compressed
   transmission key matches `pk_d`.
2. rseed and rho derive a nonzero ephemeral scalar; `epk = [esk]g_d`, the shared
   secret `[esk]pk_d` and the personalized BLAKE2b KDF are checked.
3. The plaintext `03 || diversifier11 || value8LE || rseed32 || memo512` encrypts
   under ChaCha20-Poly1305 (zero nonce, empty associated data) to all 580
   ciphertext/tag bytes ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)).
4. Every ordered Action contributes its encrypted memo and noncompact bytes to the
   complete transaction digest preimages.
5. The txid is in the accepted header's Merkle root, and the note commitment and
   rho match the selected Action's cmx and nullifier.

A commitment, a ciphertext hash or a supplied symmetric key alone does not
authenticate memo plaintext. The pure function returns `(txid, cmx)`; the adapter
returns `MemoCreated { memo, txid, cmx, value, raw_receiver }` from one load of
each capsule (68, 69, 103). Use those returned values; a second load is a new
unconstrained witness. Slot 103 has N ciphertext entries, zero after the last
Action. References: the note, encryption, key, address and bundle-commitment code
(`src/note.rs`, `src/note_encryption.rs`, `src/keys.rs`, `src/address.rs`,
`src/bundle/commitments.rs`) of the `orchard` 0.16.0 crate pinned at
[git rev `616a669`](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e) in `reference/notes/Cargo.toml`;
locked `pasta_curves 0.6.1` and `zcash_note_encryption 0.5.1`.

## Nullifier absence

Headers commit no nullifier-set root, so absence is a complete bounded scan.

`transactions::nullifier_absence::from_activation<B,TX,A>` opens **every
transaction** of `B` linked blocks ending at an accepted tip. Each V6 transaction
authenticates all its Ironwood compact Actions, each V5 transaction its format
without an Ironwood component; every active Action's nullifier must differ from
the queried one. Exact duplicate-last Merkle rules and rejection of repeated txids
prevent the `[a,b,c]` versus `[a,b,c,c]` ambiguity. `transactions::legacy::from_activation`
also authenticates full raw V4 bodies; an opaque txid is never evidence of absence.
The domain-separated V5/V6 BLAKE2b leaf preimages are distinct from 64-byte
SHA256d internal nodes; a raw-leaf path must preserve that separation. The scans
assume the tip is a valid block and do not recheck signatures, proofs or value
balance. The queried nullifier must be canonical (below the Pallas base modulus,
so `nf + p` aliases reject): pass the in-circuit `nf.to_le_bytes()`. Testnet scans
end at 4,465,025.

### Pinned pre-activation block

Every scan from activation (`from_activation`, `legacy::from_activation`,
`nullifier_absence_state::initialize`) asserts that the first block's parent equals
a constant in `noir/ironwood/src/transactions/nullifier_absence.nr`, so `B` linked
blocks are exactly heights activation to activation + B - 1 of one network: a
prover cannot claim a later block as the activation block or pass mainnet blocks as
testnet. The pin does not authenticate the tip; a fabricated chain from the pin to
an unaccepted tip still solves, so take the whole tip `(hash, height, network)`
from the accepted checkpoint. The height is the tip block's own height.

| Network | Block | Display hash (reverse for internal byte order) |
| --- | --- | --- |
| Mainnet | 3,428,142 | `00000000008b2ffd813f6a09372b4c9da20caad248245086445c19770ac270dd` |
| Testnet | 4,133,999 | `00001c94671d8de17537daf700e1c11eefd22645344d0a0c77065ed621539feb` |

The mainnet pin was checked against a raw Blockchair header and Cipherscan; the
testnet pin was cross-checked between Cipherscan and zcashexplorer without a local
raw-header hash check.

### Continuing a scan

`nullifier_absence_state::State` holds the nullifier, network, activation height,
last block hash and last height. `initialize` starts at activation with the pin and
rejects a noncanonical nullifier; `advance` requires a nonempty window within its
block capacity, exact height increments, matching parents, complete coverage and
absence, carries nullifier, network and activation unchanged, and rejects a
testnet tip above 4,465,025. The pure transition does **not** authenticate a
supplied prior `State`: take it only from `initialize`, `advance` or an
authenticated note. `nullifier_absence::continue_from_trusted_prior` is
crate-private for that reason.

The `IronwoodNullifierAbsenceState` contract
([examples/nullifier_absence_state](../examples/nullifier_absence_state/))
keeps `Owned<PrivateSet<NullifierAbsenceNote>>`. Notes are created only by `begin`
(activation initialization) and `extend` (reads and consumes the caller's note,
selected by both nullifier halves, prior height, both prior tip-hash halves and
network, so a reorg's other lineage is not chosen). A note packs seven fields
without reducing 256-bit hashes into one field. `verify(owner, nf, tip_hash,
tip_height, is_testnet)` reads without consuming, for any caller; the kernel's
note-read validation authenticates that `begin` or `extend` created it for
`owner`. It proves the note was created, not that it is the latest state: a
consumed checkpoint is rejected only by an honest PXE lookup, and remains a true
historical statement. Freshness is the application's job. Window data arrives in
capsule 67. Runtime stays proportional to all covered data; stored progress makes
windows reusable, it does not remove the initial scan.

## Claims that require composition

Each Aztec adapter loads its own capsules, and a PXE (or the holder of a second
note) can fill two adapters' capsules with different notes. When a claim combines
adapters, pass the same checkpoint where both take one and assert the returned
`cmx` values are byte-equal; never reload a capsule for a field of a claim. Prefer
one adapter that returns everything: `verify_owned` returns the contents plus the
nullifier; `ironwood_aztec::memo::verify` returns memo, txid, cmx, value and raw
receiver.

- **Spent by height h.** Derive the note's nullifier with the authority relation
  (use the nullifier the Owned or Nullifier adapter returns), then prove it occurs.
  The application authenticates the block hash, its height (at most h) and network.
- **Unspent through a checkpoint.** For ONE opening under ONE checkpoint: (a)
  membership of its `cmx` under the checkpoint (covering notes through h-1), or
  creation in an authenticated ancestor block; (b) the nullifier of the same
  opening with the same `cmx`; (c) complete absence of that nullifier through the
  same checkpoint. Without (a), an invented opening's nullifier never occurs and the
  scan succeeds. `verify_owned`, `verify_nullifier` and `derive_member` give (a)
  and (b) from one opening; `derive_with_commitment` gives only the link.
- **Created in block X and in the tree at checkpoint C.** The note first appears
  under a header at height(X) + 1 or later, so these need two checkpoints that the
  application authenticates and relates (X an ancestor of C); one hash for both
  rejects every valid note.
- **Pays this raw Zcash address.** Use the memo route; the contents, creation and
  ownership claims bind only the expanded `(g_d, pk_d)` receiver.
- **Satisfies my request (a deposit).** Use the memo route and a constrained
  predicate over its returned values bound to application state. Predicates
  checked outside the circuit are not part of the proof.

## Not supported

| Claim | Boundary |
| --- | --- |
| Transaction validity or mempool admission | Effect inclusion verifies no Halo2 proof, signature, authorization or chain-state eligibility |
| The checkpoint is on the canonical/final chain | Supplied by the application; no consensus or light-client circuit |
| Other pools or eras | Ironwood V3/NU6.3 only; no Orchard V2 or Sapling circuits; historical parsing is not a circuit |
| Transparent outputs, outpoint spends, UTXO unspentness | Not proven in circuit |
| A short nullifier non-membership path | No nullifier-set root exists; complete bounded scans instead |
| Unlimited sizes | Explicit capacities; overflow rejects and an oversized block is never split |

## Consumer obligations

A successful verification proves a fact about inputs the application supplies.

### Authenticated inputs

- Authenticate the checkpoint (header hash, height, network) or note-tree root.
  No circuit establishes consensus, canonical-chain membership or finality, and a
  mainnet/testnet label is policy.
- Created, Action and transaction adapters take only a block hash; their statement
  holds for that block with any parent, height or fork.
- Witness preparation outside the circuit is neither verification nor checkpoint
  authorization.

### Adapter address

A private call runs the callee's contract class; an impostor with the same
signature can return anything. Prefer embedding the `ironwood_aztec` functions with
`self.address`. When calling a deployed adapter, take its address from
initializer-set immutable storage or a constant, never an argument, and optionally
check its class. Capsules live at the address of the contract that loads them.

### Replay

The note, creation and memo adapters take the address, a claim index, the
checkpoint and capsules (scan contracts also the nullifier). They emit no
nullifiers, notes or logs and consume no capsules, so each succeeds again in every
later transaction for any caller. One address and claim index give one witness per
transaction, but a malicious wallet can return any valid note and two adapter
addresses can claim the same note in one transaction, so never key one-time use on
the address or claim index. The state adapter's `extend` consumes its own prior
note, which protects scan coverage, not the application's use of the result.

### One-time use and nullifiers

If a fact may be used once, emit a domain-separated application nullifier per fact:

- Contents, ownership, nullifier-link, creation and memo claims: key on the
  returned `cmx`, not on the checkpoint, block or txid. A note in the tree at one
  checkpoint is in it at every later one, a reorg can move a creation to another
  block, and keying on the txid blocks the transaction's other notes. Take `cmx`,
  value and receiver from the claim's return values: reloading the opening capsule
  is unconstrained and lets a prover choose another opening.
- `cmx` and nullifiers are canonical Pallas base-field values below
  p = 2^254 + 45560315531419706090280762371685220353, which can exceed the BN254
  scalar modulus (about 2^253.6): pack each as two 128-bit limbs.
- A note can be spent on Zcash after a historical unspent proof; choose a freshness
  rule for the checkpoint.

### Recipient, action and authority

Bind the recipient and action from the proven fact or an authority over it, never
from the caller. Key-free claims prove knowledge of the opening, which the sender
and viewing-key holders share; spending authority and unspent status are separate
claims.

### Linkability

These nullifiers are public: `cmx` and Action nullifiers are public Zcash data, so
anyone can see which note was consumed and when. The library provides no
unlinkability, and adding a free secret is not enough unless one fact fixes one
secret.

The [note_value example](../examples/note_value/contract/src/main.nr) counts calls,
discards `cmx` and has no replay, ownership, unspent or finality rule; the
other examples in [examples/](../examples) emit no nullifier. Do not copy any of them into a
contract that grants value per call.

## Capsule slots

`ironwood_aztec` (`HEADER_SLOT` to `MEMO_SLOT`) and the example contracts read their
witnesses from these capsule slots. Every capsule has scope zero and one layout
per slot.

| Slot | Content | Fields | Read by |
| --- | --- | --- | --- |
| 60 | Header, history node, auth root | 1836 | `verify_contents`, `verify_contents_capsules`, `verify_owned`, `verify_nullifier` |
| 61 | Note opening, position, 32 siblings | 145 | the same |
| 63 | Activation scan | capacity-dependent | `examples/aztec_nullifier_absence` |
| 64 | Viewing authority (ak, nk, rivk) | 12 | `verify_nullifier` |
| 65 | Spending authority (ask, nk, rivk) | 9 | `verify_owned` |
| 66 | Mixed V4/V5/V6 scan | capacity-dependent | contracts using `transactions::legacy::from_activation` |
| 67 | Scan-state window | capacity-dependent | `examples/nullifier_absence_state` |
| 68 | Transaction inclusion | 1680 + 148N + 32 DEPTH | `creation::{inclusion, verify_action, verify_created}`, `memo::verify` |
| 69 | Key-free note opening (slot 61's first 48 fields) | 48 | `creation::verify_created`, `memo::verify` |
| 70 + level | Merkle hint records, levels 0 to 31 | 780 each | `verify_contents_capsules` |
| 102 | Note-hash hint records | 1635 | `verify_contents_capsules` |
| 103 | Raw receiver, memo, full Action ciphertexts | 555 + 724N | `memo::verify` |

Slot 68 is `header[1487] || N x compact Action[148] (unused zero) || memos[32] ||
noncompact[32] || flags[1] || balance[8] || transparent[32] || sapling[32] ||
orchard[32] || lock_time[4] || expiry[4] || DEPTH x sibling[32] || action_index[4]
|| tx_index[4] || tx_count[4] || action_count[4]` (u32 little-endian, one byte per
field; 3296 fields for N=4, DEPTH=32). Slot 103 is `raw receiver[43] || memo[512]
|| N x (ciphertext[580] || cv[32] || rk[32] || out[80])`, zero after the Action
count. Slot 60 is `header[1487] || node[317] || auth_root[32]`, each a byte.

A PXE returns the first capsule matching (contract, slot, scope), so claim `k` at
one address reads `slot + 256 k` (`ironwood_aztec::claim_slot`); every slot is
below 256. Library functions take the claim index after the address; the example
contracts read claim 0, one claim per address per transaction. The claim index
selects a witness and adds no constraint.

Slots 64 and 65 carry secret authority material. Scope zero is global to every
account of a PXE, so deliver them only as transient capsules of one transaction,
never persisted; the claims do not bind `msg_sender`, and a scope argument would
not help because it reaches only an unconstrained oracle.
