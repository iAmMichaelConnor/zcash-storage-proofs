> [!WARNING]
> **This code has not been audited.** It is experimental software, provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). A bug can leave a circuit under-constrained, so that invalid proofs are accepted. Do not rely on it to protect real assets or sensitive data without your own independent review.

> [!NOTE]
> This is an independent project, not an official Zcash product. It is not affiliated with, sponsored by or endorsed by the Zcash Foundation, the Electric Coin Company or any other Zcash organisation. The Zcash name and logo belong to their owners and are used only to say what this software works with.

<a href="https://z.cash/"><img src="docs/assets/zcash.svg" width="32" alt="Zcash"></a>

# zcash-storage-proofs

**Prove facts about Zcash notes inside a Noir circuit, without revealing the note.**
Use shielded ZEC as evidence in any Noir program or Aztec private function.

For example, you can:

- Prove a note exists.
- Prove a note contains a particular value, or at least some amount.
- Prove a note was sent to a particular receiver.
- Prove a note was created in a particular block.
- Prove a note carries a particular memo, and that its receiver can decrypt it (a
  deposit).
- Prove you own a note: you hold its spending key.
- Prove you can view a note, and derive its nullifier, with only a viewing key.
- Prove a note has been nullified (spent).
- Prove a note has not been spent.
- Prove you own a particular note and that it hasn't been spent.
- Prove solvency: you control unspent notes worth at least some amount.
- Prove a transaction's shielded effects appeared in a particular block.

Prove any of these against the latest block or a historical one: each proof is
checked against a block header or note-tree root that you choose. The claims can be
composed, and programmably customised or expanded: one circuit can combine several
of them and add its own checks on the values they expose (an amount, a receiver, a
memo tag, a block height).

The circuits cover Ironwood V3 notes in V6 transactions under NU6.3. Arithmetic is
Pallas over BigNum/BigCurve with constrained hints.

The circuits **open chain data**. They do not verify an Ironwood bundle (Halo2)
proof, signatures or consensus: the application supplies an accepted checkpoint
(header hash, height, network) or note-tree root, and its own replay policy. Zcash
headers carry no nullifier-set root, so absence is a complete scan with explicit
capacities; inputs larger than a capacity are rejected, never truncated.

## What is in the repository

| Package | Contents |
| --- | --- |
| [`ironwood`](noir/ironwood) | The relations: notes and authority, headers and history, transaction effects, creation, memos, nullifier absence. No Aztec dependency |
| [`ironwood_aztec`](noir/ironwood_aztec) | Loads `ironwood` witnesses from Aztec capsules in a private function; every check stays in `ironwood` |

`noir/ironwood_{creation,notes,transactions}_tests` are test-only packages, and
`vendor/` holds copies of [noir-bignum](https://github.com/noir-lang/noir-bignum)
(with one local patch) and [noir_bigcurve](https://github.com/noir-lang/noir_bigcurve)
at pinned commits (see [NOTICE](NOTICE)).

### Aztec examples

[`examples/`](examples) holds Aztec contracts that read their witnesses from
capsules through `ironwood_aztec`:

| Example | What it shows |
| --- | --- |
| [`aztec_contents`](examples/aztec_contents) | Note contents under a header checkpoint in a private function. TXE tests of its logic, not of the deployed contract ([gaps](CONTRIBUTING.md#tests)) |
| [`aztec_contents_capsules`](examples/aztec_contents_capsules) | The same with Sinsemilla hints supplied in capsules and checked in circuit. TXE tests of its logic, not of the deployed contract ([gaps](CONTRIBUTING.md#tests)) |
| [`aztec_nullifier_absence`](examples/aztec_nullifier_absence) | A complete absence scan in one private function. TXE tests of its logic, not of the deployed contract ([gaps](CONTRIBUTING.md#tests)) |
| [`note_value`](examples/note_value) | Checkpoint and minimum value fixed at deployment; accepting a note updates a public counter. TXE tests of its logic, not of the deployed contract ([gaps](CONTRIBUTING.md#tests)) |
| [`nullifier_absence_state`](examples/nullifier_absence_state) | An absence scan carried across transactions in private notes, readable by another contract. TXE tests of its logic, not of the deployed contract or the cross-contract read ([gaps](CONTRIBUTING.md#tests)) |

None of them emits a nullifier for the note or authenticates the checkpoint: do not
copy them into a contract that grants value per call without the
[consumer obligations](docs/API.md#consumer-obligations).


## Compatibility

The Noir packages are tested with Noir 1.0.0-rc.3, the minimum supported
version (what Aztec 6.0.0 ships), and with Noir 1.0.0, the latest release, on
every pull request, and with Noir nightly every night. Keep this in sync with
the `toolchain` matrix in `.github/workflows/test.yml`.

`ironwood_aztec` and the example contracts are tested with Aztec 6.0.0 only
(Aztec.nr `v6.0.0`, nargo 1.0.0-rc.3, bb 6.0.0). Keep this in sync with
`AZTEC_VERSION` in `.github/workflows/test.yml` and with [`.aztecrc`](.aztecrc).

## Installation

In your `Nargo.toml`, add the package you need. Each lives in its own directory of
this repository:

```toml
[dependencies]
ironwood = { git = "https://github.com/iAmMichaelConnor/zcash-storage-proofs", tag = "v0.1.0", directory = "noir/ironwood" }
# In an Aztec contract, next to Aztec.nr:
ironwood_aztec = { git = "https://github.com/iAmMichaelConnor/zcash-storage-proofs", tag = "v0.1.0", directory = "noir/ironwood_aztec" }
aztec = { git = "https://github.com/aztec-labs-eng/aztec-nr", tag = "v6.0.0", directory = "aztec" }
```

`ironwood` re-exports the BigNum and BigCurve types it uses (`ironwood::{BigNum,
Pallas_Fq, Pallas_Fr, BigCurve, Pallas}`); use those rather than adding your own
`bignum` dependency, so that both sides use the same patched copy.

## Usage

Each claim is one function call. The checkpoint (header hash, height, network) or
the note-tree root is the application's policy: take it from authenticated
storage, never from the prover.

```rust
use ironwood::{BigNum, Pallas_Fq};

// A note with this opening (value, receiver, rho, rseed) is in the tree with this root.
ironwood::verify_contents_membership(note, position, siblings, Pallas_Fq::from_le_bytes(root));

// The header hashes to the accepted checkpoint; its history commits to the latest
// Ironwood note-tree root, valid for notes created up to height - 1.
let snapshot = ironwood::verify_header_latest(header, header_hash, height, is_testnet, node, auth_root);

// The deposit claim: the note was created in the block with this header hash, the
// receiver can decrypt it, and its memo is `memo`. Bind the receiver and value to
// your request and consume a nullifier keyed on the returned cmx.
let (txid, cmx) = ironwood::verify_memo_created_in_block(note, raw_receiver, memo, witness, full, header_hash);
assert(memo[0] == tag[0]); // an application-defined memo tag

// The note's output is an Action of a transaction in that block (no decryption claim).
let (action, txid) = ironwood::verify_created_in_block(note, witness, header_hash);

// A nullifier occurs in a transaction of the block with this header hash.
ironwood::verify_nullifier_inclusion(witness, nullifier, header_hash);

// The prover holds the spending authority of the receiver; or derives the note's
// commitment and nullifier from a viewing authority.
ironwood::notes::ownership::verify(note.receiver, spend_authority);
let (cmx, nf) = ironwood::derive_with_commitment(note, viewing_authority);

// No Ironwood Action from activation to the accepted tip spends `nf` (here two
// blocks of at most four transactions with at most two Actions each).
let blocks = ironwood::transactions::encoding::blocks::<2, 4, 2, 6830>(bytes);
ironwood::transactions::nullifier_absence::from_activation(blocks, nf, tip_hash, tip_height, is_testnet);
```

`witness` is an `ironwood::Inclusion<N, DEPTH>`: the header, the transaction's
effects with up to `N` Actions, its Merkle path (capacity `DEPTH`) and indices. A
scan can also be carried across transactions in private notes
(`transactions::nullifier_absence_state`).

[docs/API.md](docs/API.md) states every claim, what it does not prove, how to
compose claims and what a consumer must still check. [docs/COMPOSITION.md](docs/COMPOSITION.md)
covers the arithmetic contracts and backend premises, and
[docs/PROTOCOL.md](docs/PROTOCOL.md) the pinned Zcash protocol details.

### TypeScript SDK

[`packages/zcash-storage-proofs`](packages/zcash-storage-proofs) (npm package
`zcash-storage-proofs`, Node 22+) turns Zcash data (note openings, headers,
transactions, raw blocks) into the witnesses and Aztec capsules that `ironwood` and
`ironwood_aztec` read. It
validates and re-derives what it can, but proves nothing: the circuit checks every
value, and the application authenticates the checkpoint. It works offline; block
fetching takes an RPC client you supply.

The package is not published to npm. Build a tarball from a checkout and install it
in your project:

```bash
cd packages/zcash-storage-proofs
npm ci --ignore-scripts && npm run build && npm pack
# in your project:
npm install /path/to/zcash-storage-proofs/packages/zcash-storage-proofs/zcash-storage-proofs-0.1.0.tgz
```

```ts
import { prepareContents } from 'zcash-storage-proofs';
import { installCapsules } from 'zcash-storage-proofs/aztec';

// `envelope` is a `contents` envelope: note opening, Merkle path and header at the
// application's accepted checkpoint.
const prepared = prepareContents(envelope, { contractAddress });
const args = await installCapsules(prepared, contractAddress, {
  async setCapsule(c) {
    // Install c.fields at c.slot, scope zero, as a transient capsule of this transaction.
  },
}, checkpointPolicy);
// Pass `args` (not prepared.arguments) to the contract's private function.
```

The [package README](packages/zcash-storage-proofs/README.md) lists the envelopes,
preparation functions, capacity profiles and the native hint tool.

## Benchmarks

Circuit size (`bb gates` `circuit_size`, before power-of-two padding) of each claim's
`#[export]` benchmark function in [`noir/ironwood/src/benchmarks.nr`](noir/ironwood/src/benchmarks.nr),
measured with Noir 1.0.0 and bb 6.0.0 on 2026-11-10. Transaction claims use one
Action and a 32-level transaction Merkle path. The
[benchmark workflow](.github/workflows/benchmark.yml) reports current numbers on
pull requests that can change a circuit and records history on the `gh-pages`
branch.

| Claim | Function | ACIR opcodes | Circuit size |
| --- | --- | ---: | ---: |
| Note in the note tree | `note_membership` | 604,200 | 1,316,431 |
| Spending authority | `spending_authority` | 303,308 | 654,923 |
| Commitment and nullifier from a viewing authority | `linked_nullifier` | 451,615 | 987,066 |
| Header and history opening | `header_history` | 17,173 | 142,206 |
| Nullifier in a block | `nullifier_inclusion` | 33,592 | 553,873 |
| Note created in a block | `created_in_block` | 173,970 | 861,370 |
| Memo of a note created in a block (deposit) | `memo_created_in_block` | 531,563 | 1,670,380 |
| Nullifier absent, 2 blocks × 4 transactions × 2 Actions | `nullifier_absence_2_blocks` | 221,519 | 853,833 |

To generate the report locally:

```bash
./scripts/build-gates-report.sh
```

## Security

If you find a vulnerability, please **do not** open a public issue. Report it
privately via [GitHub's "Report a vulnerability"](https://github.com/iAmMichaelConnor/zcash-storage-proofs/security/advisories/new)
form instead.

Limitations to design around:

- **Unconstrained use needs a low inliner setting.** Every relation compiles to
  Brillig with Noir 1.0.0-rc.3 and 1.0.0, but with the default inliner compiling
  the note-commitment, Merkle and memo code takes minutes per program; pass
  `--inliner-aggressiveness 0` (see [CONTRIBUTING.md](CONTRIBUTING.md#tests)).
  The Sinsemilla S table is held in globals: as local arrays of the function the
  hash calls per chunk, it makes Brillig compilation fail
  ([noir-lang/noir#14162](https://github.com/noir-lang/noir/issues/14162), "Stack
  frame too deep").
- **Fixed capacities.** Action counts, Merkle depths and scan sizes are generic
  parameters; a larger input is rejected, and each capacity is a separate circuit.
- **One pinned protocol version.** Ironwood V3 notes, V6 transactions, NU6.3. Other
  note or transaction versions need separate implementations.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
