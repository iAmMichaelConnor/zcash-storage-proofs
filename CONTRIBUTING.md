# Contributing

Thank you for your interest in contributing! This guide covers the
[layout](#layout), [setup](#setup), [tests](#tests), [benchmarks](#benchmarks),
[generated files](#generated-files), [vendored code](#vendored-code),
[releases](#releases) and how this repository [differs from the
noir-library-starter
template](#differences-from-the-noir-library-starter-template). Keep pull
requests focused, and open an issue first for anything substantial. Breaking
changes must update the README or the documentation. Run every command below
from the repository root.

## Layout

```
noir/ironwood/                  the relations (pure Noir)
noir/ironwood_aztec/            capsule transport for Aztec private functions
noir/ironwood_*_tests/          test-only packages that use ironwood through its public API
vendor/                         noir-bignum and noir_bigcurve at pinned commits (see NOTICE)
patches/                        the local patch applied to vendor/noir-bignum
examples/<name>/contract/       Aztec example contracts
examples/<name>/tests/          their TXE tests
examples/<name>/slow_tests/     TXE tests too slow for pull requests
fixtures/                       test vectors and the data they are generated from
reference/                      Rust programs that compute reference vectors with Zcash's own crates
packages/zcash-storage-proofs/       TypeScript SDK: witness and capsule preparation (npm package)
scripts/                        generator, vendoring, example-test and benchmark scripts
docs/                           claims and API, composition requirements, protocol notes
```

The repository is a Nargo workspace.

## Setup

- Noir: install with [noirup](https://github.com/noir-lang/noirup), e.g.
  `noirup -v 1.0.0`. Either version CI tests works (see the README).
- Aztec 6.0.0 (pinned in [`.aztecrc`](.aztecrc)), only for `ironwood_aztec` and
  the example contracts:
  `curl -fsSL https://install.aztec-labs.com | VERSION=6.0.0 bash`.
- Python 3 (standard library only), to regenerate and check test vectors.
- Node.js 22 or newer, only for the TypeScript SDK in
  `packages/zcash-storage-proofs`.
- Rust (rustup), only to regenerate the fixtures that come from the Rust
  reference programs in `reference/`.
- bb, only for benchmarks:
  `curl -L https://bbup.aztec.network | bash && ~/.bb/bbup -v 6.0.0`.

## Tests

```bash
nargo test --package ironwood --force-brillig --inliner-aggressiveness 0   # one package, as pull requests run it
nargo test --package ironwood_slow_tests --test-threads 4                  # one package constrained, as the nightly slow mode runs it
aztec-nargo check --workspace                 # type-checks the example contracts (Aztec toolchain)
./scripts/test-examples.sh                    # example and ironwood_aztec tests (Aztec toolchain, starts a TXE)
./scripts/test-examples.sh --slow aztec_contents_capsules   # and an example's slow_tests crate, as the nightly workflow runs it
python3 scripts/check_vendor_hints.py         # dishonest BigNum hints cannot change constrained results
nargo fmt --check
```

`nargo test` proves nothing: it compiles each test and executes it. Run as
written (constrained), each test compiles to an ACIR circuit and executes it;
with `--force-brillig` the same assertions run as unconstrained code, without
building a circuit. Pull requests run each package unconstrained, with
`--inliner-aggressiveness 0`: with Brillig's default inliner, compiling the
BigCurve and Sinsemilla code takes minutes per test (one memo test: 6 min 19 s
by default, 16 s with 0). The nightly workflow runs the same set on Noir
nightly, and every package constrained on Noir 1.0.0 (the slow mode). It also
compiles the example contracts (`aztec-nargo compile --workspace`), which pull
requests only type-check. Tests that must exercise
the constraints pass their inputs through `std::hint::black_box` so that the
compiler cannot fold them away.

Per pull request: `ironwood`, `ironwood_creation_tests`, `ironwood_notes_tests`,
`ironwood_transactions_tests`, and the four tests of the local BigNum patch
(`nargo test --package bignum range_checked_test::`). A `*_slow_tests` crate
(`slow_tests` in an example) is a sibling crate holding tests that need their
own handling in the nightly run (memory or time) or that only make sense
constrained; it also runs per pull request when its fast mode takes under about
2 minutes. `ironwood_slow_tests` and `aztec_contents_capsules_slow_test` do not
run per pull request. Nightly only:

- `ironwood_slow_tests`: the nullifier and note-tree membership tests, whose
  32-level Sinsemilla paths are too slow for a pull request in either mode, and
  the `#[no_predicates]` tests, which check constrained behaviour (unconstrained
  code never executes a false branch).
- The vendored suites, `bignum` and `noir_bigcurve`: upstream's tests of
  upstream code, many of which feed dishonest hints and expect a failed
  constraint. `./scripts/vendor.sh --check` (pull requests) proves that the
  copies are the pinned commits plus `patches/`.
- `scripts/check_vendor_hints.py`, which compiles and runs constrained programs
  (5 min 39 s locally), in the `noir_bigcurve` job.
- `aztec_contents_capsules_slow_test`: the two `aztec_contents_capsules` tests
  that compute the Sinsemilla hints for all 32 levels of the note's path, in
  the `compile-examples` job
  (`scripts/test-examples.sh --slow aztec_contents_capsules`: 3 min 50 s
  locally on four cores, 2 min 14 s per test).

Memory grows with `--test-threads` (nargo's default is one thread per core); CI
passes 4, the vCPUs of a hosted runner. Measured locally with Noir 1.0.0; the
constrained runs were measured with more threads than the nightly jobs use, so
each nightly timeout allows for the slower four-thread run:

| Package | Tests | Per pull request: unconstrained, 4 threads | Nightly: constrained, 4 threads | Local constrained run |
| --- | ---: | --- | --- | --- |
| `bignum` (vendored) | 407 | the 4 patch tests: 4 s, 0.6 GB | 30 min timeout | 16 threads: 2 min 8 s, 3.2 GB |
| `noir_bigcurve` (vendored) | 145 | not run | 60 min timeout, with `check_vendor_hints.py` | 16 threads: 7 min 13 s, 12.4 GB |
| `ironwood` | 141 | 1 min 38 s, 5.0 GB | 120 min timeout | 32 threads: 7 min 46 s, 33.4 GB |
| `ironwood_creation_tests` | 15 | 1 min 0 s, 3.1 GB | 30 min timeout | 16 threads: 1 min 22 s, 10.0 GB |
| `ironwood_notes_tests` | 86 | 2 min 7 s, 5.3 GB | 60 min timeout | 16 threads: 4 min 25 s, 18.0 GB |
| `ironwood_transactions_tests` | 108 | 19 s, 1.6 GB | 30 min timeout | 16 threads: 46 s, 6.8 GB |
| `ironwood_slow_tests` | 11 | not run | 120 min timeout; unmeasured | one membership test alone: 6 min 28 s, 2.8 GB |

The constrained run of `ironwood_slow_tests` has not been run to completion
locally, so it is unmeasured. The per-pull-request jobs run in parallel, one per
package and toolchain; expect each to take about 2 to 3 minutes with toolchain
installation.

The TypeScript SDK has its own npm scripts, run from
`packages/zcash-storage-proofs` (CI runs them in the `host` job):

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build && npm run typecheck
npm test                  # node --test; no network, nargo or Aztec needed
npm run test:package      # packs the package and installs it into a scratch consumer
npm run fixtures:check    # tests/fixtures match tests/prepare-fixtures.py
npm run catalogue:check   # src/profile-catalogue.ts matches profiles/catalogue.v1.json
npm run schemas:check     # src/schemas/ match scripts/host_schemas.py
```

The SDK fixtures are generated from `fixtures/` through the modules in
`scripts/` (`npm run fixtures` rewrites them), so a change to those inputs can
make `fixtures:check` fail.

The Aztec tests use TXE, which simulates contract state and runs circuits; it
makes no proofs and sends no network transactions. They run the examples' logic
in TXE test contexts (`private_context_at` an address whose capsules hold the
witnesses), calling the functions the contracts call, so no contract is compiled
or deployed; the example contracts are type-checked. The tests take storage
slots from each contract's `storage_layout()`. The `aztec_contents_capsules`
tests compute the Sinsemilla hints from the note, as a host does natively, so no
fixture holds hint data. The `examples` job's `test-examples.sh --jobs 4` took
4 min 58 s locally on four cores of a shared machine (an upper bound). What the
example tests do not cover, because only a deployed contract has them:

- The `#[only_self]` attribute on note_value's `record_acceptance`: without it
  anyone could raise the counter.
- That `accept` passes `check_note` its own address and the stored policy, and
  enqueues `record_acceptance`.
- That note_value's constructor stores the policy and a zero counter.
- That `begin` and `extend` use the notes of `msg_sender`, so a caller can
  create and advance only their own scan state: the tests choose the owner.
- That `begin` and `extend` deliver the new note's message onchain: the tests
  hand the message to the PXE directly.
- A call to `verify` from another contract, which passes its own `msg_sender` as
  the owner: the tests run `verify`'s logic in a context of the contract itself.
- That the `verify` functions of `aztec_contents`, `aztec_contents_capsules` and
  `aztec_nullifier_absence` pass their own address (whose capsules hold the
  witnesses) and return what the tested function returns.
- The kernel's checks of the notes that `extend` and `verify` read: TXE trusts
  the notes its PXE returns, so the tests show only an honest lookup.
- The `count` view.

A dishonest Sinsemilla hint in `aztec_contents_capsules` is not tested either:
executing one fails in BigNum's relation hint, an assertion without a message,
before the step's constraint, so no test can name the failure;
`scripts/check_vendor_hints.py` bypasses that hint and checks that the
constraint rejects the record.

Rejection tests name their failure: use `#[test(should_fail_with = "...")]` with
the assertion message, never a bare `should_fail`, and give a new library
assertion a message and a negative test.

## Benchmarks

`noir/ironwood/src/benchmarks.nr` has one `#[export]` function per claim. See
the README for the command; the benchmark workflow posts the gate diff on pull
requests and records history on the `gh-pages` branch, which must exist before
the first workflow run. The export took 16.5 minutes locally (peak 3.6 GB), so
pull requests run the workflow only when they change `noir/ironwood`, `vendor/`,
`Nargo.toml` or the benchmark tooling; every push to `main` runs it.

## Generated files

Most large test modules and their inputs are generated; do not edit them by
hand.

```bash
python3 scripts/generate.py [--check]                   # Python generators
python3 scripts/generate_native_fixtures.py [--check]   # Rust reference programs
```

`scripts/generate.py` is the entry point for every generator except the Rust
reference programs, which have their own entry point because they need a Rust
build. Each command rewrites its outputs, or with `--check` fails if a committed
file differs. CI runs `generate.py --check` in the `format` job and
`generate_native_fixtures.py --check` in the `native-fixtures` job, which caches
the Cargo registry and the reference build and has a 30-minute timeout: locally,
with an empty reference build and a filled registry, the check took 44 s (131
CPU-seconds). Generated Noir is formatted with `nargo fmt` (`$NARGO`, else
`nargo` on `PATH`) through `scripts/noir_format.py`.

| Generator | Writes | From |
| --- | --- | --- |
| `generate_native_fixtures.py` | `fixtures/ironwood_notes/*.json`, `fixtures/memo/native-vectors.json`, `fixtures/poseidon/`, `fixtures/note-generators/`, `ironwood/src/poseidon/constants.nr`, `ironwood/src/notes/*_generator.nr`, `ironwood/src/sinsemilla/generators.nr` | `reference/notes`, `reference/memo` (zcash/orchard, zcash/halo2, sinsemilla), `fixtures/ironwood_transfer` |
| `synthetic_fixtures.py` | `fixtures/ironwood_headers/header-mainnet.json` | native note vectors, synthetic header fields |
| `prepare_memo_fixtures.py` | `fixtures/memo/case-0.toml` | native memo vectors, synthetic block |
| `generate_creation_tests.py` | `ironwood_creation_tests/src/creation_tests.nr` | native vectors, Python `hashlib` block model |
| `generate_memo_tests.py`, `generate_memo_negative_tests.py` | `ironwood/src/memo/*_tests.nr` | native memo vectors, `chacha20poly1305.py` (RFC 8439), a Python Pallas model |
| `generate_note_tests.py` | `ironwood_notes_tests/src/*.nr` | native note vectors, Python integer arithmetic |
| `generate_nullifier_tests.py` | `ironwood_slow_tests/src/nullifier_tests.nr` | native nullifier vectors |
| `generate_transaction_tests.py` | `ironwood_transactions_tests/src/*.nr`, `ironwood/src/transactions/{inclusion,legacy}_tests.nr`, `examples/aztec_nullifier_absence/tests/src/fixture.nr` | ZIP 244 digests and block models in `hashlib` |
| `generate_header_tests.py` | `ironwood/src/headers/*_tests.nr` | the synthetic header, `hashlib` |
| `generate_nullifier_absence_tests.py` | scan tests in `ironwood`, `examples/nullifier_absence_state/tests/src/fixture.nr` | synthetic chains from the pinned pre-activation block |
| `generate_note_value_fixture.py` | `examples/note_value/tests/src/fixture.nr` (also used by the `aztec_contents` and `aztec_contents_capsules` tests) | native note vector, the synthetic header |
| `generate_nullifier_absence_note_tests.py` | `examples/nullifier_absence_state/contract/src/nullifier_absence_note_tests.nr` | the Aztec 6.0.0 SDK's Poseidon2 (`$AZTEC_NODE_MODULES`, default `~/.aztec/current/node_modules`) |

`fixtures/ironwood_transfer` is retained input, not regenerated: one synthetic
Ironwood transfer, not a mainnet transaction, with a 5000-zatoshi spend and
output built locally with zcash/orchard at the commit in
`reference/notes/Cargo.toml`; its spend and binding signatures and the
recipient's decryption verified natively (`semantics.json`). `generate.py`
checks it against its `provenance.json`. All blocks, headers and checkpoints in
the vectors are synthetic.

## Vendored code

`./scripts/vendor.sh` rebuilds `vendor/` from the pinned upstream commits and
`patches/`; with `--check` it fails if the committed copies differ (CI runs it).
It pins one commit of each library. noir_bigcurve has no local patch: change its
commit in the script and run `./scripts/vendor.sh`.

`patches/bignum-prechecked.patch` is one `git format-patch` commit on top of the
pinned noir-bignum commit (its `base-commit:` line). To move it to a new commit:

```bash
git clone https://github.com/noir-lang/noir-bignum bignum && cd bignum
git fetch origin <new-commit> && git checkout FETCH_HEAD
git am -3 ../patches/bignum-prechecked.patch    # on conflicts: fix, git add, git am --continue
nargo test range_checked                        # the patch's own tests
# If a function the patch calls changed, fix the call and `git commit --amend`.
git format-patch -1 --stdout --zero-commit --no-signature --full-index --base=HEAD~1 \
    > ../patches/bignum-prechecked.patch
cd .. && rm -rf bignum
```

Then put the new commit in `scripts/vendor.sh`, `NOTICE`,
`packages/zcash-storage-proofs/profiles/catalogue.v1.json` and
`packages/zcash-storage-proofs/src/profile-catalogue.ts`, run
`./scripts/vendor.sh`, `nargo check --workspace` and
`python3 scripts/check_vendor_hints.py`, and regenerate the gate reports.
`evaluate_quadratic_expression_prechecked` must stay
`evaluate_quadratic_expression` without its three input range-check loops, so
compare the two functions in `src/fns/expressions.nr` after every move.

## Releases

Pull request titles follow [Conventional
Commits](https://www.conventionalcommits.org/en/v1.0.0/), which drive the
changelog and version numbers:

```
<type>[optional scope]: <description>
```

- `feat:` new functionality (appears in the changelog);
- `fix:` bug fixes (appears in the changelog);
- `chore:` everything else (omitted from the changelog unless breaking).

Mark a breaking change with `!` after the type or scope, e.g.
`feat(ironwood)!: Return the header snapshot`. Use the package name as the scope
when a change touches one package.

[Release Please](https://github.com/googleapis/release-please) runs on every
push to `main`. It opens or updates a release pull request with the next version
and the changelog; merging that pull request tags the release. All packages
share one version and one tag. The first release is v0.1.0. The npm package
under `packages/` carries that version: Release Please writes it into its
`package.json` and `package-lock.json` (`extra-files` in
`release-please-config.json`).

The release workflow uses the default `GITHUB_TOKEN`, and pull requests opened
with it do not trigger CI; to run the checks on release pull requests, replace
it in `release.yml` with a personal access token stored as a repository secret.

### Publishing checklist

Before the first release:

- create an empty `gh-pages` branch, where the benchmark workflow records
  history;
- enable private vulnerability reporting in the repository's security settings,
  for the README's reporting link.

## Differences from the noir-library-starter template

- **Workspace with packages under `noir/`.** The repository publishes `ironwood`
  and `ironwood_aztec`, so consumers add a `directory` to the git dependency.
  The `ironwood_*_tests` packages keep large generated tests out of the
  published package.
- **Two Noir versions per pull request.** The template tests every Noir release
  from the minimum supported version, and nightly, on each pull request. This
  repository tests the two ends, 1.0.0-rc.3 (the minimum, which Aztec 6.0.0
  ships) and 1.0.0 (the latest release), per pull request, and Noir nightly in
  the nightly workflow.
- **Vendored BigNum and BigCurve.** `ironwood` needs fixes that are not in any
  upstream release and one local BigNum addition (see NOTICE), so `vendor/`
  holds copies at pinned commits, `scripts/vendor.sh --check` checks them
  against upstream and `patches/`.
- **Tests run per package, unconstrained on pull requests.** One CI job per
  package and toolchain runs
  `nargo test --force-brillig --inliner-aggressiveness 0 --test-threads 4`,
  which keeps each job to a few minutes and inside a hosted runner's 16 GB; the
  constrained runs, the vendored libraries' suites and `ironwood_slow_tests` run
  in the nightly workflow (see [Tests](#tests)).
- **No Brillig benchmark report.** The claims are meant to be proved, so the
  benchmark workflow reports circuit sizes only. Only `ironwood` is exported,
  because the vendored libraries carry upstream's own benchmarks, and pull
  requests run the export only when they can change a circuit (see
  [Benchmarks](#benchmarks)).
- **Examples job.** `ironwood_aztec` and the examples depend on Aztec.nr v6.0.0,
  which supports nargo 1.0.0-rc.3 only, so they are type-checked and tested in
  one job with the official Aztec installer and a TXE
  (`scripts/test-examples.sh`), not in the Noir version matrix or the Noir
  nightly canary; the nightly workflow compiles the example contracts on Aztec
  6.0.0.
- **TypeScript SDK under `packages/`.** `packages/zcash-storage-proofs` prepares
  witnesses and capsules on the host; it has its own npm scripts and CI job and
  shares the repository's version.
- **No oracle server or differential tests.** The reference values are fixed
  vectors from Zcash's Rust crates and independent Python models, generated into
  Noir tests. The format job runs `scripts/generate.py --check`, and a separate
  job checks the Rust-derived fixtures; Python is used only for these
  generators, `check_vendor_hints.py` and the SDK's fixture, catalogue and
  packaging scripts.
- **bb is installed by version.** `bbup -nv` cannot resolve Noir 1.0.0, so the
  benchmark workflow names bb 6.0.0 directly and measures with Noir 1.0.0.
- **`noirfmt.toml`** keeps import order as written (`reorder_imports = false`).
- **Release Please starts at 0.1.0** (`initial-version`), not at the template's
  0.0.0.
- **Workflows trigger on `main`**, not `master`, and third-party actions are
  pinned by commit.
