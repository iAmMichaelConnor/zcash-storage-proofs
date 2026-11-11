// Host defence in depth for installCapsules and authorizePrepared.
// Host execution only: no nargo, proof, PXE or Aztec transaction. The contract
// must still enforce its own accepted checkpoint; these checks do not replace it.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  prepareContents,
  prepareInclusion,
  prepareNullifierAbsence,
  prepareMemoCreatedInBlock,
  prepareNullifierInclusion,
  authorizePrepared,
  PreparationError,
} from "../dist/index.js";
import { installCapsules, installClaims } from "../dist/aztec.js";

const read = (url) =>
  JSON.parse(fs.readFileSync(new URL(url, import.meta.url)));
const fixture = (n) => read("fixtures/" + n);
const at = { contractAddress: "4660", actions: 1, depth: 32 };
const scan = (profileId, extra = {}, blocks = fixture("blocks.v1.json")) =>
  prepareNullifierAbsence(blocks, {
    profileId,
    contractAddress: "4660",
    queriedNullifierLE: "05" + "00".repeat(31),
    allowExperimentalProfile: true,
    ...extra,
  });
const STATE = "nullifier-absence-state-2b-4t-2a-256r-v1";
// Honest witnesses of every claim.
const HONEST = {
  contents: () => prepareContents(fixture("contents.v1.json"), at),
  "contents+native hints": () => {
    // Same slot set as prepareContentsWithNative({includeHintCapsules: true});
    // the circuit, not the host, checks the hint payloads.
    const p = prepareContents(fixture("contents.v1.json"), at);
    for (let slot = 70; slot <= 102; slot++)
      p.capsules.push({ ...p.capsules[1], slot, fields: ["0", "1"] });
    return p;
  },
  action: () => {
    const x = fixture("created.v1.json");
    x.kind = "action-inclusion";
    delete x.note;
    return prepareInclusion(x, at);
  },
  created: () => prepareInclusion(fixture("created.v1.json"), at),
  "nullifier in transaction": () => {
    const x = fixture("created.v1.json");
    x.kind = "action-inclusion";
    delete x.note;
    return prepareNullifierInclusion(x, { ...at, actions: 4 });
  },
  memo: () =>
    prepareMemoCreatedInBlock(
      read("fixtures/memo-host-input.json"),
      at,
    ),
  "scan r=0": () => scan("nullifier-absence-2b-4t-2a-0r-v1"),
  "scan r>0": () => scan("nullifier-absence-2b-4t-2a-256r-v1"),
  "scan window begin": () => scan(STATE),
  "scan window extend": () => {
    const b = fixture("blocks.v1.json"),
      prior = b.blocks.shift();
    return scan(STATE, { operation: "extend", priorHeight: prior.height }, b);
  },
};
// The wallet approves exactly the honest checkpoint and network.
function strictPolicy(w) {
  const calls = [];
  return {
    calls,
    async authorize(c, p) {
      calls.push(c);
      if (
        c.hashLE !== w.checkpoint.hashLE ||
        c.height !== w.checkpoint.height ||
        p.network !== w.protocol.network
      )
        throw new Error("unaccepted checkpoint");
    },
  };
}
// A forged witness fails with `code` in both entry points, before the policy
// runs and before any capsule is written.
async function rejects(honest, mutate, code) {
  const forged = structuredClone(honest);
  mutate(forged);
  for (const entry of [
    (p) => installCapsules(forged, "9", { setCapsule: assert.fail }, p),
    (p) => authorizePrepared(forged, p),
  ]) {
    const policy = strictPolicy(honest);
    await assert.rejects(
      () => entry(policy),
      (e) => e instanceof PreparationError && e.code === code,
    );
    assert.equal(policy.calls.length, 0, "policy must not run");
  }
}
const flip = (fields, i) => (fields[i] = String((Number(fields[i]) + 1) % 256));

test("honest witnesses of every claim install and return frozen arguments", async () => {
  for (const [name, make] of Object.entries(HONEST)) {
    // A JSON round trip stands in for a CLI-written prepared.json.
    const w = JSON.parse(JSON.stringify(make())),
      writes = [];
    const args = await installCapsules(
      structuredClone(w),
      "9",
      { setCapsule: async (c) => writes.push(c) },
      strictPolicy(w),
    );
    assert.deepEqual(args, w.arguments, name);
    assert.ok(
      Object.values(args).every(
        (v) => typeof v !== "object" || v.every((x) => typeof x === "number"),
      ),
      name,
    );
    assert.ok(
      Object.isFrozen(args) && Object.values(args).every(Object.isFrozen),
      name,
    );
    assert.deepEqual(
      writes.map((c) => [c.slot, c.fields]),
      w.capsules.map((c) => [c.slot, c.fields]),
      name,
    );
    assert.ok(
      writes.every((c) => c.contractAddress === "9"),
      name,
    );
    assert.deepEqual(
      await authorizePrepared(w, strictPolicy(w)),
      w.arguments,
      name,
    );
  }
});

// [witnesses, forgery, expected code]. Each forgery must fail in both entry
// points before the policy runs.
const C = ["contents"],
  INCL = ["action", "created", "memo", "nullifier in transaction"],
  SCAN = ["scan r=0", "scan r>0", "scan window begin", "scan window extend"],
  WINDOW = ["scan window begin", "scan window extend"],
  BIND = "ARGUMENT_BINDING",
  SLOTS = "CAPSULE_SLOTS";
const stray = (slot) => (f) => f.capsules.push({ ...f.capsules.at(-1), slot });
const NEGATIVES = [
  [C, (f) => (f.arguments.expected_hash[31] ^= 1), BIND],
  [C, (f) => (f.arguments.header_height += 1), BIND],
  [
    C,
    (f) => (f.arguments.header_height = String(f.arguments.header_height)),
    BIND,
  ],
  [C, (f) => (f.arguments.is_testnet = true), BIND],
  // Wrapper objects: new Boolean(false) serialises as false but is truthy, and
  // the Aztec ABI encoder encodes it as 1. Strict equality rejects every wrapper.
  [[...C, ...SCAN], (f) => (f.arguments.is_testnet = new Boolean(false)), BIND],
  [
    C,
    (f) => (f.arguments.header_height = new Number(f.arguments.header_height)),
    BIND,
  ],
  [
    C,
    (f) => (f.arguments.header_height = new String(f.arguments.header_height)),
    BIND,
  ],
  [
    C,
    (f) =>
      (f.arguments.expected_hash[0] = new Number(f.arguments.expected_hash[0])),
    BIND,
  ],
  [
    SCAN,
    (f) =>
      (f.arguments.expected_tip_height = new Number(
        f.arguments.expected_tip_height,
      )),
    BIND,
  ],
  [
    INCL,
    (f) =>
      (f.arguments.accepted_header_hash = [
        ...f.arguments.accepted_header_hash,
      ].join()),
    BIND,
  ],
  [C, (f) => delete f.arguments.is_testnet, BIND],
  [C, (f) => (f.arguments.extra = 1), "UNKNOWN_FIELD"],
  [C, (f) => flip(f.capsules[0].fields, 200), "HEADER_HASH"],
  [C, (f) => (f.capsules[0].fields[0] = "256"), "HEADER_HASH"],
  // Moving the checkpoint to forged arguments fails the header check.
  [
    C,
    (f) => (
      (f.checkpoint.hashLE = "ab".repeat(32)),
      (f.arguments.expected_hash = Array(32).fill(0xab))
    ),
    "HEADER_HASH",
  ],
  [INCL, (f) => (f.arguments.accepted_header_hash[0] ^= 1), BIND],
  [INCL, (f) => (f.arguments.is_testnet = false), "UNKNOWN_FIELD"],
  [INCL, (f) => flip(f.capsules[0].fields, 100), "HEADER_HASH"],
  [SCAN, (f) => (f.arguments.expected_tip_hash[0] ^= 1), BIND],
  [SCAN, (f) => (f.arguments.expected_tip_height = 0xffffffff), BIND],
  [SCAN, (f) => (f.arguments.is_testnet = !f.arguments.is_testnet), BIND],
  [SCAN, (f) => (f.arguments.extra = 0), "UNKNOWN_FIELD"],
  [["scan r=0"], (f) => (f.arguments.count = 2), "UNKNOWN_FIELD"],
  // Free arguments keep their type checks; the circuit checks their values.
  [SCAN, (f) => (f.arguments.queried_nf = "not bytes"), "LENGTH"],
  [SCAN, (f) => (f.arguments.queried_nf[0] = new Number(5)), "RANGE"],
  [WINDOW, (f) => (f.arguments.count = new Number(f.arguments.count)), "RANGE"],
  [
    ["scan window extend"],
    (f) => (f.arguments.prior_height = String(f.arguments.prior_height)),
    "RANGE",
  ],
  [[...C, ...INCL.slice(1), "scan r=0"], stray(64), SLOTS],
  [[...C, ...INCL.slice(1), "scan r=0"], stray(102), SLOTS],
  [["action"], stray(69), SLOTS],
  [["created"], stray(70), SLOTS],
  [["memo", "contents+native hints"], (f) => f.capsules.pop(), SLOTS],
  [["scan window begin"], (f) => (f.capsules[0].slot = 63), SLOTS],
  [
    C,
    (f) => f.capsules.push(structuredClone(f.capsules[1])),
    "CAPSULE_DUPLICATE",
  ],
  [C, (f) => (f.claim = "owned"), "UNSUPPORTED_CLAIM"],
  [C, (f) => (f.claim = "toString"), "UNSUPPORTED_CLAIM"],
  [C, (f) => (f.claim = new String("contents")), "UNSUPPORTED_CLAIM"],
  [C, (f) => (f.claim = ["contents"]), "UNSUPPORTED_CLAIM"],
  [C, (f) => (f.kind = "contents"), "SCHEMA_VERSION"],
  [C, (f) => (f.protocol.network = "regtest"), "NETWORK"],
];
test("forged arguments, header capsules, slot sets and claims are rejected", async () => {
  for (const [names, mutate, code] of NEGATIVES)
    for (const name of names) await rejects(HONEST[name](), mutate, code);
  for (const input of [null, "x", [HONEST.contents()]])
    await assert.rejects(
      () => authorizePrepared(input, strictPolicy(HONEST.contents())),
      (e) => e instanceof PreparationError && e.code === "TYPE",
    );
});

test("the policy and installer use one copy taken before any await", async () => {
  const honest = HONEST.contents(),
    live = structuredClone(honest),
    writes = [];
  let seen;
  const args = await installCapsules(
    live,
    "9",
    { setCapsule: async (c) => writes.push(structuredClone(c)) },
    {
      async authorize(c, p) {
        await strictPolicy(honest).authorize(c, p);
        seen = c;
        // Change the caller's object after the policy decision.
        live.checkpoint.hashLE = "00".repeat(32);
        live.arguments.header_height = 1;
        live.capsules[0].fields[200] = "0";
        live.capsules.push({ ...live.capsules[1], slot: 110 });
      },
    },
  );
  assert.deepEqual(args, honest.arguments);
  assert.deepEqual(
    writes.map((c) => [c.slot, c.fields]),
    honest.capsules.map((c) => [c.slot, c.fields]),
  );
  assert.ok(Object.isFrozen(seen) && seen !== live.checkpoint);
  assert.throws(() => (args.expected_hash[0] = 1), TypeError);
});

// One slot has one layout, and claim indices separate
// several claims at one address. A PXE serves the first capsule that matches
// (address, slot, scope), so a reused key silently serves the wrong witness.
const collect = () => {
  const writes = [];
  return { writes, transport: { setCapsule: async (c) => writes.push(c) } };
};
const anyPolicy = { async authorize() {} };
test("memo and native-hint contents witnesses share one address and claim", async () => {
  const { writes, transport } = collect();
  const memo = HONEST.memo(),
    contents = HONEST["contents+native hints"]();
  await installClaims(
    [
      { prepared: memo, targetAddress: "9" },
      { prepared: contents, targetAddress: "9" },
    ],
    transport,
    anyPolicy,
  );
  const slots = writes.map((c) => c.slot);
  assert.equal(new Set(slots).size, slots.length);
  assert.equal(writes.find((c) => c.slot === 103).fields.length, 555 + 724);
  assert.deepEqual(
    writes.find((c) => c.slot === 70).fields,
    contents.capsules.find((c) => c.slot === 70).fields,
  );
});
test("two claims at one address need distinct claim indices", async () => {
  const { writes, transport } = collect();
  const [a, b] = [HONEST.memo(), HONEST.created()];
  const args = await installClaims(
    [
      { prepared: a, targetAddress: "9" },
      { prepared: b, targetAddress: "9", claim: 1 },
    ],
    transport,
    anyPolicy,
  );
  assert.deepEqual(args, [a.arguments, b.arguments]);
  assert.deepEqual(
    writes.map((c) => c.slot),
    [68, 69, 103, 68 + 256, 69 + 256],
  );
  assert.deepEqual(writes[3].fields, b.capsules[0].fields);
  // The same claim index twice: rejected before any capsule is written.
  for (const claim of [0, 1]) {
    const { writes: none, transport: t } = collect();
    await assert.rejects(
      () =>
        installClaims(
          [
            { prepared: HONEST.memo(), targetAddress: "9", claim },
            { prepared: HONEST.created(), targetAddress: "9", claim },
          ],
          t,
          anyPolicy,
        ),
      (e) => e instanceof PreparationError && e.code === "CAPSULE_DUPLICATE",
    );
    assert.equal(none.length, 0);
  }
  for (const [prepared, claim] of [
    [HONEST["scan r=0"](), 1],
    [HONEST.memo(), -1],
    [HONEST.memo(), 1.5],
    [HONEST.memo(), 2 ** 24],
  ])
    await assert.rejects(
      () =>
        installClaims(
          [{ prepared, targetAddress: "9", claim }],
          collect().transport,
          anyPolicy,
        ),
      (e) => e instanceof PreparationError && e.code === "CAPSULE_CLAIM",
    );
});
// Nullifier inclusion reads the slot-68 inclusion layout.
test("nullifier inclusion uses the slot-68 inclusion witness", () => {
  const x = fixture("created.v1.json");
  x.kind = "action-inclusion";
  delete x.note;
  const opts = { ...at, actions: 4 },
    n = prepareNullifierInclusion(structuredClone(x), opts),
    i = prepareInclusion(structuredClone(x), opts);
  assert.equal(n.claim, "nullifier-in-transaction");
  assert.deepEqual(n.capsules, i.capsules);
  assert.equal(n.capsules[0].fields.length, 1680 + 148 * 4 + 32 * 32);
  assert.deepEqual(n.arguments, {
    expected_nf: i.expected.selectedAction.slice(0, 32),
    accepted_header_hash: i.arguments.accepted_header_hash,
  });
  assert.throws(
    () => prepareNullifierInclusion(fixture("created.v1.json"), opts),
    (e) => e instanceof PreparationError && e.code === "UNSUPPORTED_CLAIM",
  );
  for (const bad of [at, { ...opts, depth: 31 }])
    assert.throws(
      () => prepareNullifierInclusion(structuredClone(x), bad),
      (e) => e instanceof PreparationError && e.code === "PROFILE_CAPACITY",
    );
});
