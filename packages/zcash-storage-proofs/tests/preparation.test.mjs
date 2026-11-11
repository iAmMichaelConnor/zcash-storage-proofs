import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import {
  prepareContents,
  validateContents,
  prepareInclusion,
  validateTransaction,
  parseRawTransaction,
  inspectRawTransaction,
  inspectRawBlock,
  prepareRawBlocks,
  transactionRoot,
  effectsTxid,
  rpcHashToLE,
  serializeCapsules,
  parseCapsules,
  PreparationError,
  fetchCompleteBlocks,
} from "../dist/index.js";
import { installCapsules } from "../dist/aztec.js";
const fixture = (n) =>
  JSON.parse(
    fs.readFileSync(
      new URL("fixtures/" + n, import.meta.url),
    ),
  );
const contents = () => fixture("contents.v1.json"),
  created = () => fixture("created.v1.json");
const code = (f, c) =>
  assert.throws(f, (e) => e instanceof PreparationError && e.code === c);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ironwood-host-test-"));
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));
test("contents reproduces exact prior private ABI capsules and omits all wallet keys", () => {
  const p = prepareContents(contents(), { contractAddress: "4660" }),
    gold = fixture("contents-expected.json");
  assert.deepEqual(
    p.capsules.map((c) => c.fields),
    gold.capsules.map((xs) => xs.map(String)),
  );
  assert.equal(p.arguments.header_height, 3428151);
  assert.equal(p.validation.checkpointAuthorized, false);
  assert.equal(p.validation.proofVerified, false);
  assert.deepEqual(parseCapsules(serializeCapsules(p.capsules)), p.capsules);
});
for (const [name, mut, expected] of [
  ["schema", (x) => (x.schemaVersion = 2), "SCHEMA_VERSION"],
  ["pool", (x) => (x.protocol.pool = "orchard"), "UNSUPPORTED_PROTOCOL"],
  ["network", (x) => (x.protocol.network = "regtest"), "NETWORK"],
  ["policy", (x) => (x.checkpoint.policyId = ""), "CHECKPOINT_POLICY"],
  ["wallet key", (x) => (x.note.spendingKey = "secret"), "UNKNOWN_FIELD"],
  [
    "field alias",
    (x) =>
      (x.note.rho = ["402183922140359270320256538385973249", "34", "16384"]),
    "NONCANONICAL",
  ],
  ["bad limb", (x) => (x.note.rho[0] = (1n << 120n).toString()), "RANGE"],
  ["bad value", (x) => (x.note.value = "18446744073709551616"), "RANGE"],
  ["unsafe number", (x) => (x.note.value = 5000), "INTEGER"],
  ["noncanonical decimal", (x) => (x.note.value = "05000"), "INTEGER"],
  [
    "off curve",
    (x) =>
      (x.note.receiver.g_d.y[0] = (
        BigInt(x.note.receiver.g_d.y[0]) + 1n
      ).toString()),
    "CURVE",
  ],
  ["depth", (x) => x.membership.siblings.pop(), "LENGTH"],
  ["negative position", (x) => (x.membership.position = -1), "RANGE"],
  [
    "uppercase",
    (x) => (x.note.rseedHex = x.note.rseedHex.toUpperCase() + "AA"),
    "HEX",
  ],
  [
    "reverse hash",
    (x) => (x.checkpoint.hashLE = rpcHashToLE(x.checkpoint.hashLE)),
    "HEADER_HASH",
  ],
  ["height", (x) => x.checkpoint.height++, "HISTORY_EPOCH"],
  [
    "auth root",
    (x) => (x.header.authRootHex = "01".repeat(32)),
    "HISTORY_COMMITMENT",
  ],
  [
    "history padding",
    (x) =>
      (x.header.historyNodeHex = x.header.historyNodeHex.slice(0, -2) + "01"),
    "HISTORY_PADDING",
  ],
])
  test("contents rejects " + name, () => {
    const x = contents();
    mut(x);
    code(() => prepareContents(x, { contractAddress: "4660" }), expected);
  });
test("created-in-block exact capsule and argument ABI equivalence", () => {
  const p = prepareInclusion(created(), {
      contractAddress: "4660",
      actions: 1,
      depth: 32,
    }),
    gold = fixture("created-expected.json");
  assert.deepEqual(
    p.capsules.map((c) => c.fields),
    gold.capsules.map((xs) => xs.map(String)),
  );
  assert.deepEqual(Object.keys(p.arguments), ["accepted_header_hash"]);
  code(
    () =>
      prepareInclusion(created(), {
        contractAddress: "4660",
        actions: 0,
        depth: 32,
      }),
    "PROFILE_ACTION_CAPACITY",
  );
  const bad = created();
  bad.note.rho = ["0", "0", "0"];
  code(
    () =>
      prepareInclusion(bad, { contractAddress: "4660", actions: 1, depth: 32 }),
    "NOTE_RHO",
  );
});
// A one-transaction block whose transaction has `n` Actions, built from the
// created fixture's first Action. The txid and header hash are recomputed.
function actionBlock(n) {
  const { createHash } = crypto;
  const sha256d = (b) =>
    createHash("sha256")
      .update(createHash("sha256").update(b).digest())
      .digest();
  const c = created();
  delete c.note;
  c.kind = "action-inclusion";
  const first = c.transaction.effects.compact_actions[0];
  c.transaction.effects.compact_actions = Array.from({ length: n }, (_, i) =>
    first.map((x, j) => (j === 0 ? (x + i) % 256 : x)),
  );
  c.transaction.txidLE = effectsTxid(6, c.transaction.effects);
  const header = Buffer.from(c.headerHex, "hex");
  Buffer.from(c.transaction.txidLE, "hex").copy(header, 36);
  c.headerHex = header.toString("hex");
  c.checkpoint.hashLE = sha256d(header).toString("hex");
  c.actionIndex = n - 1;
  c.transactionIndex = 0;
  c.transactionCount = 1;
  c.siblings = [];
  return c;
}
test("inclusion pads a 2-Action transaction to capacity 4 and appends action_count", () => {
  const c = actionBlock(2);
  const p = prepareInclusion(c, {
    contractAddress: "4660",
    actions: 4,
    depth: 32,
  });
  const f = p.capsules[0].fields.map(Number);
  assert.equal(f.length, 1680 + 148 * 4 + 32 * 32);
  const actions = c.transaction.effects.compact_actions;
  assert.deepEqual(f.slice(1487, 1487 + 148), actions[0]);
  assert.deepEqual(f.slice(1487 + 148, 1487 + 296), actions[1]);
  assert.ok(f.slice(1487 + 296, 1487 + 592).every((x) => x === 0));
  assert.deepEqual(
    f.slice(1487 + 592, 1487 + 592 + 32),
    c.transaction.effects.memos_digest,
  );
  assert.deepEqual(
    f.slice(-16),
    [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0],
  );
  assert.equal(p.expected.actionCount, 2);
  assert.equal(p.expected.actionCapacity, 4);
  code(
    () =>
      prepareInclusion(actionBlock(5), {
        contractAddress: "4660",
        actions: 4,
        depth: 32,
      }),
    "PROFILE_ACTION_CAPACITY",
  );
});
test("action-only witness carries no note secret", () => {
  const c = created();
  delete c.note;
  c.kind = "action-inclusion";
  const p = prepareInclusion(c, {
    contractAddress: "4660",
    actions: 1,
    depth: 32,
  });
  assert.equal(p.capsules.length, 1);
  assert.equal(p.capsules[0].slot, 68);
});
test("upstream ZIP244 raw vectors match all ten raw digest IDs", () => {
  for (const v of fixture("zip_0244.json").slice(2)) {
    const tx = inspectRawTransaction(v[0]);
    assert.equal(tx.transaction.txidLE, rpcHashToLE(v[1]));
    code(() => parseRawTransaction(v[0]), "UNSUPPORTED_PROTOCOL");
  }
});
test("native cached transfer raw V6 agrees with independent Python digest", () => {
  const f = fixture("raw-v6-transfer.json");
  const t = parseRawTransaction(f.rawHex);
  assert.equal(t.txidLE, f.expectedTxidLE);
  assert.equal(t.effects.compact_actions.length, 1);
  assert.deepEqual(validateTransaction(t), t);
  code(() => parseRawTransaction(f.rawHex + "00"), "TRAILING_BYTES");
  code(() => parseRawTransaction(f.rawHex.slice(0, -2)), "TRUNCATED");
});
test("mined historical mainnet block parses all transactions and binds exact header root", () => {
  const raw = fs
      .readFileSync(
        new URL(
          "fixtures/mined-mainnet-1687106.hex",
          import.meta.url,
        ),
        "utf8",
      )
      .trim(),
    b = inspectRawBlock(raw);
  assert.equal(b.transactions.length, 5);
  assert.deepEqual(
    b.transactions.map((t) => t.transaction.version),
    [5, 5, 5, 5, 4],
  );
  assert.equal(
    transactionRoot(b.transactions.map((t) => t.transaction.txidLE)),
    b.headerHex.slice(72, 136),
  );
  assert.equal(
    rpcHashToLE(b.hashLE),
    "00000000017d40c50ef7f27bd2e997ed5d1009a332e4fa85b9939652b8dd516b",
  );
  code(
    () =>
      prepareRawBlocks({
        schemaVersion: 1,
        kind: "raw-blocks",
        protocol: contents().protocol,
        checkpoint: {
          height: 1687106,
          hashLE: b.hashLE,
          policyId: "historical-reference-only",
        },
        blocks: [{ height: 1687106, rawHex: raw }],
      }),
    "UNSUPPORTED_PROTOCOL",
  );
});
test("transparent outpoints, output amounts and scripts remain full-width inspection data", () => {
  const b = inspectRawBlock(
    fs
      .readFileSync(
        new URL(
          "fixtures/mined-mainnet-1687106.hex",
          import.meta.url,
        ),
        "utf8",
      )
      .trim(),
  );
  for (const t of b.transactions) {
    for (const o of t.transparent.outputs) {
      assert.equal(typeof o.value, "string");
      assert.ok(/^[0-9a-f]*$/.test(o.scriptPubKeyHex));
    }
    for (const i of t.transparent.inputs)
      assert.equal(i.outpointTxidLE.length, 64);
  }
});
test("host rejects malformed CompactSize and raw version without guessing an era", () => {
  code(() => inspectRawTransaction("01000000"), "TRANSACTION_VERSION");
  const v = fixture("raw-v6-transfer.json").rawHex;
  code(
    () => inspectRawTransaction(v.slice(0, 40) + "fd0000" + v.slice(42)),
    "NONCANONICAL",
  );
});
test("complete tree rejects duplicate transactions and requires nonempty data", () => {
  code(() => transactionRoot([]), "EMPTY_BLOCK");
  code(
    () => transactionRoot(["00".repeat(32), "00".repeat(32)]),
    "DUPLICATE_TXID",
  );
});
test("capsule schema rejects field aliases and duplicate keys", () => {
  const p = prepareContents(contents(), { contractAddress: "4660" });
  code(
    () => serializeCapsules([p.capsules[0], p.capsules[0]]),
    "CAPSULE_DUPLICATE",
  );
  p.capsules[0].fields[0] =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
  code(() => serializeCapsules(p.capsules), "RANGE");
});
test("Aztec transport authorizes before any write and explicitly rebinds address", async () => {
  const p = prepareContents(contents(), { contractAddress: "4660" }),
    events = [];
  await installCapsules(
    p,
    "9",
    {
      setCapsule: async (c) => {
        assert.equal(c.contractAddress, "9");
        events.push(c.slot);
      },
    },
    {
      authorize: async (c, protocol) => {
        assert.equal(c.policyId, "test-only/synthetic-checkpoint");
        assert.equal(protocol.network, "mainnet");
        events.push("authorize");
      },
    },
  );
  assert.deepEqual(events, ["authorize", 60, 61]);
  let writes = 0;
  await assert.rejects(() =>
    installCapsules(
      p,
      "9",
      {
        setCapsule: async () => {
          writes++;
        },
      },
      {
        authorize: async () => {
          throw Error("unaccepted checkpoint");
        },
      },
    ),
  );
  assert.equal(writes, 0);
});
test("RPC acquisition refuses implicit checkpoint substitution before fetching raw block", async () => {
  const calls = [];
  await assert.rejects(
    () =>
      fetchCompleteBlocks(
        {
          request: async (method) => {
            calls.push(method);
            return "00".repeat(32);
          },
        },
        {
          protocol: contents().protocol,
          checkpoint: contents().checkpoint,
          startHeight: contents().checkpoint.height,
          maxBlocks: 1,
        },
      ),
    (e) => e.code === "CHECKPOINT",
  );
  assert.deepEqual(calls, ["getblockhash"]);
});
test("pure import works from empty directory and starts no external processes", () => {
  const before = fs.readdirSync(dir),
    file = new URL("../dist/index.js", import.meta.url).href;
  const r = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", `await import(${JSON.stringify(file)});`],
    { cwd: dir, env: { PATH: "" }, encoding: "utf8" },
  );
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(fs.readdirSync(dir), before);
});
test("CLI writes explicit new output only and rejects overwrite", () => {
  const input = path.join(dir, "input.json"),
    output = path.join(dir, "prepared.json");
  fs.writeFileSync(input, JSON.stringify(contents()));
  const cli = new URL("../bin/ironwood-prepare.mjs", import.meta.url)
      .pathname,
    args = [
      cli,
      "prepare",
      "--input",
      input,
      "--output",
      output,
      "--contract-address",
      "4660",
    ];
  const good = spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.equal(good.status, 0, good.stderr);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  const digest = fs.readFileSync(output, "utf8");
  assert.notEqual(spawnSync(process.execPath, args).status, 0);
  assert.equal(fs.readFileSync(output, "utf8"), digest);
});

test("SDK AztecAddress string normalizes without truncating field aliases", () => {
  const p = prepareContents(contents(), {
    contractAddress: "0x" + "1234".padStart(64, "0"),
  });
  assert.equal(p.contractAddress, "4660");
  code(
    () =>
      prepareContents(contents(), { contractAddress: "0x" + "f".repeat(64) }),
    "RANGE",
  );
});

test("scan encoding preserves complete counts, rejects truncation and absent prefixes", async () => {
  const { prepareNullifierAbsence } = await import("../dist/index.js");
  const b = fixture("blocks.v1.json"),
    options = {
      profileId: "nullifier-absence-2b-4t-2a-0r-v1",
      contractAddress: "4660",
      queriedNullifierLE: "05" + "00".repeat(31),
      allowExperimentalProfile: true,
    };
  const p = prepareNullifierAbsence(b, options);
  assert.equal(p.capsules[0].slot, 63);
  assert.equal(p.capsules[0].fields.length, 6830);
  assert.equal(p.capsules[0].fields[1487], "2");
  assert.equal(p.validation.proofVerified, false);
  const omitted = structuredClone(b);
  omitted.blocks[1].transactions.pop();
  code(() => prepareNullifierAbsence(omitted, options), "BLOCK_MERKLE");
  const shorter = structuredClone(b);
  shorter.blocks.shift();
  code(() => prepareNullifierAbsence(shorter, options), "EXACT_BLOCK_COUNT");
  const found = b.blocks[0].transactions[1].effects.compact_actions[0]
    .slice(0, 32)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
  code(
    () => prepareNullifierAbsence(b, { ...options, queriedNullifierLE: found }),
    "NULLIFIER_PRESENT",
  );
  // Nf + p is never on chain, so a scan would "prove" it absent.
  const P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;
  const le = (x) =>
    Array.from({ length: 32 }, (_, i) =>
      Number((x >> BigInt(8 * i)) & 255n)
        .toString(16)
        .padStart(2, "0"),
    ).join("");
  const nf = BigInt("0x" + found.match(/../g).reverse().join(""));
  assert.ok(nf + P < 1n << 256n);
  for (const alias of [nf + P, P])
    code(
      () => prepareNullifierAbsence(b, { ...options, queriedNullifierLE: le(alias) }),
      "NONCANONICAL_NULLIFIER",
    );
  assert.equal(
    prepareNullifierAbsence(b, { ...options, queriedNullifierLE: le(P - 1n) }).arguments
      .queried_nf.length,
    32,
  );
});

test("scan preparation rejects what the circuit rejects: unpinned parent, testnet tip past NU6.3", async () => {
  const { prepareNullifierAbsence, preActivationHashLE } = await import(
    "../dist/index.js"
  );
  const base = {
    contractAddress: "4660",
    queriedNullifierLE: "05" + "00".repeat(31),
    allowExperimentalProfile: true,
  };
  const stateless = { ...base, profileId: "nullifier-absence-2b-4t-2a-0r-v1" };
  const state = { ...base, profileId: "nullifier-absence-state-2b-4t-2a-256r-v1" };
  // The pinned hashes equal the constants in nullifier_absence.nr (internal byte order).
  const nr = fs.readFileSync(
    new URL("../../../noir/ironwood/src/transactions/nullifier_absence.nr", import.meta.url),
    "utf8",
  );
  const pinNr = (name) =>
    Buffer.from(
      nr
        .match(new RegExp(name + "[^=]*= \\[([^\\]]+)\\]"))[1]
        .split(",")
        .filter((x) => x.trim() !== "")
        .map((x) => Number(x.trim())),
    ).toString("hex");
  assert.equal(
    preActivationHashLE("mainnet"),
    pinNr("MAINNET_PRE_ACTIVATION_HASH"),
  );
  assert.equal(
    preActivationHashLE("testnet"),
    pinNr("TESTNET_PRE_ACTIVATION_HASH"),
  );
  // Both networks start from their pinned predecessor.
  for (const options of [stateless, state]) {
    assert.equal(
      prepareNullifierAbsence(fixture("blocks.v1.json"), options).arguments.is_testnet,
      false,
    );
    assert.equal(
      prepareNullifierAbsence(fixture("blocks-testnet.v1.json"), options).arguments
        .is_testnet,
      true,
    );
    // A consistent chain whose first block links to another parent.
    code(
      () => prepareNullifierAbsence(fixture("blocks-synthetic-parent.v1.json"), options),
      "NULLIFIER_ABSENCE_PREDECESSOR",
    );
    // The mainnet chain under the testnet label (heights follow the label).
    const relabelled = fixture("blocks.v1.json");
    relabelled.protocol.network = "testnet";
    relabelled.blocks.forEach((b, i) => (b.height = 4134000 + i));
    relabelled.checkpoint.height = 4134001;
    code(() => prepareNullifierAbsence(relabelled, options), "NULLIFIER_ABSENCE_PREDECESSOR");
  }
  // An extension has a trusted prior, so its first block has no pinned parent.
  const later = fixture("blocks-synthetic-parent.v1.json");
  assert.equal(
    prepareNullifierAbsence(later, { ...state, operation: "extend", priorHeight: 3428142 })
      .operation,
    "extend",
  );
  // Testnet NU7 starts at 4,465,026: a window may end at 4,465,025, not after.
  const window = (tip) => {
    const w = fixture("blocks-testnet.v1.json");
    w.blocks.forEach((b, i) => (b.height = tip - 1 + i));
    w.checkpoint.height = tip;
    return w;
  };
  const extend = (tip) => ({
    ...state,
    operation: "extend",
    priorHeight: tip - 2,
  });
  assert.equal(
    prepareNullifierAbsence(window(4465025), extend(4465025)).arguments.expected_tip_height,
    4465025,
  );
  code(() => prepareNullifierAbsence(window(4465026), extend(4465026)), "NULLIFIER_ABSENCE_EPOCH");
  // Mainnet has no epoch end yet.
  const mainnetLate = fixture("blocks-synthetic-parent.v1.json");
  mainnetLate.blocks.forEach((b, i) => (b.height = 4465026 + i));
  mainnetLate.checkpoint.height = 4465027;
  assert.equal(
    prepareNullifierAbsence(mainnetLate, {
      ...state,
      operation: "extend",
      priorHeight: 4465025,
    }).arguments.is_testnet,
    false,
  );
});

test("runTool keeps its private copy in a caller-chosen directory", async () => {
  const { runTool } = await import("../dist/toolchain.js");
  const { createHash } = await import("node:crypto");
  const t = fs.mkdtempSync(path.join(os.tmpdir(), "ironwood-tooldir-test-"));
  try {
    const body = '#!/bin/sh\necho "$0"\n';
    const tool = path.join(t, "self.sh");
    fs.writeFileSync(tool, body, { mode: 0o700 });
    const spec = {
      path: tool,
      sha256: createHash("sha256").update(body).digest("hex"),
    };
    const holder = path.join(t, "exec-ok");
    fs.mkdirSync(holder, { mode: 0o700 });
    const r = await runTool(spec, [], { cwd: t, toolDirectory: holder });
    assert.equal(path.dirname(path.dirname(r.stdout.trim())), holder);
    assert.deepEqual(fs.readdirSync(holder), []);
    await assert.rejects(
      () => runTool(spec, [], { cwd: t, toolDirectory: "relative/dir" }),
      (e) => e.code === "OUTPUT_PATH",
    );
    await assert.rejects(
      () =>
        runTool(spec, [], { cwd: t, toolDirectory: path.join(t, "missing") }),
      (e) => e.code === "ENOENT",
    );
  } finally {
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("tool adapter retains bounded diagnostics for explicit caller inspection", async () => {
  const { runTool, ToolExecutionError } = await import(
    "../dist/toolchain.js"
  );
  const { createHash } = await import("node:crypto");
  const tool = {
    path: process.execPath,
    sha256: createHash("sha256")
      .update(fs.readFileSync(process.execPath))
      .digest("hex"),
  };
  await assert.rejects(
    () =>
      runTool(
        tool,
        [
          "-e",
          'process.stdout.write("example-out");process.stderr.write("example-error");process.exit(7)',
        ],
        { cwd: dir },
      ),
    (e) =>
      e instanceof ToolExecutionError &&
      e.exitCode === 7 &&
      e.stdout === "example-out" &&
      e.stderr === "example-error",
  );
  await assert.rejects(
    () =>
      runTool(tool, ["-e", 'process.stdout.write("x".repeat(10000))'], {
        cwd: dir,
        maxOutputBytes: 31,
      }),
    (e) =>
      e.code === "TOOL_OUTPUT" &&
      Buffer.byteLength(e.stdout) + Buffer.byteLength(e.stderr) <= 31,
  );
});

test("tool adapter pins one private copy and a minimal environment", async () => {
  const { runTool, verifyTool } = await import("../dist/toolchain.js");
  const { createHash } = await import("node:crypto");
  const pin = (b) => createHash("sha256").update(b).digest("hex");
  const t = fs.mkdtempSync(path.join(os.tmpdir(), "ironwood-tool-test-"));
  try {
    const good = "#!/bin/sh\necho good\n",
      evil = "#!/bin/sh\necho EVIL\n";
    const goodPath = path.join(t, "good.sh");
    fs.writeFileSync(goodPath, good, { mode: 0o700 });
    fs.writeFileSync(path.join(t, "evil.sh"), evil, { mode: 0o700 });
    // A symbolic link is rejected even when its target matches the pin.
    fs.symlinkSync(goodPath, path.join(t, "link"));
    await assert.rejects(
      () => verifyTool({ path: path.join(t, "link"), sha256: pin(good) }),
      (e) => e.code === "TOOL_PATH",
    );
    // A group- or world-writable tool is rejected.
    const writable = path.join(t, "writable.sh");
    fs.writeFileSync(writable, good);
    fs.chmodSync(writable, 0o777);
    await assert.rejects(
      () => runTool({ path: writable, sha256: pin(good) }, [], { cwd: t }),
      (e) => e.code === "TOOL_PATH",
    );
    // The process runs from a private copy: a swap of the checked path after
    // the hash check cannot change what runs. The tool reports its own path.
    const self = path.join(t, "self.sh");
    const selfBody = '#!/bin/sh\necho "$0"\n';
    fs.writeFileSync(self, selfBody, { mode: 0o700 });
    const r = await runTool({ path: self, sha256: pin(selfBody) }, [], {
      cwd: t,
    });
    assert.notEqual(r.stdout.trim(), self);
    assert.ok(!fs.existsSync(path.dirname(r.stdout.trim())));
    // Dynamic-loader keys never reach the tool, also when the caller passes them.
    const envBody = "#!/bin/sh\nenv\n";
    const envTool = path.join(t, "env.sh");
    fs.writeFileSync(envTool, envBody, { mode: 0o700 });
    const saved = process.env.LD_PRELOAD;
    process.env.LD_PRELOAD = "/nonexistent/evil.so";
    process.env.IRONWOOD_TEST_SECRET = "inherited";
    try {
      const e = await runTool({ path: envTool, sha256: pin(envBody) }, [], {
        cwd: t,
        env: {
          LD_LIBRARY_PATH: "/nonexistent",
          DYLD_INSERT_LIBRARIES: "x",
          KEEP: "1",
        },
      });
      assert.doesNotMatch(e.stdout, /^(LD_|DYLD_)/m);
      assert.doesNotMatch(e.stdout, /IRONWOOD_TEST_SECRET/);
      assert.match(e.stdout, /^KEEP=1$/m);
    } finally {
      if (saved === undefined) delete process.env.LD_PRELOAD;
      else process.env.LD_PRELOAD = saved;
      delete process.env.IRONWOOD_TEST_SECRET;
    }
  } finally {
    fs.rmSync(t, { recursive: true, force: true });
  }
});
test("native contents labels a fabricated provider's cmx as unverified", async () => {
  const { prepareContentsWithNative } = await import("../dist/native.js");
  const input = contents();
  const rootLE = prepareContents(input, { contractAddress: "4660" }).expected
    .rootLE;
  const v = BigInt("0x" + rootLE.match(/../g).reverse().join(""));
  const M = (1n << 120n) - 1n;
  const limbs = (x) => [x & M, (x >> 120n) & M, x >> 240n].map(String);
  const z = ["0", "0", "0"],
    rec = [z, z, z, z, z];
  const fake = {
    hash: async () => ({
      records: Array(109).fill(rec),
      point: { ...input.note.receiver.g_d, infinity: false },
      bottom: false,
      message_bits: 1086,
    }),
    merkle: async () => ({
      records: Array(1664).fill(rec),
      root: limbs(v),
      depth: 32,
    }),
  };
  const p = await prepareContentsWithNative(
    input,
    { contractAddress: "4660" },
    fake,
  );
  const truth = fixture("contents-expected.json").returns;
  assert.equal(p.expected.cmxSource, "native-provider-unverified");
  assert.notEqual(
    p.expected.cmxLE,
    Buffer.from(truth.slice(0, 32).map(Number)).toString("hex"),
  );
});
test("capsule rebinding rejects colliding target slots before policy and writes", async () => {
  const prepared = prepareContents(contents(), { contractAddress: "1" });
  prepared.capsules = [
    {
      schemaVersion: 1,
      contractAddress: "1",
      slot: 68,
      scope: "0",
      fields: ["1"],
    },
    {
      schemaVersion: 1,
      contractAddress: "2",
      slot: 68,
      scope: "0",
      fields: ["2"],
    },
  ];
  let policies = 0,
    writes = 0;
  await assert.rejects(
    () =>
      installCapsules(
        prepared,
        "3",
        {
          setCapsule: async () => {
            writes++;
          },
        },
        {
          authorize: async () => {
            policies++;
          },
        },
      ),
    (e) => e.code === "CAPSULE_DUPLICATE",
  );
  assert.equal(writes, 0);
  assert.equal(policies, 0);
});

test("sparse caller arrays cannot bypass element validation", async () => {
  const { validateCapsule, bytes, limbs, validateEffects } = await import(
    "../dist/index.js"
  );
  code(
    () =>
      validateCapsule({
        schemaVersion: 1,
        contractAddress: "1",
        slot: 68,
        scope: "0",
        fields: new Array(1),
      }),
    "INTEGER",
  );
  code(() => bytes(new Array(32), 32), "RANGE");
  code(() => limbs(new Array(3)), "INTEGER");
  const fx = structuredClone(created().transaction.effects);
  fx.compact_actions = new Array(1);
  code(() => validateEffects(fx), "LENGTH");
  const x = contents();
  x.membership.siblings = new Array(32);
  code(() => validateContents(x), "LENGTH");
});
test("inclusion normalizes SDK addresses consistently", () => {
  const p = prepareInclusion(created(), {
    contractAddress: "0x" + "1234".padStart(64, "0"),
    actions: 1,
    depth: 32,
  });
  assert.equal(p.contractAddress, "4660");
  assert.ok(p.capsules.every((x) => x.contractAddress === "4660"));
});
