/** Bounded wire framing and effect hashing, NOT signature/curve/proof/consensus validation.
 * Based on pinned librustzcash 8672a4b2 transaction/components and ZIP 229/244. */
import {
  blake,
  compactSize,
  concat,
  fromHex,
  hex,
  readLE,
  sha256d,
  toHex,
  u32,
} from "./bytes.js";
import { requireThat } from "./errors.js";
import { object, integer } from "./validation.js";
import { NU63 } from "./headers.js";
import { validateBlocks } from "./transactions.js";
import type {
  BlockData,
  BlocksEnvelope,
  Checkpoint,
  Protocol,
  TransactionData,
  TransactionEffects,
} from "./types.js";
class Reader {
  offset = 0;
  constructor(readonly data: Uint8Array) {}
  take(n: number) {
    requireThat(
      Number.isSafeInteger(n) && n >= 0 && this.offset + n <= this.data.length,
      "TRUNCATED",
      "Truncated transaction serialization",
    );
    const x = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return x;
  }
  word() {
    return Number(readLE(this.take(4)));
  }
  count() {
    const c = compactSize(this.data, this.offset);
    this.offset = c.next;
    requireThat(
      c.value <= 2000000n,
      "CAPACITY",
      "CompactSize exceeds maximum block bytes",
    );
    return Number(c.value);
  }
  blob() {
    return this.take(this.count());
  }
}
export interface TransparentInput {
  outpointTxidLE: string;
  outputIndex: number;
  scriptSigHex: string;
  sequence: number;
}
export interface TransparentOutput {
  value: string;
  scriptPubKeyHex: string;
}
export interface RawShieldedBundle {
  pool: "orchard" | "ironwood";
  actionsHex: string[];
  flags: number;
  valueBalanceLE: string;
  anchorLE: string;
  proofHex: string;
  spendAuthSignaturesHex: string[];
  bindingSignatureHex: string;
}
export interface RawTransactionInspection {
  transaction: TransactionData;
  branchId: number | null;
  bytesRead: number;
  shieldedBundles: {
    orchard: RawShieldedBundle | null;
    ironwood: RawShieldedBundle | null;
  };
  transparent: { inputs: TransparentInput[]; outputs: TransparentOutput[] };
  validation: "framing-and-digest-only";
}
const H = (domain: string, ...xs: Uint8Array[]) => blake(concat(...xs), domain);
const A = (x: Uint8Array) => Array.from(x);
function transparent(r: Reader) {
  const inputs: TransparentInput[] = [],
    outputs: TransparentOutput[] = [],
    prev: Uint8Array[] = [],
    seq: Uint8Array[] = [],
    outs: Uint8Array[] = [];
  const ni = r.count();
  for (let i = 0; i < ni; i++) {
    const outpoint = r.take(36),
      script = r.blob(),
      sequence = r.take(4);
    prev.push(outpoint);
    seq.push(sequence);
    inputs.push({
      outpointTxidLE: toHex(outpoint.slice(0, 32)),
      outputIndex: Number(readLE(outpoint.slice(32))),
      scriptSigHex: toHex(script),
      sequence: Number(readLE(sequence)),
    });
  }
  const no = r.count();
  for (let i = 0; i < no; i++) {
    const start = r.offset,
      value = r.take(8),
      script = r.blob();
    outs.push(r.data.slice(start, r.offset));
    outputs.push({
      value: readLE(value).toString(),
      scriptPubKeyHex: toHex(script),
    });
  }
  return {
    inputs,
    outputs,
    digest:
      ni || no
        ? H(
            "ZTxIdTranspaHash",
            H("ZTxIdPrevoutHash", ...prev),
            H("ZTxIdSequencHash", ...seq),
            H("ZTxIdOutputsHash", ...outs),
          )
        : H("ZTxIdTranspaHash"),
  };
}
function sapling(r: Reader, version: 5 | 6) {
  const spends: Uint8Array[] = [],
    outputs: Uint8Array[] = [];
  const ns = r.count();
  for (let i = 0; i < ns; i++) spends.push(r.take(96));
  const no = r.count();
  for (let i = 0; i < no; i++) outputs.push(r.take(756));
  const balance = ns || no ? r.take(8) : new Uint8Array(8),
    anchor = ns ? r.take(32) : new Uint8Array();
  r.take(ns * 192);
  r.take(ns * 64);
  r.take(no * 192);
  if (ns || no) r.take(64);
  const spend = ns
    ? H(
        "ZTxIdSSpendsHash",
        H("ZTxIdSSpendCHash", ...spends.map((s) => s.slice(32, 64))),
        H(
          version === 6 ? "ZTxIdSSpendNH_v6" : "ZTxIdSSpendNHash",
          ...spends.map((s) =>
            concat(
              s.slice(0, 32),
              version === 5 ? anchor : new Uint8Array(),
              s.slice(64, 96),
            ),
          ),
        ),
      )
    : H("ZTxIdSSpendsHash");
  const out = no
    ? H(
        "ZTxIdSOutputHash",
        H("ZTxIdSOutC__Hash", ...outputs.map((o) => o.slice(32, 148))),
        H("ZTxIdSOutM__Hash", ...outputs.map((o) => o.slice(148, 660))),
        H(
          "ZTxIdSOutN__Hash",
          ...outputs.map((o) => concat(o.slice(0, 32), o.slice(660, 756))),
        ),
      )
    : H("ZTxIdSOutputHash");
  return ns || no
    ? H("ZTxIdSaplingHash", spend, out, balance)
    : H("ZTxIdSaplingHash");
}
function orchard(r: Reader, version: 5 | 6, ironwood: boolean) {
  const actions: Uint8Array[] = [],
    n = r.count();
  for (let i = 0; i < n; i++) actions.push(r.take(820));
  const flags = n ? r.take(1)[0] : 0,
    balance = n ? r.take(8) : new Uint8Array(8),
    anchor = n ? r.take(32) : new Uint8Array();
  requireThat(
    flags < (ironwood ? 8 : 4),
    "FLAGS",
    "Reserved Orchard/Ironwood flags",
  );
  const proof = n ? r.blob() : new Uint8Array(),
    signatures = Array.from({ length: n }, () => toHex(r.take(64))),
    binding = n ? r.take(64) : new Uint8Array();
  const bundle: RawShieldedBundle | null = n
    ? {
        pool: ironwood ? "ironwood" : "orchard",
        actionsHex: actions.map(toHex),
        flags,
        valueBalanceLE: toHex(balance),
        anchorLE: toHex(anchor),
        proofHex: toHex(proof),
        spendAuthSignaturesHex: signatures,
        bindingSignatureHex: toHex(binding),
      }
    : null;
  const compact = actions.map((x) => concat(x.slice(32, 64), x.slice(96, 212))),
    memos = H(
      ironwood ? "ZTxIdIrnActMH_v6" : "ZTxIdOrcActMHash",
      ...actions.map((x) => x.slice(212, 724)),
    ),
    noncompact = H(
      ironwood ? "ZTxIdIrnActNH_v6" : "ZTxIdOrcActNHash",
      ...actions.map((x) =>
        concat(x.slice(0, 32), x.slice(64, 96), x.slice(724, 820)),
      ),
    ),
    domain = ironwood
      ? "ZTxIdIronwd_H_v6"
      : version === 6
        ? "ZTxIdOrchardH_v6"
        : "ZTxIdOrchardHash";
  const digest = n
    ? H(
        domain,
        H(ironwood ? "ZTxIdIrnActCH_v6" : "ZTxIdOrcActCHash", ...compact),
        memos,
        noncompact,
        Uint8Array.of(flags),
        balance,
        version === 5 ? anchor : new Uint8Array(),
      )
    : H(domain);
  return {
    bundle,
    compact_actions: compact.map(A),
    memos_digest: A(memos),
    noncompact_digest: A(noncompact),
    flags,
    value_balance: A(balance),
    digest,
  };
}
function readTransaction(r: Reader): RawTransactionInspection {
  const start = r.offset,
    header = r.word(),
    version = header & 0x7fffffff;
  requireThat(
    header >= 0x80000000 && (version === 4 || version === 5 || version === 6),
    "TRANSACTION_VERSION",
    "Raw parser supports Overwintered V4/V5/V6 only",
  );
  const group = r.word();
  requireThat(
    group ===
      (version === 4 ? 0x892f2085 : version === 5 ? 0x26a7270a : 0xd884b698),
    "TRANSACTION_VERSION",
    "Version group mismatch",
  );
  let branchId: number | null = null,
    t: ReturnType<typeof transparent>,
    effects: TransactionEffects | undefined,
    txidLE: string;
  let shieldedBundles: RawTransactionInspection["shieldedBundles"] = {
    orchard: null,
    ironwood: null,
  };
  if (version === 4) {
    t = transparent(r);
    r.take(8);
    r.take(8);
    const ns = r.count();
    r.take(ns * 384);
    const no = r.count();
    r.take(no * 948);
    const nj = r.count();
    r.take(nj * 1698);
    if (nj) r.take(96);
    if (ns || no) r.take(64);
    txidLE = toHex(sha256d(r.data.slice(start, r.offset)));
  } else {
    branchId = r.word();
    const lock_time = r.word(),
      expiry_height = r.word();
    t = transparent(r);
    const s = sapling(r, version),
      o = orchard(r, version, false),
      iw =
        version === 6
          ? orchard(r, version, true)
          : {
              bundle: null,
              compact_actions: [],
              memos_digest: new Array(32).fill(0),
              noncompact_digest: new Array(32).fill(0),
              flags: 0,
              value_balance: new Array(8).fill(0),
              digest: new Uint8Array(),
            };
    shieldedBundles = { orchard: o.bundle, ironwood: iw.bundle };
    effects = {
      compact_actions: iw.compact_actions,
      memos_digest: iw.memos_digest,
      noncompact_digest: iw.noncompact_digest,
      flags: iw.flags,
      value_balance: iw.value_balance,
      transparent_digest: A(t.digest),
      sapling_digest: A(s),
      orchard_digest: A(o.digest),
      lock_time,
      expiry_height,
    };
    txidLE = toHex(
      blake(
        concat(
          H("ZTxIdHeadersHash", r.data.slice(start, start + 20)),
          t.digest,
          s,
          o.digest,
          iw.digest,
        ),
        concat(new TextEncoder().encode("ZcashTxHash_"), u32(branchId)),
      ),
    );
  }
  const transaction: TransactionData =
    version === 4
      ? { version, txidLE, rawHex: toHex(r.data.slice(start, r.offset)) }
      : { version: version as 5 | 6, txidLE, effects: effects! };
  return {
    transaction,
    branchId,
    shieldedBundles,
    bytesRead: r.offset - start,
    transparent: { inputs: t.inputs, outputs: t.outputs },
    validation: "framing-and-digest-only",
  };
}
/** Historical inspection is explicit; this does not create an Ironwood witness. */
export function inspectRawTransaction(
  rawHex: string,
): RawTransactionInspection {
  const raw = fromHex(hex(rawHex));
  requireThat(
    raw.length <= 2000000,
    "CAPACITY",
    "Transaction exceeds maximum block bytes",
  );
  const r = new Reader(raw),
    result = readTransaction(r);
  requireThat(
    r.offset === raw.length,
    "TRAILING_BYTES",
    "Trailing transaction bytes",
  );
  return result;
}
/** Normalize complete raw bytes for the pinned protocol; never trust RPC txids. */
export function parseRawTransaction(rawHex: string): TransactionData {
  const r = inspectRawTransaction(rawHex);
  requireThat(
    r.branchId === null || r.branchId === NU63.branchId,
    "UNSUPPORTED_PROTOCOL",
    "Raw transaction branch differs from pinned NU6.3",
  );
  return r.transaction;
}
export function inspectRawBlock(rawHex: string): {
  headerHex: string;
  hashLE: string;
  transactions: RawTransactionInspection[];
} {
  const raw = fromHex(hex(rawHex));
  requireThat(raw.length <= 2000000, "CAPACITY", "Block exceeds 2 MB");
  const r = new Reader(raw),
    fixed = r.take(140),
    solution = r.blob();
  requireThat(
    solution.length === 1344,
    "HEADER_ENCODING",
    "Expected Equihash(200,9) solution",
  );
  const header = r.data.slice(0, r.offset);
  requireThat(
    header.length === 1487 && fixed.length === 140,
    "HEADER_ENCODING",
    "Noncanonical header",
  );
  const count = r.count();
  requireThat(count > 0, "EMPTY_BLOCK", "Block contains no transactions");
  const transactions: RawTransactionInspection[] = [];
  for (let i = 0; i < count; i++) transactions.push(readTransaction(r));
  requireThat(
    r.offset === raw.length,
    "TRAILING_BYTES",
    "Trailing block bytes",
  );
  return {
    headerHex: toHex(header),
    hashLE: toHex(sha256d(header)),
    transactions,
  };
}
export function prepareRawBlocks(value: unknown): BlocksEnvelope {
  const input = object(value, [
    "schemaVersion",
    "kind",
    "protocol",
    "checkpoint",
    "blocks",
  ]);
  requireThat(
    input.schemaVersion === 1 && input.kind === "raw-blocks",
    "SCHEMA_VERSION",
    "Expected raw-blocks v1",
  );
  requireThat(
    Array.isArray(input.blocks) && input.blocks.length > 0,
    "EMPTY_BLOCKS",
    "Expected complete blocks",
  );
  const blocks: BlockData[] = Array.from(input.blocks, (value) => {
    const b = object(value, ["height", "rawHex"]);
    const block = inspectRawBlock(hex(b.rawHex));
    for (const t of block.transactions)
      requireThat(
        t.branchId === null || t.branchId === NU63.branchId,
        "UNSUPPORTED_PROTOCOL",
        "Transaction branch differs from pinned NU6.3",
      );
    return {
      height: integer(b.height, 0xffffffff),
      headerHex: block.headerHex,
      transactions: block.transactions.map((t) => t.transaction),
    };
  });
  return validateBlocks({ ...input, kind: "complete-blocks", blocks });
}
