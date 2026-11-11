import {
  blake,
  compactSize,
  concat,
  fromHex,
  hex,
  sha256d,
  toHex,
  u32,
} from "./bytes.js";
import { requireThat } from "./errors.js";
import type { Protocol, Checkpoint, HeaderWitness } from "./types.js";
export const NU63 = {
  branchId: 0x37a5165b,
  mainnetActivation: 3428143,
  testnetActivation: 4134000,
} as const;
export function validateHeader(
  headerHex: string,
  checkpoint: Checkpoint,
): Uint8Array {
  const h = fromHex(hex(headerHex, 1487));
  requireThat(
    h[140] === 253 && h[141] === 64 && h[142] === 5,
    "HEADER_ENCODING",
    "Expected standard Equihash(200,9) header",
  );
  requireThat(
    toHex(sha256d(h)) === checkpoint.hashLE,
    "HEADER_HASH",
    "Header does not match checkpoint",
  );
  return h;
}
/** Validates hash openings, not PoW, consensus, initialization or chain selection. */
export function openHeader(
  w: HeaderWitness,
  c: Checkpoint,
  p: Protocol,
): { snapshotHeight: number; rootLE: string; capsuleBytes: number[] } {
  const h = validateHeader(w.headerHex, c),
    raw = fromHex(hex(w.historyNodeHex));
  requireThat(
    raw.length >= 277 && raw.length <= 317,
    "HISTORY_LENGTH",
    "Expected 277..317 history node bytes",
  );
  const node = new Uint8Array(317);
  node.set(raw);
  let a = compactSize(node, 144),
    b = compactSize(node, a.next),
    count = compactSize(node, b.next),
    orchard = compactSize(node, count.next + 64),
    end = compactSize(node, orchard.next + 64);
  requireThat(a.value <= b.value, "HISTORY_RANGE", "Descending history range");
  requireThat(
    end.next >= 277 && end.next <= 317,
    "HISTORY_LENGTH",
    "Invalid history serialization",
  );
  requireThat(
    raw.length >= end.next && node.slice(end.next).every((x) => x === 0),
    "HISTORY_PADDING",
    "Truncated node or nonzero padding",
  );
  const activation =
    p.network === "mainnet" ? NU63.mainnetActivation : NU63.testnetActivation;
  requireThat(
    c.height > activation &&
      a.value === BigInt(activation) &&
      b.value === BigInt(c.height - 1),
    "HISTORY_EPOCH",
    "History must span NU6.3 activation through checkpoint minus one",
  );
  const history = blake(
      node.slice(0, end.next),
      concat(new TextEncoder().encode("ZcashHistory"), u32(NU63.branchId)),
    ),
    auth = fromHex(hex(w.authRootHex, 32)),
    commit = blake(
      concat(history, auth, new Uint8Array(32)),
      "ZcashBlockCommit",
    );
  requireThat(
    toHex(commit) === toHex(h.slice(68, 100)),
    "HISTORY_COMMITMENT",
    "History/auth opening does not match header",
  );
  return {
    snapshotHeight: c.height - 1,
    rootLE: toHex(node.slice(orchard.next + 32, orchard.next + 64)),
    capsuleBytes: Array.from(concat(h, node, auth)),
  };
}
