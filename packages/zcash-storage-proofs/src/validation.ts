import { requireThat } from "./errors.js";
import { hex, PALLAS_BASE, AZTEC_FIELD } from "./bytes.js";
import type {
  Protocol,
  Checkpoint,
  Limbs,
  Point,
  NoteOpening,
  ContentsEnvelope,
} from "./types.js";
export function object(
  v: unknown,
  keys: string[],
  path = "$",
): Record<string, unknown> {
  requireThat(
    v !== null && typeof v === "object" && !Array.isArray(v),
    "TYPE",
    "Expected object",
    path,
  );
  const o = v as Record<string, unknown>;
  requireThat(
    Object.keys(o).every((k) => keys.includes(k)),
    "UNKNOWN_FIELD",
    "Unsupported field",
    path,
  );
  return o;
}
export function integer(v: unknown, max: number, path = "$"): number {
  requireThat(
    typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= max,
    "RANGE",
    `Expected integer in [0,${max}]`,
    path,
  );
  return v;
}
export function decimal(v: unknown, maxExclusive: bigint, path = "$"): string {
  requireThat(
    typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v),
    "INTEGER",
    "Expected canonical decimal string",
    path,
  );
  requireThat(
    BigInt(v) < maxExclusive,
    "RANGE",
    "Integer is out of range",
    path,
  );
  return v;
}
export function bytes(v: unknown, length: number, path = "$"): number[] {
  requireThat(
    Array.isArray(v) && v.length === length,
    "LENGTH",
    `Expected ${length} bytes`,
    path,
  );
  return Array.from(v, (x, i) => integer(x, 255, `${path}[${i}]`));
}
export function limbs(v: unknown, path = "$", canonical = true): Limbs {
  requireThat(
    Array.isArray(v) && v.length === 3,
    "LENGTH",
    "Expected three limbs",
    path,
  );
  const a = Array.from(v, (x, i) =>
    decimal(x, 1n << BigInt(i === 2 ? 15 : 120), `${path}[${i}]`),
  ) as Limbs;
  requireThat(
    !canonical || limbValue(a) < PALLAS_BASE,
    "NONCANONICAL",
    "Expected canonical Pallas base field",
    path,
  );
  return a;
}
export function limbValue(v: Limbs): bigint {
  return BigInt(v[0]) + (BigInt(v[1]) << 120n) + (BigInt(v[2]) << 240n);
}
export function toLimbs(x: bigint): Limbs {
  return [0, 1, 2].map((i) =>
    (
      (x >> BigInt(120 * i)) &
      ((1n << BigInt(i === 2 ? 15 : 120)) - 1n)
    ).toString(),
  ) as Limbs;
}
export function point(v: unknown, path = "$"): Point {
  const o = object(v, ["x", "y"], path),
    x = limbs(o.x, `${path}.x`),
    y = limbs(o.y, `${path}.y`),
    a = limbValue(x),
    b = limbValue(y);
  requireThat(
    (b * b - a * a * a - 5n) % PALLAS_BASE === 0n,
    "CURVE",
    "Expected a nonidentity Pallas point",
    path,
  );
  return { x, y };
}
export function noteOpening(v: unknown, path = "$.note"): NoteOpening {
  const o = object(v, ["receiver", "value", "rho", "rseedHex"], path),
    r = object(o.receiver, ["g_d", "pk_d"], path + ".receiver");
  return {
    receiver: {
      g_d: point(r.g_d, path + ".receiver.g_d"),
      pk_d: point(r.pk_d, path + ".receiver.pk_d"),
    },
    value: decimal(o.value, 1n << 64n, path + ".value"),
    rho: limbs(o.rho, path + ".rho"),
    rseedHex: hex(o.rseedHex, 32, path + ".rseedHex"),
  };
}
export function protocol(v: unknown): Protocol {
  const o = object(v, ["pool", "era", "network"], "$.protocol");
  requireThat(
    o.pool === "ironwood-v3" && o.era === "nu6.3",
    "UNSUPPORTED_PROTOCOL",
    "Only pinned Ironwood V3 / NU6.3 is supported",
    "$.protocol",
  );
  requireThat(
    o.network === "mainnet" || o.network === "testnet",
    "NETWORK",
    "Expected mainnet or testnet",
    "$.protocol.network",
  );
  return o as unknown as Protocol;
}
export function checkpoint(v: unknown): Checkpoint {
  const o = object(v, ["height", "hashLE", "policyId"], "$.checkpoint");
  requireThat(
    typeof o.policyId === "string" &&
      o.policyId.length > 0 &&
      o.policyId.length <= 256,
    "CHECKPOINT_POLICY",
    "Explicit application policy ID required",
    "$.checkpoint.policyId",
  );
  return {
    height: integer(o.height, 0xffffffff, "$.checkpoint.height"),
    hashLE: hex(o.hashLE, 32, "$.checkpoint.hashLE"),
    policyId: o.policyId,
  };
}
export function envelope(v: unknown, keys: string[], kind: string | string[]) {
  const o = object(v, [
    "schemaVersion",
    "kind",
    "protocol",
    "checkpoint",
    ...keys,
  ]);
  requireThat(
    o.schemaVersion === 1,
    "SCHEMA_VERSION",
    "Unsupported schema version",
  );
  requireThat(
    (Array.isArray(kind) ? kind : [kind]).includes(String(o.kind)),
    "UNSUPPORTED_CLAIM",
    "Unsupported claim",
  );
  return o;
}
export function validateContents(v: unknown): ContentsEnvelope {
  const o = envelope(v, ["header", "note", "membership"], "contents"),
    h = object(
      o.header,
      ["headerHex", "historyNodeHex", "authRootHex"],
      "$.header",
    ),
    m = object(o.membership, ["position", "siblings"], "$.membership");
  requireThat(
    Array.isArray(m.siblings) && m.siblings.length === 32,
    "LENGTH",
    "Expected depth-32 membership path",
    "$.membership.siblings",
  );
  return {
    schemaVersion: 1,
    kind: "contents",
    protocol: protocol(o.protocol),
    checkpoint: checkpoint(o.checkpoint),
    header: {
      headerHex: hex(h.headerHex, 1487, "$.header.headerHex"),
      historyNodeHex: hex(
        h.historyNodeHex,
        undefined,
        "$.header.historyNodeHex",
      ),
      authRootHex: hex(h.authRootHex, 32, "$.header.authRootHex"),
    },
    note: noteOpening(o.note),
    membership: {
      position: integer(m.position, 0xffffffff, "$.membership.position"),
      siblings: Array.from(m.siblings, (s, i) =>
        limbs(s, `$.membership.siblings[${i}]`),
      ),
    },
  };
}
export function contractAddress(v: unknown): string {
  const normalized =
    typeof v === "string" && /^0x[0-9a-f]{64}$/.test(v)
      ? BigInt(v).toString()
      : v;
  return decimal(normalized, AZTEC_FIELD, "$.contractAddress");
}
