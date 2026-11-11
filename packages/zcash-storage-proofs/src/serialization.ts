import { requireThat } from "./errors.js";
import { AZTEC_FIELD } from "./bytes.js";
import { contractAddress, decimal, integer, object } from "./validation.js";
import type { Capsule } from "./types.js";
export function validateCapsule(input: unknown): Capsule {
  const c = object(input, [
    "schemaVersion",
    "contractAddress",
    "slot",
    "scope",
    "fields",
  ]);
  requireThat(
    c.schemaVersion === 1 && c.scope === "0",
    "CAPSULE_SCHEMA",
    "Expected capsule v1, scope zero",
  );
  requireThat(
    Array.isArray(c.fields) && c.fields.length <= 2000000,
    "CAPSULE_LENGTH",
    "Capsule field cap exceeded",
  );
  return {
    schemaVersion: 1,
    contractAddress: contractAddress(c.contractAddress),
    slot: integer(c.slot, 0xffffffff),
    scope: "0",
    fields: Array.from(c.fields, (f, i) =>
      decimal(f, AZTEC_FIELD, `$.fields[${i}]`),
    ),
  };
}
/** Stable JSON encoding; JSON-safe decimal strings preserve full-width integers. */
export function serializeCapsules(values: readonly Capsule[]): string {
  const cs = Array.from(values, validateCapsule),
    slots = new Set(cs.map((c) => `${c.contractAddress}:${c.slot}:${c.scope}`));
  requireThat(
    slots.size === cs.length,
    "CAPSULE_DUPLICATE",
    "Duplicate capsule key",
  );
  return JSON.stringify({ schemaVersion: 1, kind: "capsules", capsules: cs });
}
export function parseCapsules(json: string): Capsule[] {
  let v: unknown;
  try {
    v = JSON.parse(json);
  } catch {
    requireThat(false, "JSON", "Malformed capsule JSON");
  }
  const o = object(v, ["schemaVersion", "kind", "capsules"]);
  requireThat(
    o.schemaVersion === 1 && o.kind === "capsules" && Array.isArray(o.capsules),
    "CAPSULE_SCHEMA",
    "Expected capsules v1",
  );
  const cs = Array.from(o.capsules as unknown[], validateCapsule);
  serializeCapsules(cs);
  return cs;
}
