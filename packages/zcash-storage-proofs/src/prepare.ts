import { fromHex, sha256d, toHex } from "./bytes.js";
import { requireThat } from "./errors.js";
import {
  bytes,
  checkpoint as validateCheckpoint,
  contractAddress,
  integer,
  object,
  protocol as validateProtocol,
  validateContents,
} from "./validation.js";
import { openHeader } from "./headers.js";
import { validateCapsule } from "./serialization.js";
import { SLOTS } from "./slots.js";
import type {
  AuthorizedArguments,
  AuthorizedWitness,
  Capsule,
  NoteOpening,
  PreparationOptions,
  PreparedContentsWitness,
  PreparedWitness,
  CheckpointPolicy,
} from "./types.js";
export function openingFields(n: NoteOpening): string[] {
  return [
    ...n.receiver.g_d.x,
    ...n.receiver.g_d.y,
    ...n.receiver.pk_d.x,
    ...n.receiver.pk_d.y,
    n.value,
    ...n.rho,
    ...Array.from(fromHex(n.rseedHex), String),
  ];
}
export function capsule(
  address: string,
  slot: number,
  fields: (string | number)[],
): Capsule {
  return {
    schemaVersion: 1,
    contractAddress: contractAddress(address),
    slot,
    scope: "0",
    fields: fields.map(String),
  };
}
/** Pure hash/encoding preparation. The circuit still checks the note commitment and path. */
export function prepareContents(
  input: unknown,
  options: PreparationOptions,
): PreparedContentsWitness {
  const e = validateContents(input),
    address = contractAddress(options.contractAddress),
    h = openHeader(e.header, e.checkpoint, e.protocol);
  return {
    schemaVersion: 1,
    kind: "prepared-witness",
    claim: "contents",
    protocol: e.protocol,
    checkpoint: e.checkpoint,
    contractAddress: address,
    arguments: {
      expected_hash: Array.from(fromHex(e.checkpoint.hashLE)),
      header_height: e.checkpoint.height,
      is_testnet: e.protocol.network === "testnet",
    },
    capsules: [
      capsule(address, SLOTS.header, h.capsuleBytes),
      capsule(address, SLOTS.note, [
        ...openingFields(e.note),
        String(e.membership.position),
        ...e.membership.siblings.flat(),
      ]),
    ],
    validation: {
      structure: true,
      hashBindings: true,
      checkpointAuthorized: false,
      proofVerified: false,
    },
    expected: { snapshotHeight: h.snapshotHeight, rootLE: h.rootLE },
  };
}
const HEADER_BYTES = 1487;
/** Native hint capsules: Merkle levels 70..101 and the note-hash hints at 102. */
const NATIVE_HINT_SLOTS = Array.from(
  { length: 33 },
  (_, i) => SLOTS.merkleHints + i,
);
type Bound = (hash: number[], height: number, testnet: boolean) => object;
const headerBound: Bound = (hash) => ({ accepted_header_hash: hash });
const tipBound: Bound = (hash, height, testnet) => ({
  expected_tip_hash: hash,
  expected_tip_height: height,
  is_testnet: testnet,
});
/** Per claim: exact capsule slot sets, the header slot hashed to the checkpoint,
 * the arguments re-derived from the checkpoint, and argument keys the circuit
 * checks itself (scan windows: prior_height + count == expected_tip_height). */
const CLAIMS: Record<
  string,
  { slots: number[][]; header?: number; bound: Bound; free?: string[] }
> = {
  contents: {
    slots: [
      [60, 61],
      [60, 61, ...NATIVE_HINT_SLOTS],
    ],
    header: 60,
    bound: (hash, height, testnet) => ({
      expected_hash: hash,
      header_height: height,
      is_testnet: testnet,
    }),
  },
  "action-inclusion": { slots: [[68]], header: 68, bound: headerBound },
  "created-in-block": { slots: [[68, 69]], header: 68, bound: headerBound },
  "memo-created-in-block": {
    slots: [[68, 69, SLOTS.memo]],
    header: 68,
    bound: headerBound,
  },
  "nullifier-in-transaction": {
    slots: [[68]],
    header: 68,
    bound: headerBound,
    free: ["expected_nf"],
  },
  "nullifier-absence-from-activation": {
    slots: [[63], [66]],
    bound: tipBound,
    free: ["queried_nf"],
  },
  "nullifier-absence-window": {
    slots: [[67]],
    bound: tipBound,
    free: ["queried_nf", "count", "prior_height"],
  },
};
/** Free arguments: the host checks only their type; the circuit checks values. */
const FREE: Record<string, (v: unknown, path: string) => unknown> = {
  queried_nf: (v, path) => bytes(v, 32, path),
  expected_nf: (v, path) => bytes(v, 32, path),
  count: (v, path) => integer(v, 0xffffffff, path),
  prior_height: (v, path) => integer(v, 0xffffffff, path),
};
/** Strict equality of primitives, element by element for arrays. A wrapper
 * object such as new Boolean(false) never matches. */
const same = (actual: unknown, expected: unknown): boolean =>
  Array.isArray(expected)
    ? Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((x, i) => actual[i] === x)
    : actual === expected;
function freezeAll<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freezeAll(child);
    Object.freeze(value);
  }
  return value;
}
/** Checks one plain-data copy, synchronously, so nothing can change it meanwhile. */
function bindSnapshot(input: unknown): AuthorizedWitness {
  let s: Record<string, unknown> | undefined;
  try {
    s = structuredClone(input) as Record<string, unknown>;
  } catch {
    requireThat(false, "TYPE", "Expected plain prepared witness data");
  }
  requireThat(
    s !== null && typeof s === "object" && !Array.isArray(s),
    "TYPE",
    "Expected prepared witness object",
  );
  requireThat(
    s.schemaVersion === 1 && s.kind === "prepared-witness",
    "SCHEMA_VERSION",
    "Expected prepared witness v1",
  );
  const claim = s.claim,
    rule =
      typeof claim === "string" && Object.hasOwn(CLAIMS, claim)
        ? CLAIMS[claim]
        : undefined;
  requireThat(rule, "UNSUPPORTED_CLAIM", "Unsupported claim", "$.claim");
  const checkpoint = validateCheckpoint(s.checkpoint),
    protocol = validateProtocol(s.protocol);
  requireThat(
    Array.isArray(s.capsules),
    "TYPE",
    "Expected capsules",
    "$.capsules",
  );
  const capsules = s.capsules.map((c) => validateCapsule(c)),
    slots = capsules
      .map((c) => c.slot)
      .sort((a, b) => a - b)
      .join();
  requireThat(
    new Set(capsules.map((c) => c.slot)).size === capsules.length,
    "CAPSULE_DUPLICATE",
    "Duplicate capsule slot",
    "$.capsules",
  );
  requireThat(
    rule.slots.some((x) => x.join() === slots),
    "CAPSULE_SLOTS",
    "Capsule slots do not match the prepared claim",
    "$.capsules",
  );
  const bound = rule.bound(
      Array.from(fromHex(checkpoint.hashLE)),
      checkpoint.height,
      protocol.network === "testnet",
    ),
    args = object(
      s.arguments,
      [...Object.keys(bound), ...(rule.free ?? [])],
      "$.arguments",
    );
  // Return the re-derived values, never the caller's, so only the checked
  // primitives reach the ABI encoder.
  const out: Record<string, unknown> = {};
  for (const k of rule.free ?? [])
    if (Object.hasOwn(args, k)) out[k] = FREE[k](args[k], `$.arguments.${k}`);
  for (const [k, v] of Object.entries(bound)) {
    requireThat(
      same(args[k], v),
      "ARGUMENT_BINDING",
      "Argument does not match the authorised checkpoint",
      `$.arguments.${k}`,
    );
    out[k] = v;
  }
  if (rule.header !== undefined) {
    const fields = capsules.find((c) => c.slot === rule.header)!.fields;
    requireThat(
      fields.length >= HEADER_BYTES &&
        fields.slice(0, HEADER_BYTES).every((f) => BigInt(f) < 256n) &&
        toHex(
          sha256d(Uint8Array.from(fields.slice(0, HEADER_BYTES), Number)),
        ) === checkpoint.hashLE,
      "HEADER_HASH",
      "Header capsule does not match the authorised checkpoint",
      "$.capsules",
    );
  }
  return freezeAll({
    claim: claim as AuthorizedWitness["claim"],
    protocol,
    checkpoint,
    capsules,
    arguments: out as AuthorizedArguments,
  });
}
/**
 * Host defence in depth, shared by authorizePrepared and installCapsules. It
 * copies the witness before any await, then requires a known claim with its
 * exact slot set, checkpoint-bound arguments strictly equal to those re-derived
 * from the checkpoint and protocol, and (slots 60 and 68) sha256d(header) ==
 * hashLE. Only then does it ask the policy, with frozen copies. It returns the
 * re-derived values and type-checked free arguments, not the caller's objects.
 * Other capsules and argument values are left to the circuit. The contract must still enforce its own
 * accepted checkpoint.
 */
export async function authorizeWitness(
  prepared: unknown,
  policy: CheckpointPolicy,
): Promise<AuthorizedWitness> {
  const authorized = bindSnapshot(prepared);
  await policy.authorize(authorized.checkpoint, authorized.protocol);
  return authorized;
}
/** Explicit application authorization. Preparation alone is never authorization.
 * Pass the returned frozen arguments, not the caller's object, to the private function. */
export async function authorizePrepared(
  w: PreparedWitness,
  policy: CheckpointPolicy,
): Promise<AuthorizedArguments> {
  return (await authorizeWitness(w, policy)).arguments;
}
