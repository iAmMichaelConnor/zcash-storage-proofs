import {
  blake,
  concat,
  fromHex,
  hex,
  readLE,
  sha256d,
  toHex,
  u32,
} from "./bytes.js";
import { requireThat } from "./errors.js";
import {
  bytes,
  contractAddress,
  checkpoint,
  envelope,
  integer,
  noteOpening,
  object,
  protocol,
  limbValue,
} from "./validation.js";
import { NU63, validateHeader } from "./headers.js";
import { capsule, openingFields } from "./prepare.js";
import type {
  BlocksEnvelope,
  BlockData,
  TransactionData,
  TransactionEffects,
  InclusionEnvelope,
  PreparedInclusionWitness,
  PreparedNullifierInclusionWitness,
  PreparationOptions,
} from "./types.js";
const EFFECT_KEYS = [
  "compact_actions",
  "memos_digest",
  "noncompact_digest",
  "flags",
  "value_balance",
  "transparent_digest",
  "sapling_digest",
  "orchard_digest",
  "lock_time",
  "expiry_height",
];
export function validateEffects(input: unknown): TransactionEffects {
  const e = object(input, EFFECT_KEYS);
  requireThat(
    Array.isArray(e.compact_actions) &&
      e.compact_actions.length <= Math.floor(2000000 / 148),
    "CAPACITY",
    "Invalid Action count",
  );
  return {
    compact_actions: Array.from(e.compact_actions, (x, i) =>
      bytes(x, 148, `$.compact_actions[${i}]`),
    ),
    memos_digest: bytes(e.memos_digest, 32),
    noncompact_digest: bytes(e.noncompact_digest, 32),
    flags: integer(e.flags, 7),
    value_balance: bytes(e.value_balance, 8),
    transparent_digest: bytes(e.transparent_digest, 32),
    sapling_digest: bytes(e.sapling_digest, 32),
    orchard_digest: bytes(e.orchard_digest, 32),
    lock_time: integer(e.lock_time, 0xffffffff),
    expiry_height: integer(e.expiry_height, 0xffffffff),
  };
}
export function effectsTxid(version: 5 | 6, e: TransactionEffects): string {
  requireThat(
    version === 5 || version === 6,
    "TRANSACTION_VERSION",
    "Unsupported transaction version",
  );
  requireThat(
    version === 6 || e.compact_actions.length === 0,
    "TRANSACTION_VERSION",
    "V5 cannot contain Ironwood",
  );
  const header = blake(
      concat(
        ...[
          0x80000000 + version,
          version === 6 ? 0xd884b698 : 0x26a7270a,
          NU63.branchId,
          e.lock_time,
          e.expiry_height,
        ].map(u32),
      ),
      "ZTxIdHeadersHash",
    ),
    ds = [header, e.transparent_digest, e.sapling_digest, e.orchard_digest];
  if (version === 6) {
    const part = e.compact_actions.length
      ? concat(
          blake(concat(...e.compact_actions), "ZTxIdIrnActCH_v6"),
          e.memos_digest,
          e.noncompact_digest,
          [e.flags],
          e.value_balance,
        )
      : new Uint8Array();
    ds.push(blake(part, "ZTxIdIronwd_H_v6"));
  }
  return toHex(
    blake(
      concat(...ds),
      concat(new TextEncoder().encode("ZcashTxHash_"), u32(NU63.branchId)),
    ),
  );
}
export function validateTransaction(input: unknown): TransactionData {
  const t = object(input, ["version", "txidLE", "effects", "rawHex"]);
  requireThat(
    t.version === 4 || t.version === 5 || t.version === 6,
    "TRANSACTION_VERSION",
    "Only V4/V5/V6 supported",
  );
  const id = hex(t.txidLE, 32);
  if (t.version === 4) {
    requireThat(
      t.effects === undefined,
      "TRANSACTION_VERSION",
      "V4 uses raw serialization, not effects",
    );
    const raw = fromHex(hex(t.rawHex));
    requireThat(
      raw.length >= 70 && raw.length <= 2000000,
      "TRANSACTION_LENGTH",
      "Invalid raw V4 length",
    );
    requireThat(
      readLE(raw.slice(0, 4)) === 0x80000004n &&
        readLE(raw.slice(4, 8)) === 0x892f2085n,
      "TRANSACTION_VERSION",
      "Expected Sapling V4 header",
    );
    requireThat(toHex(sha256d(raw)) === id, "TXID", "Raw V4 txid mismatch");
    return { version: 4, txidLE: id, rawHex: toHex(raw) };
  }
  const effects = validateEffects(t.effects);
  requireThat(
    effectsTxid(t.version, effects) === id,
    "TXID",
    "Transaction effect digest mismatch",
  );
  requireThat(
    t.rawHex === undefined,
    "RAW_ADAPTER_REQUIRED",
    "Decode raw V5/V6 bytes first; do not attach unbound bytes to an effect witness",
  );
  return { version: t.version, txidLE: id, effects };
}
export function transactionRoot(ids: string[]): string {
  requireThat(
    ids.length > 0,
    "EMPTY_BLOCK",
    "Block needs complete nonempty transaction list",
  );
  requireThat(
    new Set(ids).size === ids.length,
    "DUPLICATE_TXID",
    "Complete block contains duplicate transaction IDs",
  );
  let layer = Array.from(ids, (x) => fromHex(hex(x, 32)));
  while (layer.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length)
        requireThat(
          toHex(layer[i]) !== toHex(layer[i + 1]),
          "MUTATED_MERKLE",
          "Equal adjacent real transaction nodes make count ambiguous",
        );
      next.push(sha256d(concat(layer[i], layer[i + 1] ?? layer[i])));
    }
    layer = next;
  }
  return toHex(layer[0]);
}
export function validateBlocks(input: unknown): BlocksEnvelope {
  const o = envelope(input, ["blocks"], "complete-blocks"),
    p = protocol(o.protocol),
    c = checkpoint(o.checkpoint);
  requireThat(
    Array.isArray(o.blocks) && o.blocks.length > 0,
    "EMPTY_BLOCKS",
    "Expected complete consecutive blocks",
  );
  const activation =
    p.network === "mainnet" ? NU63.mainnetActivation : NU63.testnetActivation;
  const blocks = Array.from(o.blocks, (x, i): BlockData => {
    const b = object(
      x,
      ["height", "headerHex", "transactions"],
      `$.blocks[${i}]`,
    );
    const height = integer(b.height, 0xffffffff);
    requireThat(
      height >= activation,
      "HISTORY_EPOCH",
      "Block predates pinned NU6.3 epoch",
    );
    const h = fromHex(hex(b.headerHex, 1487));
    validateHeader(toHex(h), { ...c, hashLE: toHex(sha256d(h)) });
    requireThat(
      Array.isArray(b.transactions) &&
        b.transactions.length > 0 &&
        b.transactions.length <= 2000000,
      "CAPACITY",
      "Expected complete transaction list",
    );
    const transactions = Array.from(b.transactions, validateTransaction);
    requireThat(
      transactionRoot(transactions.map((t) => t.txidLE)) ===
        toHex(h.slice(36, 68)),
      "BLOCK_MERKLE",
      "Complete transaction list does not match header",
    );
    return { height, headerHex: toHex(h), transactions };
  });
  for (let i = 1; i < blocks.length; i++) {
    requireThat(
      blocks[i].height === blocks[i - 1].height + 1,
      "CHAIN_HEIGHT",
      "Nonconsecutive block heights",
    );
    requireThat(
      toHex(fromHex(blocks[i].headerHex).slice(4, 36)) ===
        toHex(sha256d(fromHex(blocks[i - 1].headerHex))),
      "CHAIN_LINK",
      "Previous block hash mismatch",
    );
  }
  const tip = blocks.at(-1)!;
  requireThat(
    tip.height === c.height &&
      toHex(sha256d(fromHex(tip.headerHex))) === c.hashLE,
    "CHECKPOINT",
    "Last block does not match checkpoint",
  );
  return {
    schemaVersion: 1,
    kind: "complete-blocks",
    protocol: p,
    checkpoint: c,
    blocks,
  };
}
export function validateInclusion(input: unknown): InclusionEnvelope {
  const o = envelope(
      input,
      [
        "headerHex",
        "transaction",
        "actionIndex",
        "transactionIndex",
        "transactionCount",
        "siblings",
        "note",
      ],
      ["action-inclusion", "created-in-block"],
    ),
    p = protocol(o.protocol),
    c = checkpoint(o.checkpoint),
    t = validateTransaction(o.transaction);
  requireThat(
    t.version === 6 &&
      t.effects !== undefined &&
      t.effects.compact_actions.length > 0,
    "TRANSACTION_VERSION",
    "Selected Ironwood Action requires nonempty V6 bundle",
  );
  const actionIndex = integer(
      o.actionIndex,
      t.effects.compact_actions.length - 1,
    ),
    transactionCount = integer(o.transactionCount, 0xffffffff);
  requireThat(transactionCount > 0, "EMPTY_BLOCK", "Transaction count is zero");
  const transactionIndex = integer(o.transactionIndex, transactionCount - 1);
  requireThat(
    Array.isArray(o.siblings) && o.siblings.length <= 32,
    "MERKLE_DEPTH",
    "Expected at most 32 Merkle siblings",
  );
  const siblings = Array.from(o.siblings, (s) => hex(s, 32));
  const h = validateHeader(hex(o.headerHex, 1487), c);
  let value = t.txidLE,
    index = transactionIndex,
    count = transactionCount,
    level = 0;
  while (count > 1) {
    requireThat(
      level < siblings.length,
      "MERKLE_DEPTH",
      "Missing transaction sibling",
    );
    const sibling = siblings[level];
    if (index % 2 === 0 && index + 1 >= count)
      requireThat(
        sibling === value,
        "MERKLE_DUPLICATE",
        "Odd final node must duplicate itself",
      );
    value = toHex(
      sha256d(
        index % 2
          ? concat(fromHex(sibling), fromHex(value))
          : concat(fromHex(value), fromHex(sibling)),
      ),
    );
    index = Math.floor(index / 2);
    count = Math.ceil(count / 2);
    level++;
  }
  requireThat(
    siblings.slice(level).every((s) => s === "00".repeat(32)),
    "MERKLE_PADDING",
    "Unused Merkle siblings must be zero",
  );
  requireThat(
    value === toHex(h.slice(36, 68)),
    "BLOCK_MERKLE",
    "Transaction inclusion does not match header",
  );
  const note = o.kind === "created-in-block" ? noteOpening(o.note) : undefined;
  requireThat(
    note !== undefined || o.note === undefined,
    "UNKNOWN_FIELD",
    "Action-only claim must not contain note secrets",
  );
  if (note)
    requireThat(
      limbValue(note.rho) ===
        readLE(
          Uint8Array.from(t.effects.compact_actions[actionIndex].slice(0, 32)),
        ),
      "NOTE_RHO",
      "Created note rho must equal selected Action nullifier",
    );
  return {
    schemaVersion: 1,
    kind: o.kind as InclusionEnvelope["kind"],
    protocol: p,
    checkpoint: c,
    headerHex: toHex(h),
    transaction: t,
    actionIndex,
    transactionIndex,
    transactionCount,
    siblings,
    ...(note ? { note } : {}),
  };
}
export function effectBytes(e: TransactionEffects): number[] {
  return Array.from(
    concat(
      ...e.compact_actions,
      e.memos_digest,
      e.noncompact_digest,
      [e.flags],
      e.value_balance,
      e.transparent_digest,
      e.sapling_digest,
      e.orchard_digest,
      u32(e.lock_time),
      u32(e.expiry_height),
    ),
  );
}
/**
 * options.actions is the Action CAPACITY of the circuit instance, not an exact
 * count. The circuit takes action_count (1 <= action_count <= capacity) and
 * hashes exactly 148 * action_count compact bytes, so zero padding of unused
 * slots does not change the txid. Unused slots must be zero.
 * Slot 68: header1487 || capacity*148 compact Actions || memos32 ||
 * noncompact32 || flags1 || balance8 || transparent32 || sapling32 ||
 * orchard32 || lock4 || expiry4 || depth*32 siblings || actionIndex4 ||
 * txIndex4 || txCount4 || actionCount4 (u32 little-endian).
 */
export function inclusionPayload(
  e: InclusionEnvelope,
  capacity: number,
  depth: number,
): number[] {
  const effects = e.transaction.effects!,
    count = effects.compact_actions.length;
  // A capacity check, not an exact-count check: the circuit binds the exact
  // count through action_count, not through its array length.
  requireThat(
    Number.isInteger(capacity) && count >= 1 && count <= capacity,
    "PROFILE_ACTION_CAPACITY",
    "Transaction Action count does not fit the inclusion Action capacity",
  );
  requireThat(
    Number.isInteger(depth) && depth >= e.siblings.length && depth <= 32,
    "PROFILE_CAPACITY",
    "Inclusion Merkle depth does not fit",
  );
  const bytes = effectBytes(effects),
    compact = 148 * count;
  return [
    ...fromHex(e.headerHex),
    ...bytes.slice(0, compact),
    ...new Array(148 * (capacity - count)).fill(0),
    ...bytes.slice(compact),
    ...e.siblings.flatMap((s) => Array.from(fromHex(s))),
    ...new Array(32 * (depth - e.siblings.length)).fill(0),
    ...u32(e.actionIndex),
    ...u32(e.transactionIndex),
    ...u32(e.transactionCount),
    ...u32(count),
  ];
}
export function prepareInclusion(
  input: unknown,
  options: PreparationOptions & { actions: number; depth: number },
): PreparedInclusionWitness {
  const e = validateInclusion(input),
    address = contractAddress(options.contractAddress),
    effects = e.transaction.effects!;
  const payload = inclusionPayload(e, options.actions, options.depth),
    capsules = [capsule(address, 68, payload)];
  if (e.note) capsules.push(capsule(address, 69, openingFields(e.note)));
  return {
    schemaVersion: 1,
    kind: "prepared-witness",
    claim: e.kind,
    protocol: e.protocol,
    checkpoint: e.checkpoint,
    contractAddress: address,
    arguments: {
      accepted_header_hash: Array.from(fromHex(e.checkpoint.hashLE)),
    },
    capsules,
    validation: {
      structure: true,
      hashBindings: true,
      checkpointAuthorized: false,
      proofVerified: false,
    },
    expected: {
      txidLE: e.transaction.txidLE,
      selectedAction: effects.compact_actions[e.actionIndex],
      actionCount: effects.compact_actions.length,
      actionCapacity: options.actions,
      noteCommitmentCheckedByCircuit: e.kind === "created-in-block",
    },
  };
}
/** Witness for a contract that reads ironwood_aztec::creation::inclusion::<4, 32>
 * and calls ironwood::transactions::verify_nullifier_inclusion: the same
 * slot-68 inclusion layout, and the selected Action's nullifier as expected_nf.
 * The circuit, not the host, checks that the nullifier occurs in the
 * transaction. Takes an action-inclusion envelope. */
export function prepareNullifierInclusion(
  input: unknown,
  options: PreparationOptions & { actions: number; depth: number },
): PreparedNullifierInclusionWitness {
  requireThat(
    options.actions === 4 && options.depth === 32,
    "PROFILE_CAPACITY",
    "Nullifier inclusion reads Action capacity 4 and depth 32",
  );
  const prepared = prepareInclusion(input, options);
  requireThat(
    prepared.claim === "action-inclusion",
    "UNSUPPORTED_CLAIM",
    "Nullifier inclusion takes an action-inclusion envelope",
    "$.kind",
  );
  return {
    ...prepared,
    claim: "nullifier-in-transaction",
    arguments: {
      expected_nf: prepared.expected.selectedAction.slice(0, 32),
      accepted_header_hash: prepared.arguments.accepted_header_hash,
    },
  };
}
