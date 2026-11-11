import { PALLAS_BASE, fromHex, hex, readLE, toHex, u32 } from "./bytes.js";
import { requireThat } from "./errors.js";
import { NU63 } from "./headers.js";
import { capsule } from "./prepare.js";
import { getProfile, assertProfileFits, inspectBlocks } from "./profiles.js";
import { effectBytes, validateBlocks } from "./transactions.js";
import { contractAddress, integer } from "./validation.js";
import type { PreparedBase } from "./types.js";
/** Block hash in display order of the block before NU6.3 activation (heights 3,428,142 and
 * 4,133,999). `nullifier_absence.nr` pins the same hashes in internal byte order. A scan from activation
 * must link to it, or the circuit rejects the witness. */
const PRE_ACTIVATION_DISPLAY = {
  mainnet: "00000000008b2ffd813f6a09372b4c9da20caad248245086445c19770ac270dd",
  testnet: "00001c94671d8de17537daf700e1c11eefd22645344d0a0c77065ed621539feb",
} as const;
/** Last testnet height of the NU6.3 epoch (`TESTNET_LAST_NU63_HEIGHT` in `nullifier_absence.nr`). */
export const TESTNET_LAST_NU63_HEIGHT = 4465025;
export function preActivationHashLE(network: "mainnet" | "testnet"): string {
  return toHex(fromHex(PRE_ACTIVATION_DISPLAY[network]).reverse());
}
export interface PreparedNullifierAbsenceWitness extends PreparedBase {
  claim: "nullifier-absence-from-activation" | "nullifier-absence-window";
  operation: "verify" | "begin" | "extend";
  profileId: string;
  arguments: {
    queried_nf: number[];
    expected_tip_hash: number[];
    expected_tip_height: number;
    is_testnet: boolean;
    count?: number;
    prior_height?: number;
  };
  authenticatedPriorStateRequired: boolean;
}
/** Complete coverage only. Never truncates transactions or substitutes padded blocks.
 * A state window is not global absence until the contract authenticates its prior note. */
export function prepareNullifierAbsence(
  input: unknown,
  options: {
    profileId: string;
    contractAddress: string;
    queriedNullifierLE: string;
    operation?: "verify" | "begin" | "extend";
    priorHeight?: number;
    allowExperimentalProfile?: boolean;
  },
): PreparedNullifierAbsenceWitness {
  const e = validateBlocks(input),
    shape = inspectBlocks(e),
    profile = getProfile(options.profileId);
  requireThat(
    profile.generationKind === "nullifier-absence" ||
      profile.generationKind === "nullifier-absence-state",
    "UNSUPPORTED_PROFILE_CLAIM",
    "Expected scan profile",
  );
  assertProfileFits(profile, shape);
  requireThat(
    options.allowExperimentalProfile === true ||
      (profile.selectable && profile.validation.status === "validated-private"),
    "NO_VALIDATED_PROFILE",
    "Profile is not released; explicit experimental preparation required",
  );
  const c = profile.capacities!,
    state = profile.generationKind === "nullifier-absence-state",
    mixed = state || c.legacyBytesPerTransaction > 0,
    nf = hex(options.queriedNullifierLE, 32),
    address = contractAddress(options.contractAddress),
    operation = options.operation ?? (state ? "begin" : "verify");
  // On-chain nullifiers are canonical little-endian encodings below the Pallas
  // base modulus p. nf + k*p never occurs on chain, so a scan for such an
  // alias always succeeds. Never reduce modulo p silently.
  requireThat(
    readLE(fromHex(nf)) < PALLAS_BASE,
    "NONCANONICAL_NULLIFIER",
    "Queried nullifier is not a canonical Pallas base field encoding",
  );
  requireThat(
    state
      ? operation === "begin" || operation === "extend"
      : operation === "verify",
    "NULLIFIER_ABSENCE_OPERATION",
    "Operation does not match profile",
  );
  const activation =
    e.protocol.network === "mainnet"
      ? NU63.mainnetActivation
      : NU63.testnetActivation;
  // The circuit rejects a testnet tip past the NU6.3 epoch in every operation.
  requireThat(
    e.protocol.network !== "testnet" ||
      e.checkpoint.height <= TESTNET_LAST_NU63_HEIGHT,
    "NULLIFIER_ABSENCE_EPOCH",
    "Testnet scan ends past the last NU6.3 height",
  );
  if (operation === "extend") {
    requireThat(
      options.priorHeight !== undefined,
      "PRIOR_STATE",
      "Explicit prior note height required",
    );
    requireThat(
      integer(options.priorHeight, 0xffffffff) + 1 === e.blocks[0].height,
      "CHAIN_HEIGHT",
      "Prior height does not precede complete window",
    );
  } else {
    requireThat(
      e.blocks[0].height === activation,
      "NULLIFIER_ABSENCE_COVERAGE",
      "Initial scan must start at Ironwood activation",
    );
    // Bytes 4..36 of a header hold the parent hash in internal byte order.
    requireThat(
      toHex(fromHex(e.blocks[0].headerHex).slice(4, 36)) ===
        preActivationHashLE(e.protocol.network),
      "NULLIFIER_ABSENCE_PREDECESSOR",
      "First block does not link to the pinned pre-activation block",
    );
  }
  const rowLength =
      (mixed ? 189 + c.legacyBytesPerTransaction : 185) +
      148 * c.actionsPerTransaction,
    blockLength = 1491 + c.transactionsPerBlock * rowLength,
    payload: number[] = [];
  for (const b of e.blocks) {
    payload.push(...fromHex(b.headerHex), ...u32(b.transactions.length));
    for (const t of b.transactions) {
      requireThat(
        profile.transactionVersions.includes(t.version),
        "TRANSACTION_VERSION",
        "Profile does not support transaction version",
      );
      let row: number[];
      if (t.version === 4) {
        requireThat(mixed, "TRANSACTION_VERSION", "V4 needs a mixed profile");
        row = [
          ...new Array(177 + 148 * c.actionsPerTransaction).fill(0),
          ...u32(4),
          ...u32(0),
        ];
      } else {
        const fx = t.effects!,
          count = fx.compact_actions.length;
        for (const action of fx.compact_actions)
          requireThat(
            toHex(action.slice(0, 32)) !== nf,
            "NULLIFIER_PRESENT",
            "Queried nullifier occurs in complete transaction list",
          );
        const data = effectBytes(fx);
        row = [
          ...data.slice(0, 148 * count),
          ...new Array(148 * (c.actionsPerTransaction - count)).fill(0),
          ...data.slice(148 * count),
          ...u32(t.version),
          ...u32(count),
        ];
      }
      if (mixed) {
        const raw = t.version === 4 ? Array.from(fromHex(t.rawHex!)) : [];
        row.push(
          ...u32(raw.length),
          ...raw,
          ...new Array(c.legacyBytesPerTransaction - raw.length).fill(0),
        );
      }
      requireThat(
        row.length === rowLength,
        "INTERNAL_LAYOUT",
        "Scan row length mismatch",
      );
      payload.push(...row);
    }
    payload.push(
      ...new Array(
        (c.transactionsPerBlock - b.transactions.length) * rowLength,
      ).fill(0),
    );
  }
  if (state)
    payload.push(
      ...new Array((c.blocks - e.blocks.length) * blockLength).fill(0),
    );
  requireThat(
    payload.length === c.blocks * blockLength,
    "INTERNAL_LAYOUT",
    "Scan capsule length mismatch",
  );
  const args: PreparedNullifierAbsenceWitness["arguments"] = {
    queried_nf: Array.from(fromHex(nf)),
    expected_tip_hash: Array.from(fromHex(e.checkpoint.hashLE)),
    expected_tip_height: e.checkpoint.height,
    is_testnet: e.protocol.network === "testnet",
  };
  if (state) args.count = e.blocks.length;
  if (operation === "extend") args.prior_height = options.priorHeight;
  return {
    schemaVersion: 1,
    kind: "prepared-witness",
    claim: state
      ? "nullifier-absence-window"
      : "nullifier-absence-from-activation",
    profileId: profile.id,
    operation,
    protocol: e.protocol,
    checkpoint: e.checkpoint,
    contractAddress: address,
    arguments: args,
    capsules: [capsule(address, state ? 67 : mixed ? 66 : 63, payload)],
    validation: {
      structure: true,
      hashBindings: true,
      checkpointAuthorized: false,
      proofVerified: false,
    },
    authenticatedPriorStateRequired: operation === "extend",
  };
}
