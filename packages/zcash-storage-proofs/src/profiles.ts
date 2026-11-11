import { PreparationError } from "./errors.js";
import { validateBlocks } from "./transactions.js";
import { PROFILE_CATALOGUE } from "./profile-catalogue.js";

export interface CapacityShape {
  blocks: number;
  transactionsPerBlock: number;
  actionsPerTransaction: number;
  legacyBytesPerTransaction: number;
}
export type HintTransport = "ordinary" | "capsule";
export interface Profile {
  readonly id: string;
  readonly claim: string;
  readonly generationKind: string;
  readonly sourcePackage: string | null;
  readonly hintTransport: HintTransport;
  readonly capacities: CapacityShape | null;
  readonly blockCount: "none" | "exact" | "up-to";
  readonly transactionVersions: readonly number[];
  readonly selectable: boolean;
  readonly validation: {
    readonly status: string;
    readonly evidence: readonly string[];
    readonly functions: readonly unknown[];
  };
  readonly verificationKey: unknown;
  readonly actionCount?: number;
  readonly proofBytes?: number;
  readonly limitations?: readonly string[];
}
const dimensions = [
  "blocks",
  "transactionsPerBlock",
  "actionsPerTransaction",
  "legacyBytesPerTransaction",
] as const;
function freeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
/** Check a catalogue capacity, which sizes a generated circuit, not an observed shape.
 * ironwood decoders assert at least one block and transaction, and
 * merkle::complete_root asserts a power-of-two transaction capacity; any other
 * capacity gives a circuit that rejects every input. Observed blocks may hold
 * any transaction count up to the capacity (validateCapacityShape). */
export function validateProfileCapacities(
  capacities: CapacityShape,
): CapacityShape {
  validateCapacityShape(capacities);
  const fail = (key: string, message: string) => {
    throw new PreparationError(
      "INVALID_PROFILE_CAPACITY",
      message,
      key ? `$.capacities.${key}` : "$.capacities",
    );
  };
  if (Object.keys(capacities).length !== dimensions.length)
    fail("", "Profile capacities must have exactly the four dimensions");
  let odd = capacities.transactionsPerBlock;
  while (odd % 2 === 0) odd /= 2;
  if (odd !== 1)
    fail("transactionsPerBlock", "transactionsPerBlock must be a power of two");
  if (capacities.actionsPerTransaction < 1)
    fail("actionsPerTransaction", "actionsPerTransaction must be at least 1");
  const r = capacities.legacyBytesPerTransaction;
  if (r !== 0 && r < 70)
    fail(
      "legacyBytesPerTransaction",
      "legacyBytesPerTransaction must be 0 or at least 70",
    );
  return { ...capacities };
}
for (const profile of PROFILE_CATALOGUE.profiles as readonly Profile[]) {
  const scan =
    profile.generationKind === "nullifier-absence" ||
    profile.generationKind === "nullifier-absence-state";
  if (scan || profile.capacities !== null)
    validateProfileCapacities(profile.capacities as CapacityShape);
}
freeze(PROFILE_CATALOGUE);
export const profileCatalogue = PROFILE_CATALOGUE;
export function listProfiles(): readonly Profile[] {
  return PROFILE_CATALOGUE.profiles;
}
export function getProfile(id: string): Profile {
  const profile = listProfiles().find((p) => p.id === id);
  if (!profile)
    throw new PreparationError(
      "UNKNOWN_PROFILE",
      `Unknown profile: ${id}`,
      "$.profile",
    );
  return profile;
}
export function validateCapacityShape(shape: CapacityShape): CapacityShape {
  if (!shape || typeof shape !== "object")
    throw new PreparationError(
      "INVALID_CAPACITY",
      "Capacity shape must be an object",
      "$.shape",
    );
  for (const key of dimensions) {
    const n = shape[key];
    const minimum = key === "blocks" || key === "transactionsPerBlock" ? 1 : 0;
    if (!Number.isSafeInteger(n) || n < minimum || n > 0xffffffff)
      throw new PreparationError(
        "INVALID_CAPACITY",
        `${key} must be an integer between ${minimum} and 4294967295`,
        `$.shape.${key}`,
      );
  }
  return { ...shape };
}
/** Shape inspection never authorizes a checkpoint or proves complete acquisition. */
export function assertProfileFits(
  profile: Profile,
  shape: CapacityShape,
): void {
  validateCapacityShape(shape);
  const capacity = profile.capacities;
  if (!capacity)
    throw new PreparationError(
      "PROFILE_HAS_NO_SCAN_CAPACITY",
      `${profile.id} is not a scan profile`,
      "$.profile",
    );
  for (const key of dimensions) {
    if (shape[key] > capacity[key])
      throw new PreparationError(
        "CAPACITY_OVERFLOW",
        `${key}=${shape[key]} exceeds ${profile.id} capacity ${capacity[key]}; data must not be truncated`,
        `$.shape.${key}`,
      );
  }
  if (profile.blockCount === "exact" && shape.blocks !== capacity.blocks)
    throw new PreparationError(
      "EXACT_BLOCK_COUNT",
      `${profile.id} requires exactly ${capacity.blocks} complete blocks; padding cannot replace coverage`,
      "$.shape.blocks",
    );
}
/** Validate the complete block/hash envelope before calculating its required shape.
 * A fitting shape does not authorize the explicit checkpoint policy. */
export function inspectBlocks(input: unknown): CapacityShape {
  const envelope = validateBlocks(input);
  const shape: CapacityShape = {
    blocks: envelope.blocks.length,
    transactionsPerBlock: 0,
    actionsPerTransaction: 0,
    legacyBytesPerTransaction: 0,
  };
  for (const block of envelope.blocks) {
    shape.transactionsPerBlock = Math.max(
      shape.transactionsPerBlock,
      block.transactions.length,
    );
    for (const transaction of block.transactions) {
      shape.actionsPerTransaction = Math.max(
        shape.actionsPerTransaction,
        transaction.effects?.compact_actions.length ?? 0,
      );
      shape.legacyBytesPerTransaction = Math.max(
        shape.legacyBytesPerTransaction,
        transaction.version === 4 ? transaction.rawHex!.length / 2 : 0,
      );
    }
  }
  return shape;
}
