import { requireThat } from "./errors.js";
/** Capsule slot table, the host side of ironwood_aztec's slot table. One slot
 * has one layout at scope zero, so witnesses of different claim kinds at one
 * contract address never overwrite each other. */
export const SLOTS = Object.freeze({
  header: 60,
  note: 61,
  nullifierAbsence: 63,
  viewingAuthority: 64,
  spendingAuthority: 65,
  nullifierAbsenceWithV4: 66,
  nullifierAbsenceState: 67,
  inclusion: 68,
  opening: 69,
  /** Merkle hint level `l` (0..31) is at merkleHints + l. */
  merkleHints: 70,
  noteHashHints: 102,
  memo: 103,
});
/** Claim k at one address reads slot + CLAIM_STRIDE * k (ironwood_aztec::claim_slot).
 * Every slot above is below the stride, so the slots of two claims are disjoint. */
export const CLAIM_STRIDE = 256;
/** Largest claim index whose slots fit the host's 32-bit slot numbers. */
export const MAX_CLAIM = Math.floor((0xffffffff - 0xff) / CLAIM_STRIDE);
/** The slot of a claim-0 slot for claim index `claim`. */
export function claimSlot(slot: number, claim: number): number {
  requireThat(
    Number.isInteger(slot) &&
      slot >= 0 &&
      slot < CLAIM_STRIDE &&
      Number.isInteger(claim) &&
      claim >= 0 &&
      claim <= MAX_CLAIM,
    "CAPSULE_CLAIM",
    "Expected a claim-0 slot and a claim index",
  );
  return slot + CLAIM_STRIDE * claim;
}
