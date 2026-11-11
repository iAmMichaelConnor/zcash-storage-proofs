/** SDK-independent transport. The application supplies its own pinned Aztec adapter. */
import type {
  PreparedBase,
  Capsule,
  CheckpointPolicy,
  AuthorizedArguments,
} from "./types.js";
import { contractAddress } from "./validation.js";
import { serializeCapsules } from "./serialization.js";
import { authorizeWitness } from "./prepare.js";
import { requireThat } from "./errors.js";
import { claimSlot } from "./slots.js";
/** Deliver every capsule as a transient capsule of one transaction (for
 * example `.with({ capsules })`), never as a persistent contract capsule:
 * scope zero is global to every account of a PXE. */
export interface CapsuleTransport {
  setCapsule(capsule: Readonly<Capsule>): Promise<void>;
}
/** One witness of a transaction: the contract that reads it and the claim
 * index (default 0) that the contract passes to the library. The shipped
 * adapter contracts read claim 0 only. */
export interface ClaimInstall {
  prepared: PreparedBase;
  targetAddress: string;
  claim?: number;
}
/** Scan contracts read fixed slots; they take no claim index. */
const FIXED_SLOT_CLAIMS = new Set([
  "nullifier-absence-from-activation",
  "nullifier-absence-window",
]);
/** Installs the witnesses of one transaction together. Each witness passes
 * authorizeWitness; its capsules are rebound to its address and claim slots.
 * Any (contract, slot, scope) used twice, across witnesses too, is rejected
 * before a capsule is written: a PXE serves the first match, so a reused key
 * would give a second claim the first claim's witness or overwrite it.
 * Returns the frozen arguments of each witness, in order. */
export async function installClaims(
  claims: readonly ClaimInstall[],
  transport: CapsuleTransport,
  policy: CheckpointPolicy,
): Promise<AuthorizedArguments[]> {
  const all: Capsule[] = [],
    args: AuthorizedArguments[] = [];
  for (const { prepared, targetAddress, claim = 0 } of claims) {
    const address = contractAddress(targetAddress);
    const authorized = await authorizeWitness(prepared, policy);
    requireThat(
      claim === 0 || !FIXED_SLOT_CLAIMS.has(authorized.claim),
      "CAPSULE_CLAIM",
      "Scan witnesses use claim 0",
    );
    for (const c of authorized.capsules)
      all.push({
        ...c,
        contractAddress: address,
        slot: claimSlot(c.slot, claim),
        fields: [...c.fields],
      });
    args.push(authorized.arguments);
  }
  serializeCapsules(all);
  for (const c of all) await transport.setCapsule(c);
  return args;
}
/** Address rebinding is explicit; capsules are witness hints, not authorization.
 * Installs only the checked snapshot (see authorizeWitness) and returns its
 * frozen arguments; pass those to the private function. For several claims in
 * one transaction, use installClaims. */
export async function installCapsules(
  prepared: PreparedBase,
  targetAddress: string,
  transport: CapsuleTransport,
  policy: CheckpointPolicy,
): Promise<AuthorizedArguments> {
  const [args] = await installClaims(
    [{ prepared, targetAddress }],
    transport,
    policy,
  );
  return args;
}
