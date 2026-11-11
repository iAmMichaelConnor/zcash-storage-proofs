/** All hex strings are lower-case, without 0x. HashLE means raw/internal bytes,
 * not the reversed human-facing RPC hash. Decimal integers never use JS numbers. */
export type Limbs = [string, string, string];
export type Network = "mainnet" | "testnet";
export interface Protocol {
  pool: "ironwood-v3";
  era: "nu6.3";
  network: Network;
}
export interface Checkpoint {
  height: number;
  hashLE: string;
  policyId: string;
}
export interface Point {
  x: Limbs;
  y: Limbs;
}
export interface NoteOpening {
  receiver: { g_d: Point; pk_d: Point };
  value: string;
  rho: Limbs;
  rseedHex: string;
}
export interface HeaderWitness {
  headerHex: string;
  historyNodeHex: string;
  authRootHex: string;
}
export interface ContentsEnvelope {
  schemaVersion: 1;
  kind: "contents";
  protocol: Protocol;
  checkpoint: Checkpoint;
  header: HeaderWitness;
  note: NoteOpening;
  membership: { position: number; siblings: Limbs[] };
}
/** Actual compact Actions only. Profile encoding performs checked zero padding. */
export interface TransactionEffects {
  compact_actions: number[][];
  memos_digest: number[];
  noncompact_digest: number[];
  flags: number;
  value_balance: number[];
  transparent_digest: number[];
  sapling_digest: number[];
  orchard_digest: number[];
  lock_time: number;
  expiry_height: number;
}
export interface TransactionData {
  version: 4 | 5 | 6;
  txidLE: string;
  effects?: TransactionEffects;
  rawHex?: string;
}
export interface BlockData {
  height: number;
  headerHex: string;
  transactions: TransactionData[];
}
export interface BlocksEnvelope {
  schemaVersion: 1;
  kind: "complete-blocks";
  protocol: Protocol;
  checkpoint: Checkpoint;
  blocks: BlockData[];
}
export interface InclusionEnvelope {
  schemaVersion: 1;
  kind: "action-inclusion" | "created-in-block";
  protocol: Protocol;
  checkpoint: Checkpoint;
  headerHex: string;
  transaction: TransactionData;
  actionIndex: number;
  transactionIndex: number;
  transactionCount: number;
  siblings: string[];
  note?: NoteOpening;
}
export interface Capsule {
  schemaVersion: 1;
  contractAddress: string;
  slot: number;
  scope: "0";
  fields: string[];
}
export interface PreparationOptions {
  contractAddress: string;
}
export interface PreparedBase {
  schemaVersion: 1;
  kind: "prepared-witness";
  protocol: Protocol;
  checkpoint: Checkpoint;
  contractAddress: string;
  capsules: Capsule[];
  validation: {
    structure: true;
    hashBindings: true;
    checkpointAuthorized: false;
    proofVerified: false;
  };
}
export interface ContentsExpected {
  snapshotHeight: number;
  rootLE: string;
  cmxLE?: string;
  value?: string;
  receiver?: NoteOpening["receiver"];
  rho?: Limbs;
  nativeProviderUsed?: boolean;
  /** cmxLE comes from an untrusted native provider; the circuit's cmx is authoritative. */
  cmxSource?: "native-provider-unverified";
}
export interface PreparedContentsWitness extends PreparedBase {
  claim: "contents";
  arguments: {
    expected_hash: number[];
    header_height: number;
    is_testnet: boolean;
  };
  expected: ContentsExpected;
}
export interface PreparedInclusionWitness extends PreparedBase {
  claim: "action-inclusion" | "created-in-block" | "memo-created-in-block";
  arguments: { accepted_header_hash: number[] };
  expected: {
    txidLE: string;
    selectedAction: number[];
    noteCommitmentCheckedByCircuit: boolean;
    /** Exact Action count of the transaction (the circuit's action_count). */
    actionCount: number;
    /** Action capacity of the circuit instance; unused slots are zero. */
    actionCapacity: number;
  };
}
/** Nullifier inclusion: the slot-68 witness and the queried nullifier. */
export interface PreparedNullifierInclusionWitness
  extends Omit<PreparedInclusionWitness, "claim" | "arguments"> {
  claim: "nullifier-in-transaction";
  arguments: { expected_nf: number[]; accepted_header_hash: number[] };
}
export type PreparedWitness =
  | PreparedContentsWitness
  | PreparedInclusionWitness
  | PreparedNullifierInclusionWitness
  | import("./nullifier-absence.js").PreparedNullifierAbsenceWitness;

export interface CheckpointPolicy {
  /** Application policy, not a data source: must reject unaccepted hash/height/network.
   * It receives frozen copies; the host checks that the arguments and header
   * capsule match them before this call. */ authorize(
    checkpoint: Readonly<Checkpoint>,
    protocol: Readonly<Protocol>,
  ): Promise<void>;
}
type DeepReadonly<T> = T extends readonly (infer U)[]
  ? readonly DeepReadonly<U>[]
  : T extends object
    ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
    : T;
/** The checked snapshot's arguments, deep-frozen. Checkpoint-bound values are
 * the values re-derived from the authorised checkpoint and protocol, after a
 * strict equality check against the caller's; free arguments (queried_nf,
 * count, prior_height) are the caller's, type-checked, for the circuit. */
export type AuthorizedArguments = DeepReadonly<PreparedWitness["arguments"]>;
/** A frozen snapshot that passed the host binding checks and the policy. */
export interface AuthorizedWitness {
  readonly claim: PreparedWitness["claim"];
  readonly protocol: Readonly<Protocol>;
  readonly checkpoint: Readonly<Checkpoint>;
  readonly capsules: readonly Readonly<Capsule>[];
  readonly arguments: AuthorizedArguments;
}
export type AffineHintRecord = [Limbs, Limbs, Limbs, Limbs, Limbs];
export interface HashHintResult {
  records: AffineHintRecord[];
  point: Point & { infinity: boolean };
  bottom: boolean;
  message_bits: number;
}
export interface MerkleHintResult {
  records: AffineHintRecord[];
  root: Limbs;
  depth: number;
}
export interface NativeHintProvider {
  hash(input: { domain: 1; message: boolean[] }): Promise<HashHintResult>;
  merkle(input: {
    leaf: Limbs;
    position: number;
    siblings: Limbs[];
  }): Promise<MerkleHintResult>;
}
