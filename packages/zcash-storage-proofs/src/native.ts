/** Optional native hint adapter. All process execution and secret-file I/O is explicit. */
import { SLOTS } from "./slots.js";
import { mkdtemp, writeFile, rm, chmod } from "node:fs/promises";
import { join, isAbsolute } from "node:path";
import { runTool, type ToolSpec } from "./toolchain.js";
import { PreparationError, requireThat } from "./errors.js";
import {
  blake,
  concat,
  fromHex,
  le,
  PALLAS_BASE as P,
  PALLAS_SCALAR as Q,
  readLE,
  toHex,
} from "./bytes.js";
import {
  validateContents,
  limbValue,
  toLimbs,
  limbs,
  point,
} from "./validation.js";
import { prepareContents, capsule } from "./prepare.js";
import type {
  NativeHintProvider,
  HashHintResult,
  MerkleHintResult,
  Point,
  Limbs,
  AffineHintRecord,
  PreparationOptions,
  PreparedContentsWitness,
} from "./types.js";
export function createNativeHintProvider(options: {
  tool: ToolSpec;
  workDirectory: string;
  timeoutMs?: number;
}): NativeHintProvider {
  requireThat(
    isAbsolute(options.workDirectory),
    "OUTPUT_PATH",
    "Native working directory must be absolute",
  );
  async function call(mode: string, input: unknown): Promise<any> {
    const dir = await mkdtemp(join(options.workDirectory, "ironwood-native-"));
    await chmod(dir, 0o700);
    try {
      const path = join(dir, "input.json");
      await writeFile(path, JSON.stringify(input), { mode: 0o600, flag: "wx" });
      const r = await runTool(options.tool, [mode, path], {
        cwd: dir,
        // The caller's work directory must allow execution; /tmp may be noexec.
        toolDirectory: options.workDirectory,
        timeoutMs: options.timeoutMs,
        maxOutputBytes: 16 * 1024 * 1024,
      });
      try {
        return JSON.parse(r.stdout);
      } catch {
        throw new PreparationError(
          "NATIVE_OUTPUT",
          "Native tool returned invalid JSON",
        );
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
  return {
    hash: (input) => call("--hash-hints", input),
    merkle: (input) => call("--merkle-hints", input),
  };
}
const mod = (x: bigint) => ((x % P) + P) % P;
function inverse(a: bigint): bigint {
  let n = P - 2n,
    b = mod(a),
    x = 1n;
  while (n) {
    if (n & 1n) x = mod(x * b);
    b = mod(b * b);
    n >>= 1n;
  }
  return x;
}
type Affine = [bigint, bigint] | null;
function add(a: Affine, b: Affine): Affine {
  if (!a) return b;
  if (!b) return a;
  const [x, y] = a,
    [u, v] = b;
  if (x === u && (y !== v || y === 0n)) return null;
  const l = mod(
      (x === u ? 3n * x * x : v - y) * inverse(x === u ? 2n * y : u - x),
    ),
    z = mod(l * l - x - u);
  return [z, mod(l * (x - z) - y)];
}
function mul(p: Affine, n: bigint): Affine {
  let r: Affine = null;
  while (n) {
    if (n & 1n) r = add(r, p);
    p = add(p, p);
    n >>= 1n;
  }
  return r;
}
// CommitDomain("z.cash:Orchard-NoteCommit").R(), pinned sinsemilla 0.2.0.
const R: Point = {
  x: [
    "824385905346551206742246074141666835",
    "35112072537048778278202885980156451",
    "9906",
  ],
  y: [
    "1037170815975651730455124483368761315",
    "448066984249512386131804376902256249",
    "15582",
  ],
};
const affine = (p: Point): Affine => [limbValue(p.x), limbValue(p.y)];
const encode = (p: Point) =>
  le(limbValue(p.x) | ((limbValue(p.y) & 1n) << 255n), 32);
const bits = (x: bigint, n: number) =>
  Array.from({ length: n }, (_, i) => Boolean((x >> BigInt(i)) & 1n));
function records(value: unknown, n: number): AffineHintRecord[] {
  requireThat(
    Array.isArray(value) && value.length === n,
    "NATIVE_OUTPUT",
    `Expected ${n} affine records`,
  );
  return Array.from(value, (r, i) => {
    requireThat(
      Array.isArray(r) && r.length === 5,
      "NATIVE_OUTPUT",
      "Expected five fields per record",
    );
    return Array.from(r, (x, j) =>
      limbs(x, `$.records[${i}][${j}]`, j !== 0 && j !== 2),
    ) as AffineHintRecord;
  });
}
/** Derive key-free note PRFs, commitment, path and optional hint capsules.
 * The provider is untrusted. The host does not recompute the Sinsemilla note
 * hash, the Merkle root or the hint records: it checks only their shape, that
 * the point is on the curve, and that the provider root equals the root that
 * the authenticated header opens. A provider that returns any on-curve point
 * and echoes that root passes. So expected.cmxLE is provider-derived
 * (cmxSource "native-provider-unverified"). The Noir circuit derives cmx in
 * constraints and checks every hint; the cmx that the circuit returns is the
 * authoritative value. Do not use cmxLE for bookkeeping before that. */
export async function prepareContentsWithNative(
  input: unknown,
  options: PreparationOptions,
  provider: NativeHintProvider,
  settings: { includeHintCapsules?: boolean } = {},
): Promise<PreparedContentsWitness> {
  const e = validateContents(input),
    prepared = prepareContents(e, options),
    n = e.note,
    rseed = fromHex(n.rseedHex),
    rho = le(limbValue(n.rho), 32),
    gd = encode(n.receiver.g_d),
    pkd = encode(n.receiver.pk_d),
    psi = readLE(blake(concat(rseed, [9], rho), "Zcash_ExpandSeed", 64)) % P,
    rcm =
      readLE(
        blake(
          concat(
            rseed,
            [11],
            gd,
            pkd,
            le(BigInt(n.value), 8),
            rho,
            le(psi, 32),
          ),
          "Zcash_ExpandSeed",
          64,
        ),
      ) % Q,
    message = [
      ...bits(readLE(gd), 256),
      ...bits(readLE(pkd), 256),
      ...bits(BigInt(n.value), 64),
      ...bits(limbValue(n.rho), 255),
      ...bits(psi, 255),
    ];
  const hash: HashHintResult = await provider.hash({ domain: 1, message });
  requireThat(
    hash.message_bits === 1086 &&
      hash.bottom === false &&
      typeof hash.point?.infinity === "boolean",
    "NOTE_COMMITMENT",
    "Native note hash is bottom or malformed",
  );
  const hp = hash.point.infinity
      ? null
      : affine(point({ x: hash.point.x, y: hash.point.y })),
    hints = records(hash.records, 109),
    cm = add(hp, mul(affine(R), rcm));
  const cmx = toLimbs(cm === null ? 0n : cm[0]),
    path: MerkleHintResult = await provider.merkle({
      leaf: cmx,
      position: e.membership.position,
      siblings: e.membership.siblings,
    }),
    pathHints = records(path.records, 1664);
  requireThat(
    path.depth === 32,
    "NATIVE_OUTPUT",
    "Expected complete 32-level path",
  );
  const root = toHex(le(limbValue(limbs(path.root)), 32));
  requireThat(
    root === prepared.expected?.rootLE,
    "NOTE_MEMBERSHIP",
    "Native note root does not match authenticated header opening",
  );
  if (settings.includeHintCapsules) {
    prepared.capsules.push(
      capsule(prepared.contractAddress, SLOTS.noteHashHints, hints.flat(2)),
    );
    for (let level = 0; level < 32; level++)
      prepared.capsules.push(
        capsule(
          prepared.contractAddress,
          SLOTS.merkleHints + level,
          pathHints.slice(52 * level, 52 * (level + 1)).flat(2),
        ),
      );
  }
  prepared.expected = {
    ...prepared.expected,
    cmxLE: toHex(le(limbValue(cmx), 32)),
    value: n.value,
    receiver: n.receiver,
    rho: n.rho,
    nativeProviderUsed: true,
    cmxSource: "native-provider-unverified",
  };
  return prepared;
}
