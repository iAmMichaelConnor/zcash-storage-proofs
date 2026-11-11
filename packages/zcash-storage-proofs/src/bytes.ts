import { blake2b } from "@noble/hashes/blake2b";
import { sha256 } from "@noble/hashes/sha256";
import { requireThat } from "./errors.js";
export const PALLAS_BASE = BigInt(
  "0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
);
export const PALLAS_SCALAR = BigInt(
  "0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001",
);
export const AZTEC_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export function hex(value: unknown, length?: number, path = "$"): string {
  requireThat(
    typeof value === "string" && /^(?:[0-9a-f]{2})*$/.test(value),
    "HEX",
    "Expected lower-case even-length hex without 0x",
    path,
  );
  requireThat(
    length === undefined || value.length === length * 2,
    "LENGTH",
    `Expected ${length} bytes`,
    path,
  );
  return value;
}
export const fromHex = (v: string): Uint8Array =>
  Uint8Array.from(v.match(/../g) ?? [], (s) => parseInt(s, 16));
export const toHex = (v: Uint8Array | number[]): string =>
  Array.from(v, (x) => x.toString(16).padStart(2, "0")).join("");
export const concat = (...xs: (Uint8Array | number[])[]): Uint8Array =>
  Uint8Array.from(xs.flatMap((x) => Array.from(x)));
export function le(x: bigint, n: number): Uint8Array {
  requireThat(
    x >= 0n && x < 1n << BigInt(8 * n),
    "RANGE",
    "Integer does not fit encoding",
  );
  return Uint8Array.from({ length: n }, (_, i) =>
    Number((x >> BigInt(8 * i)) & 255n),
  );
}
export function readLE(x: Uint8Array): bigint {
  return Array.from(x).reduceRight((v, b) => (v << 8n) + BigInt(b), 0n);
}
export const u32 = (x: number) => le(BigInt(x), 4);
export const sha256d = (x: Uint8Array) => sha256(sha256(x));
export function blake(
  x: Uint8Array,
  personal: string | Uint8Array,
  length = 32,
): Uint8Array {
  return blake2b(x, {
    dkLen: length,
    personalization:
      typeof personal === "string"
        ? new TextEncoder().encode(personal)
        : personal,
  });
}
export function compactSize(
  bytes: Uint8Array,
  offset: number,
): { value: bigint; next: number } {
  requireThat(
    offset >= 0 && offset < bytes.length,
    "TRUNCATED",
    "Missing CompactSize",
  );
  const tag = bytes[offset],
    n = tag < 253 ? 0 : tag === 253 ? 2 : tag === 254 ? 4 : 8;
  requireThat(
    offset + 1 + n <= bytes.length,
    "TRUNCATED",
    "Truncated CompactSize",
  );
  const value = n
    ? readLE(bytes.slice(offset + 1, offset + 1 + n))
    : BigInt(tag);
  requireThat(
    n === 0 || value >= (n === 2 ? 253n : n === 4 ? 65536n : 4294967296n),
    "NONCANONICAL",
    "Noncanonical CompactSize",
  );
  return { value, next: offset + 1 + n };
}
export function rpcHashToLE(value: unknown): string {
  return toHex(fromHex(hex(value, 32)).reverse());
}
