import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  listProfiles,
  getProfile,
  assertProfileFits,
  validateCapacityShape,
  validateProfileCapacities,
  profileCatalogue,
  inspectBlocks,
} from "../dist/profiles.js";
const small = {
  blocks: 2,
  transactionsPerBlock: 4,
  actionsPerTransaction: 2,
  legacyBytesPerTransaction: 256,
};
const error = (fn, code) => assert.throws(fn, (e) => e.code === code);
test("catalogue export equals pinned JSON and is deeply immutable", () => {
  assert.deepEqual(
    profileCatalogue,
    JSON.parse(
      fs.readFileSync(
        new URL("../profiles/catalogue.v1.json", import.meta.url),
      ),
    ),
  );
  assert.ok(Object.isFrozen(profileCatalogue));
  assert.ok(Object.isFrozen(listProfiles()[0].validation));
  error(() => getProfile("unknown"), "UNKNOWN_PROFILE");
});
test("profile fit preserves each capacity and exact block coverage", () => {
  const p = getProfile("nullifier-absence-2b-4t-2a-256r-v1");
  assertProfileFits(p, small);
  for (const k of Object.keys(small))
    error(
      () => assertProfileFits(p, { ...small, [k]: small[k] + 1 }),
      "CAPACITY_OVERFLOW",
    );
  error(
    () => assertProfileFits(p, { ...small, blocks: 1 }),
    "EXACT_BLOCK_COUNT",
  );
  assertProfileFits(p, {
    ...small,
    transactionsPerBlock: 1,
    actionsPerTransaction: 0,
    legacyBytesPerTransaction: 0,
  });
  assertProfileFits(getProfile("nullifier-absence-state-2b-4t-2a-256r-v1"), {
    ...small,
    blocks: 1,
  });
});
test("malformed capacities and block envelopes are rejected", () => {
  for (const n of [-1, 0.1, NaN, Infinity, 4294967296])
    error(
      () => validateCapacityShape({ ...small, blocks: n }),
      "INVALID_CAPACITY",
    );
  error(
    () => validateCapacityShape({ ...small, blocks: 0 }),
    "INVALID_CAPACITY",
  );
  error(() => inspectBlocks({ schemaVersion: 2 }), "SCHEMA_VERSION");
});
test("catalogue capacities must give a satisfiable circuit", () => {
  // merkle::complete_root asserts a power-of-two transaction capacity.
  for (const transactionsPerBlock of [3, 5, 6, 7, 12, 4294967295])
    error(
      () => validateProfileCapacities({ ...small, transactionsPerBlock }),
      "INVALID_PROFILE_CAPACITY",
    );
  for (const legacyBytesPerTransaction of [1, 69])
    error(
      () => validateProfileCapacities({ ...small, legacyBytesPerTransaction }),
      "INVALID_PROFILE_CAPACITY",
    );
  error(
    () => validateProfileCapacities({ ...small, actionsPerTransaction: 0 }),
    "INVALID_PROFILE_CAPACITY",
  );
  error(
    () => validateProfileCapacities({ ...small, transactionsPerBlock: 0 }),
    "INVALID_CAPACITY",
  );
  for (const transactionsPerBlock of [1, 2, 4, 8, 2147483648])
    validateProfileCapacities({ ...small, transactionsPerBlock });
  validateProfileCapacities({ ...small, legacyBytesPerTransaction: 0 });
  for (const p of listProfiles())
    if (p.capacities) validateProfileCapacities(p.capacities);
  // An observed block may hold any count up to the capacity.
  assertProfileFits(getProfile("nullifier-absence-2b-4t-2a-256r-v1"), {
    ...small,
    transactionsPerBlock: 3,
  });
});
