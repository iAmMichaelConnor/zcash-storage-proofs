import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  prepareMemoCreatedInBlock,
  validateMemoCiphertexts,
} from "../dist/index.js";
const fixture = JSON.parse(
  fs.readFileSync(
    new URL("fixtures/memo-host-input.json", import.meta.url),
  ),
);
const options = {
  contractAddress: "0x" + "01".repeat(32),
  actions: 1,
  depth: 32,
};
const fresh = () => structuredClone(fixture);
test("memo preparation uses exact ciphertext sequence and capsules, never bulk arguments", () => {
  const result = prepareMemoCreatedInBlock(fresh(), options);
  assert.equal(result.claim, "memo-created-in-block");
  assert.deepEqual(
    result.capsules.map((c) => c.slot),
    [68, 69, 103],
  );
  assert.equal(result.capsules[2].fields.length, 555 + 724);
  assert.deepEqual(Object.keys(result.arguments), ["accepted_header_hash"]);
  assert.equal(result.validation.hashBindings, true);
  assert.equal(result.validation.memoEncryptionChecked, false);
  assert.equal(result.validation.rawReceiverChecked, false);
  assert.equal(result.validation.checkpointAuthorized, false);
});
test("memo preparation rejects missing and extra Actions", () => {
  const x = fresh();
  x.actions = [];
  assert.throws(() => prepareMemoCreatedInBlock(x, options), /Action count/);
  const y = fresh();
  y.actions.push(y.actions[0]);
  assert.throws(() => prepareMemoCreatedInBlock(y, options), /every Action/);
});
test("memo preparation rejects compact, memo, tag and noncompact tampering", () => {
  for (const [field, index] of [
    ["encrypted_note", 0],
    ["encrypted_note", 52],
    ["encrypted_note", 564],
    ["value_commitment", 0],
    ["randomized_key", 0],
    ["outgoing_ciphertext", 0],
  ]) {
    const x = fresh();
    x.actions[0][field][index] ^= 1;
    assert.throws(
      () => prepareMemoCreatedInBlock(x, options),
      /mismatch|differs/,
    );
  }
});
test("memo preparation rejects omitted tag and non-byte data", () => {
  const x = fresh();
  x.actions[0].encrypted_note.length = 564;
  assert.throws(() => prepareMemoCreatedInBlock(x, options), /580/);
  const y = fresh();
  y.actions[0].encrypted_note[0] = 256;
  assert.throws(() => validateMemoCiphertexts(y.actions));
});
test("memo preparation does not accept a caller-supplied symmetric key", () => {
  const x = fresh();
  x.keyHex = "00".repeat(32);
  assert.throws(
    () => prepareMemoCreatedInBlock(x, options),
    /Unsupported field/,
  );
});
test("memo plaintext and receiver remain explicit circuit obligations", () => {
  const x = fresh();
  x.memoHex = "ff".repeat(512);
  x.rawReceiverHex = "00".repeat(43);
  const result = prepareMemoCreatedInBlock(x, options);
  assert.equal(result.validation.memoEncryptionChecked, false);
  assert.equal(result.validation.rawReceiverChecked, false);
});
test("memo preparation rejects a substituted accepted header", () => {
  const x = fresh();
  x.inclusion.checkpoint.hashLE = "00".repeat(32);
  assert.throws(
    () => prepareMemoCreatedInBlock(x, options),
    /match checkpoint/,
  );
});
test("memo preparation zero-pads the memo slot (103) to the Action capacity", () => {
  const p = prepareMemoCreatedInBlock(fresh(), { ...options, actions: 3 });
  const slot = (n) => p.capsules.find((c) => c.slot === n).fields.map(Number);
  const memo = slot(103);
  assert.equal(memo.length, 555 + 724 * 3);
  assert.ok(memo.slice(555 + 724).every((x) => x === 0));
  assert.ok(memo.slice(555, 555 + 724).some((x) => x !== 0));
  assert.equal(slot(68).length, 1680 + 148 * 3 + 32 * options.depth);
  assert.deepEqual(slot(68).slice(-4), [1, 0, 0, 0]);
});
