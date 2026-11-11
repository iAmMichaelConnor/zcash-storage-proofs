import { SLOTS } from "./slots.js";
import { blake, concat, fromHex, hex, toHex } from "./bytes.js";
import { requireThat } from "./errors.js";
import { bytes, object } from "./validation.js";
import { prepareInclusion, validateInclusion } from "./transactions.js";
import { capsule } from "./prepare.js";
import type { PreparationOptions } from "./types.js";

export interface FullActionCiphertext {
  encrypted_note: number[];
  value_commitment: number[];
  randomized_key: number[];
  outgoing_ciphertext: number[];
}

/** Validate complete ordered preimages; never pad or truncate the Action list. */
export function validateMemoCiphertexts(
  input: unknown,
): FullActionCiphertext[] {
  requireThat(
    Array.isArray(input),
    "TYPE",
    "Expected complete Action ciphertext array",
  );
  requireThat(
    input.length > 0 && input.length <= Math.floor(2000000 / 820),
    "CAPACITY",
    "Invalid Action count",
  );
  return input.map((row, i) => {
    const x = object(
      row,
      [
        "encrypted_note",
        "value_commitment",
        "randomized_key",
        "outgoing_ciphertext",
      ],
      `$.actions[${i}]`,
    );
    return {
      encrypted_note: bytes(x.encrypted_note, 580),
      value_commitment: bytes(x.value_commitment, 32),
      randomized_key: bytes(x.randomized_key, 32),
      outgoing_ciphertext: bytes(x.outgoing_ciphertext, 80),
    };
  });
}

/**
 * Prepare the pinned Ironwood V3 / transaction V6 memo composition.
 * The existing created-in-block envelope supplies the note and authenticated
 * transaction witness. This function checks structure and transaction hashes;
 * the Noir circuit MUST check raw receiver derivation, commitment, key and AEAD.
 * Additional private payload is in capsule 103, not private function arguments.
 */
export function prepareMemoCreatedInBlock(
  input: unknown,
  options: PreparationOptions & { actions: number; depth: number },
) {
  const x = object(input, [
    "inclusion",
    "rawReceiverHex",
    "memoHex",
    "actions",
  ]);
  const inclusion = validateInclusion(x.inclusion);
  requireThat(
    inclusion.kind === "created-in-block",
    "CLAIM",
    "Memo requires a created-in-block note witness",
  );
  requireThat(
    inclusion.transaction.version === 6,
    "TRANSACTION_VERSION",
    "Memo profile requires transaction V6",
  );
  const raw = fromHex(hex(x.rawReceiverHex, 43));
  const memo = fromHex(hex(x.memoHex, 512));
  const full = validateMemoCiphertexts(x.actions);
  const effects = inclusion.transaction.effects!;
  requireThat(
    full.length === effects.compact_actions.length,
    "MEMO_ACTION_COUNT",
    "Memo ciphertexts must cover every Action in order",
  );
  for (let i = 0; i < full.length; i++) {
    requireThat(
      toHex(full[i].encrypted_note.slice(0, 52)) ===
        toHex(effects.compact_actions[i].slice(96)),
      "CIPHERTEXT_PREFIX",
      "Ciphertext prefix differs from committed Action",
    );
  }
  const memoDigest = blake(
    concat(...full.map((a) => a.encrypted_note.slice(52, 564))),
    "ZTxIdIrnActMH_v6",
  );
  const noncompactDigest = blake(
    concat(
      ...full.map((a) =>
        concat(
          a.value_commitment,
          a.randomized_key,
          a.encrypted_note.slice(564),
          a.outgoing_ciphertext,
        ),
      ),
    ),
    "ZTxIdIrnActNH_v6",
  );
  requireThat(
    toHex(memoDigest) === toHex(effects.memos_digest),
    "MEMO_DIGEST",
    "Memo ciphertext sequence digest mismatch",
  );
  requireThat(
    toHex(noncompactDigest) === toHex(effects.noncompact_digest),
    "NONCOMPACT_DIGEST",
    "Noncompact Action sequence digest mismatch",
  );
  const prepared = prepareInclusion(x.inclusion, options);
  // Memo slot (103): raw receiver43 || memo512 || capacity * (ciphertext580 || cv32 ||
  // rk32 || out80). Entries at and after the Action count are all zero; the
  // circuit hashes only the first action_count entries and checks the padding.
  const fields = [
    ...raw,
    ...memo,
    ...full.flatMap((a) => [
      ...a.encrypted_note,
      ...a.value_commitment,
      ...a.randomized_key,
      ...a.outgoing_ciphertext,
    ]),
    ...new Array(724 * (options.actions - full.length)).fill(0),
  ];
  return {
    ...prepared,
    claim: "memo-created-in-block" as const,
    capsules: [
      ...prepared.capsules,
      capsule(prepared.contractAddress, SLOTS.memo, fields),
    ],
    memoWitness: {
      raw_receiver: Array.from(raw),
      memo: Array.from(memo),
      full,
    },
    validation: {
      ...prepared.validation,
      memoEncryptionChecked: false,
      rawReceiverChecked: false,
    },
  };
}
