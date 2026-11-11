#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  prepareContents,
  prepareInclusion,
  prepareRawBlocks,
  prepareNullifierAbsence,
  inspectRawBlock,
  inspectRawTransaction,
  PreparationError,
} from "../dist/index.js";
import {
  createNativeHintProvider,
  prepareContentsWithNative,
} from "../dist/native.js";
const [command, ...args] = process.argv.slice(2);
const opts = {};
try {
  for (let i = 0; i < args.length; i += 2) {
    if (!args[i].startsWith("--") || args[i + 1] === undefined)
      throw new PreparationError("CLI", "Expected --name value arguments");
    const key = args[i].slice(2);
    if (key in opts) throw new PreparationError("CLI", "Duplicate option");
    opts[key] = args[i + 1];
  }
  const allowed = [
    "input",
    "output",
    "contract-address",
    "actions",
    "depth",
    "native",
    "native-sha256",
    "work-directory",
    "hint-capsules",
    "profile",
    "nullifier",
    "operation",
    "prior-height",
    "experimental",
  ];
  if (Object.keys(opts).some((k) => !allowed.includes(k)))
    throw new PreparationError("CLI", "Unknown option");
  if (command === "doctor") {
    process.stdout.write(
      JSON.stringify({
        schemaVersion: 1,
        node: process.version,
        pureHost: true,
        aztecSdk: "caller-supplied",
        noirCommit: "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7",
        protocol: "Ironwood V3 / NU6.3",
        automaticProofGeneration: false,
      }) + "\n",
    );
    process.exit(0);
  }
  if (!opts.input || !opts.output)
    throw new PreparationError(
      "CLI",
      "Use prepare|prepare-nullifier-absence|normalize-blocks|inspect-raw-block|inspect-raw-transaction --input FILE --output NEW_FILE",
    );
  const input = JSON.parse(await readFile(resolve(opts.input), "utf8"));
  let output;
  if (command === "prepare") {
    if (!opts["contract-address"])
      throw new PreparationError(
        "CLI",
        "Explicit --contract-address decimal or SDK hex address required",
      );
    const options = { contractAddress: opts["contract-address"] };
    if (input.kind === "contents") {
      if (opts.native) {
        if (!opts["native-sha256"] || !opts["work-directory"])
          throw new PreparationError(
            "CLI",
            "Native provider requires --native-sha256 and --work-directory",
          );
        const provider = createNativeHintProvider({
          tool: { path: resolve(opts.native), sha256: opts["native-sha256"] },
          workDirectory: resolve(opts["work-directory"]),
        });
        if (
          opts["hint-capsules"] &&
          !["true", "false"].includes(opts["hint-capsules"])
        )
          throw new PreparationError(
            "CLI",
            "hint-capsules must be true or false",
          );
        output = await prepareContentsWithNative(input, options, provider, {
          includeHintCapsules: opts["hint-capsules"] === "true",
        });
      } else output = prepareContents(input, options);
    } else
      output = prepareInclusion(input, {
        ...options,
        // --actions is the Action capacity of the circuit instance.
        actions: Number(opts.actions),
        depth: Number(opts.depth),
      });
  } else if (command === "prepare-nullifier-absence") {
    if (opts.experimental && !["true", "false"].includes(opts.experimental))
      throw new PreparationError("CLI", "experimental must be true or false");
    output = prepareNullifierAbsence(input, {
      contractAddress: opts["contract-address"],
      profileId: opts.profile,
      queriedNullifierLE: opts.nullifier,
      operation: opts.operation,
      priorHeight:
        opts["prior-height"] === undefined
          ? undefined
          : Number(opts["prior-height"]),
      allowExperimentalProfile: opts.experimental === "true",
    });
  } else if (command === "normalize-blocks") output = prepareRawBlocks(input);
  else if (command === "inspect-raw-block")
    output = inspectRawBlock(input.rawHex);
  else if (command === "inspect-raw-transaction")
    output = inspectRawTransaction(input.rawHex);
  else throw new PreparationError("CLI", "Unsupported command");
  await writeFile(
    resolve(opts.output),
    JSON.stringify(output, null, 2) + "\n",
    { flag: "wx", mode: 0o600 },
  );
  process.stdout.write(
    "Prepared offline witness/inspection; no checkpoint authorization or proof verification.\n",
  );
} catch (e) {
  process.stderr.write(
    JSON.stringify(
      e instanceof PreparationError
        ? { error: e.code, path: e.path, message: e.message }
        : {
            error: "IO_OR_RUNTIME",
            message:
              "Operation failed; existing outputs are never overwritten. Check caller-owned paths and permissions.",
          },
    ) + "\n",
  );
  process.exitCode = 1;
}
