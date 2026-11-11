#!/usr/bin/env node
/** Explicit local packaging smoke. No publishing or proof generation. */
import {
  mkdtemp,
  writeFile,
  readFile,
  mkdir,
  stat,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
const root = fileURLToPath(new URL("../", import.meta.url));
const dir = await mkdtemp(join(tmpdir(), "ironwood-package-"));
const evidence = process.argv[2];
function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, {
    cwd,
    encoding: "utf8",
    timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (r.status !== 0) throw Error(`${cmd} failed: ${r.stderr}\n${r.stdout}`);
  return r.stdout;
}
try {
  const packed = JSON.parse(
    run("npm", ["pack", "--json", "--pack-destination", dir], root),
  )[0];
  const consumer = join(dir, "consumer");
  await mkdir(consumer);
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  run(
    "npm",
    [
      "install",
      "--offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(dir, packed.filename),
    ],
    consumer,
  );
  const module = join(
    consumer,
    "node_modules/zcash-storage-proofs",
  );
  const source = `import {prepareContents, prepareMemoCreatedInBlock, listProfiles, type ContentsEnvelope, type PreparedContentsWitness} from 'zcash-storage-proofs';\nimport {installCapsules} from 'zcash-storage-proofs/aztec';\nimport {ToolExecutionError} from 'zcash-storage-proofs/toolchain';\nconst prepare: (value: ContentsEnvelope, options:{contractAddress:string})=>PreparedContentsWitness=prepareContents;\nconsole.log(JSON.stringify({profiles:listProfiles().length,prepare:typeof prepare,memoPreparation:typeof prepareMemoCreatedInBlock,transport:typeof installCapsules,diagnostics:typeof ToolExecutionError}));\n`;
  await writeFile(join(consumer, "smoke.ts"), source);
  run(
    process.execPath,
    [
      join(root, "node_modules/typescript/bin/tsc"),
      "smoke.ts",
      "--strict",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--target",
      "ES2022",
    ],
    consumer,
  );
  const imports = JSON.parse(run(process.execPath, ["smoke.js"], consumer));
  const doctor = JSON.parse(
    run(
      process.execPath,
      [join(module, "bin/ironwood-prepare.mjs"), "doctor"],
      consumer,
    ),
  );
  for (const file of [
    "LICENSE",
    "NOTICE",
    "docs/API.md",
    "docs/COMPOSITION.md",
    "docs/PROTOCOL.md",
    "src/schemas/contents.v1.json",
    "profiles/catalogue.v1.json",
  ])
    await stat(join(module, file));
  // Validate the actual tarball: source-only references must not masquerade
  // as local files, while doc and schema links must remain usable offline.
  for (const { path } of packed.files.filter(({ path }) =>
    path.endsWith(".md"),
  )) {
    const document = join(module, path);
    const text = await readFile(document, "utf8");
    for (const match of text.matchAll(/(?<!!)\[[^\]]+\]\(([^)\s]+)\)/g)) {
      const href = match[1].replace(/^<|>$/g, "");
      if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(href) || href.startsWith("#"))
        continue;
      const target = resolve(
        dirname(document),
        decodeURIComponent(href.split(/[?#]/)[0]),
      );
      if (
        target !== resolve(module) &&
        !target.startsWith(resolve(module) + sep)
      )
        throw Error(
          `Packed documentation escapes its package: ${path}: ${href}`,
        );
      await stat(target);
    }
  }
  const packageMetadata = JSON.parse(
    await readFile(join(module, "package.json"), "utf8"),
  );
  if (
    packageMetadata.license !== "Apache-2.0" ||
    !(await readFile(join(module, "NOTICE"), "utf8")).includes("Michael Connor")
  )
    throw Error("Packed license metadata or attribution is missing");
  const mode =
    (await stat(join(module, "bin/ironwood-prepare.mjs"))).mode & 0o777;
  if (!(mode & 0o111)) throw Error("Packed CLI is not executable");
  const result = {
    schemaVersion: 1,
    status: "PASS",
    tarballSha256: createHash("sha256")
      .update(await readFile(join(dir, packed.filename)))
      .digest("hex"),
    fileCount: packed.files.length,
    unpackedBytes: packed.unpackedSize,
    imports,
    doctor,
    cliMode: mode.toString(8),
    offlineInstall: true,
    published: false,
  };
  if (evidence)
    await writeFile(resolve(evidence), JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify(result));
} finally {
  await rm(dir, { recursive: true, force: true });
}
