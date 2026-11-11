/** Optional Node adapter. Importing does not launch processes or touch the filesystem. */
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { lstat, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join } from "node:path";
import { PreparationError, requireThat } from "./errors.js";
export interface ToolSpec {
  path: string;
  sha256: string;
}
export interface RunOptions {
  cwd: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  env?: Record<string, string>;
  signal?: AbortSignal;
  /** Absolute existing directory that holds the private copy of the tool. Default: os.tmpdir().
   * Set it where the filesystem allows execution, because a noexec temporary directory
   * makes the spawn fail. A new 0700 subdirectory is created in it and removed afterwards. */
  toolDirectory?: string;
}
export interface ToolResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
/** Captured diagnostics are available to the caller, never printed implicitly. */
export class ToolExecutionError extends PreparationError {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number | null;
  readonly signal: string | null;
  constructor(
    code: string,
    message: string,
    diagnostics: {
      stdout: string;
      stderr: string;
      exitCode: number | null;
      signal: string | null;
    },
  ) {
    super(code, message);
    this.name = "ToolExecutionError";
    this.stdout = diagnostics.stdout;
    this.stderr = diagnostics.stderr;
    this.exitCode = diagnostics.exitCode;
    this.signal = diagnostics.signal;
  }
}
/**
 * Reads the pinned tool once and returns the bytes that match the pin.
 * The path must be an absolute regular file, not a symbolic link, and not
 * group- or world-writable. The file is opened with O_NOFOLLOW and the open
 * descriptor must be the file that lstat checked.
 */
async function readPinnedTool(tool: ToolSpec): Promise<Buffer> {
  requireThat(isAbsolute(tool.path), "TOOL_PATH", "Tool path must be absolute");
  requireThat(
    /^[0-9a-f]{64}$/.test(tool.sha256),
    "TOOL_PIN",
    "Expected executable SHA256",
  );
  const link = await lstat(tool.path);
  requireThat(
    !link.isSymbolicLink(),
    "TOOL_PATH",
    "Tool path must not be a symbolic link",
  );
  requireThat(link.isFile(), "TOOL_PATH", "Tool must be a regular file");
  requireThat(
    (link.mode & 0o022) === 0,
    "TOOL_PATH",
    "Tool must not be group- or world-writable",
  );
  const handle = await open(
    tool.path,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  let bytes: Buffer;
  try {
    const opened = await handle.stat();
    requireThat(
      opened.isFile() && opened.ino === link.ino && opened.dev === link.dev,
      "TOOL_PATH",
      "Tool changed while it was opened",
    );
    bytes = await handle.readFile();
  } finally {
    await handle.close();
  }
  const actual = createHash("sha256").update(bytes).digest("hex");
  requireThat(
    actual === tool.sha256,
    "TOOL_PIN",
    "Executable hash does not match pin",
  );
  return bytes;
}
/** Checks the path rules and the pin. runTool repeats the check itself. */
export async function verifyTool(tool: ToolSpec): Promise<void> {
  await readPinnedTool(tool);
}
/**
 * Environment of the tool process. Only these keys come from process.env;
 * dynamic-loader keys (LD_*, DYLD_*) are always removed, also from options.env.
 */
const ENVIRONMENT_ALLOWLIST = [
  "PATH",
  "HOME",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "TZ",
];
const LOADER_KEY = /^(LD_|DYLD_)/;
export function toolEnvironment(
  extra: Record<string, string> = {},
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of ENVIRONMENT_ALLOWLIST) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  for (const [key, value] of Object.entries(extra)) env[key] = value;
  for (const key of Object.keys(env)) if (LOADER_KEY.test(key)) delete env[key];
  return env;
}
/**
 * Runs the pinned tool. The bytes are read and hashed once, then written to a
 * new private directory (mode 0700, file mode 0500) in options.toolDirectory
 * or os.tmpdir(). The process runs from
 * that copy, so a later change to tool.path cannot change what runs. The pin
 * covers only this file: an interpreter named in a "#!" line and shared
 * libraries are not pinned. The tool receives the private witness.
 */
export async function runTool(
  tool: ToolSpec,
  args: readonly string[],
  options: RunOptions,
): Promise<ToolResult> {
  const bytes = await readPinnedTool(tool);
  requireThat(
    isAbsolute(options.cwd),
    "OUTPUT_PATH",
    "Working directory must be absolute",
  );
  const limit = options.maxOutputBytes ?? 16 * 1024 * 1024,
    timeout = options.timeoutMs ?? 600000;
  requireThat(
    Number.isSafeInteger(limit) &&
      limit > 0 &&
      Number.isSafeInteger(timeout) &&
      timeout > 0,
    "TOOL_LIMIT",
    "Positive output/time bounds required",
  );
  requireThat(
    options.toolDirectory === undefined || isAbsolute(options.toolDirectory),
    "OUTPUT_PATH",
    "Tool directory must be absolute",
  );
  const privateDirectory = await mkdtemp(
    join(options.toolDirectory ?? tmpdir(), "ironwood-tool-"),
  );
  try {
    const copy = join(privateDirectory, basename(tool.path));
    await writeFile(copy, bytes, { mode: 0o500, flag: "wx" });
    return await spawnTool(copy, args, options, limit, timeout);
  } finally {
    await rm(privateDirectory, { recursive: true, force: true });
  }
}
function spawnTool(
  path: string,
  args: readonly string[],
  options: RunOptions,
  limit: number,
  timeout: number,
): Promise<ToolResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(path, [...args], {
      cwd: options.cwd,
      env: toolEnvironment(options.env),
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      signal: options.signal,
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let size = 0,
      failure: PreparationError | undefined;
    const kill = (e: PreparationError) => {
      failure ??= e;
      child.kill("SIGKILL");
    };
    const timer = setTimeout(
      () =>
        kill(new PreparationError("TOOL_TIMEOUT", "Tool exceeded time limit")),
      timeout,
    );
    const data = (list: Buffer[]) => (b: Buffer) => {
      const remaining = Math.max(0, limit - size);
      if (remaining) list.push(b.subarray(0, remaining));
      size += b.length;
      if (size > limit)
        kill(new PreparationError("TOOL_OUTPUT", "Tool exceeded output limit"));
    };
    child.stdout.on("data", data(out));
    child.stderr.on("data", data(err));
    child.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      const diagnostics = {
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
        exitCode: code,
        signal,
      };
      if (failure)
        return reject(
          new ToolExecutionError(failure.code, failure.message, diagnostics),
        );
      if (code !== 0)
        return reject(
          new ToolExecutionError(
            "TOOL_FAILED",
            `Tool exited with code ${code}`,
            diagnostics,
          ),
        );
      resolve({ ...diagnostics, exitCode: 0 });
    });
  });
}
