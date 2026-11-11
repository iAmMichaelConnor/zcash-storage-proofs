/** Stable machine-readable input/preparation failure. Never includes witness contents. */
export class PreparationError extends Error {
  readonly code: string;
  readonly path: string;
  constructor(code: string, message: string, path = "$") {
    super(`${path}: ${message}`);
    this.name = "PreparationError";
    this.code = code;
    this.path = path;
  }
}
export function requireThat(
  condition: unknown,
  code: string,
  message: string,
  path = "$",
): asserts condition {
  if (!condition) throw new PreparationError(code, message, path);
}
