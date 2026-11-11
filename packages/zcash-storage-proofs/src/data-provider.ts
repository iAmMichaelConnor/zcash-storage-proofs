/** Read-only provider protocol; callers supply credentials/endpoint and checkpoint policy. */
import { hex, rpcHashToLE } from "./bytes.js";
import { requireThat } from "./errors.js";
import {
  integer,
  checkpoint as validateCheckpoint,
  protocol as validateProtocol,
} from "./validation.js";
import { prepareRawBlocks } from "./raw.js";
import type { Checkpoint, Protocol, BlocksEnvelope } from "./types.js";
export interface ZcashRpc {
  request(
    method: "getblockhash" | "getblock",
    params: readonly unknown[],
  ): Promise<unknown>;
}
/** Fetch every complete block; never compact-block summaries or sampled transactions.
 * A provider response is untrusted data, not application checkpoint authorization. */
export async function fetchCompleteBlocks(
  rpc: ZcashRpc,
  options: {
    protocol: Protocol;
    checkpoint: Checkpoint;
    startHeight: number;
    maxBlocks: number;
  },
): Promise<BlocksEnvelope> {
  const protocol = validateProtocol(options.protocol),
    checkpoint = validateCheckpoint(options.checkpoint),
    start = integer(options.startHeight, 0xffffffff),
    max = integer(options.maxBlocks, 100000);
  requireThat(
    start <= checkpoint.height && checkpoint.height - start + 1 <= max,
    "CAPACITY",
    "Requested range exceeds caller cap",
  );
  const blocks = [];
  for (let height = start; height <= checkpoint.height; height++) {
    const hash = hex(await rpc.request("getblockhash", [height]), 32);
    if (height === checkpoint.height)
      requireThat(
        rpcHashToLE(hash) === checkpoint.hashLE,
        "CHECKPOINT",
        "Provider tip does not match explicit checkpoint",
      );
    const rawHex = hex(await rpc.request("getblock", [hash, 0]));
    blocks.push({ height, rawHex });
  }
  return prepareRawBlocks({
    schemaVersion: 1,
    kind: "raw-blocks",
    protocol,
    checkpoint,
    blocks,
  });
}
