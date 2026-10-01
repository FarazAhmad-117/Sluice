import { ConvexError } from "convex/values";
import { assertId } from "@sluice/crypto";
import type { IdKind } from "@sluice/crypto";

/**
 * `assertId` from `@sluice/crypto`, with its failure carried as a
 * `ConvexError`.
 *
 * The rule itself (kind prefix, 32 lowercase hex, nothing else) lives in the
 * package, because the client mints these ids and binds them into associated
 * data, and a second copy of the pattern here is the drift hazard the package
 * exists to remove. What this wrapper adds is the transport: the package
 * throws a plain `Error`, which would reach a caller as an opaque server
 * error, and is rethrown so the message ("uid must be a well-formed usr id")
 * arrives as `data`, the way `normaliseEmail` and the hex checks report.
 * The message never echoes the value.
 *
 * Shape only. Uniqueness is the caller's job, through the table's `by_uid`
 * index, in the same mutation as the insert.
 */
export function requireId(kind: IdKind, field: string, value: string): string {
  try {
    return assertId(kind, field, value);
  } catch (error) {
    if (error instanceof Error) throw new ConvexError(error.message);
    throw error;
  }
}
