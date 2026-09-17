import { v } from "convex/values";
import { internalMutation } from "./_generated/server";
import { deleteExpiredSessions } from "./repo/sessions";

/**
 * How many rows one run removes.
 *
 * Bounded, and the count comes back, for the reason `handshakeNonces` records:
 * a cleanup that tries to delete everything expired in a single transaction
 * eventually exceeds Convex's per transaction limits, fails, retries, fails
 * again, and from then on the table only grows. A capped page always succeeds,
 * and the cron interval is short enough that a backlog drains.
 */
const PRUNE_LIMIT = 512;

/**
 * WHY EXPIRED SESSIONS ARE DELETED AND NOT MERELY IGNORED.
 *
 * Two reasons, and the second is the one that is easy to miss.
 *
 * The obvious one: `sessions` gains a row per login and nothing else ever
 * removes it, so without this the table grows for ever. That is the identical
 * defect already written down against `handshakeNonces`, on the table that
 * holds authentication credentials.
 *
 * The one that matters more: Convex re-runs a QUERY when a row it read
 * changes, not when the clock moves. A dashboard subscription that resolved a
 * live session is therefore not re-evaluated at the instant that session's
 * deadline passes, and keeps serving the cached result until something it read
 * changes. Deleting the row IS that change, so this cron is what turns expiry
 * from a check into an event. Logout does the same thing immediately for the
 * one session it ends.
 *
 * Internal, so it is unreachable from any client. It takes no arguments at
 * all: a `now` parameter would let a caller decide what "expired" means.
 */
export const pruneExpiredSessions = internalMutation({
  args: {},
  returns: v.number(),
  handler: async (ctx) => {
    return await deleteExpiredSessions(ctx, Date.now(), PRUNE_LIMIT);
  },
});
