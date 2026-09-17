import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

/**
 * There is deliberately no `getSession(ctx, id)`. A session is only ever
 * reached by presenting its token, and a by-id getter is the shape that lets
 * some future handler take a session id as an argument, which is the hole this
 * whole layer exists to close.
 */

/**
 * The lookup every authenticated call makes. The caller hashes the presented
 * token and passes the hash, because the plaintext token is never stored.
 *
 * `.unique()` rather than `.first()`: two rows for one token hash would mean
 * either a SHA-256 collision or a bug that wrote the same credential twice,
 * and both should stop the request rather than pick one.
 */
export async function getSessionByTokenHash(
  ctx: QueryCtx,
  tokenHash: string,
): Promise<Doc<"sessions"> | null> {
  return await ctx.db
    .query("sessions")
    .withIndex("by_token_hash", (q) => q.eq("tokenHash", tokenHash))
    .unique();
}

export async function listSessionsByUser(
  ctx: QueryCtx,
  userId: Id<"users">,
): Promise<Doc<"sessions">[]> {
  return await ctx.db
    .query("sessions")
    .withIndex("by_user", (q) => q.eq("userId", userId))
    .collect();
}

export async function insertSession(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"sessions">>,
): Promise<Id<"sessions">> {
  return await ctx.db.insert("sessions", doc);
}

export async function deleteSession(
  ctx: MutationCtx,
  id: Id<"sessions">,
): Promise<void> {
  await ctx.db.delete(id);
}

/**
 * The prune cron's one operation.
 *
 * `limit` is not optional and the count comes back, for the reason
 * `deleteExpiredHandshakeNonces` gives: a cleanup that tries to delete
 * everything expired in a single transaction eventually exceeds Convex's per
 * transaction limits and then never succeeds again, which is the failure mode
 * where the table quietly grows for months. The caller pages.
 */
export async function deleteExpiredSessions(
  ctx: MutationCtx,
  now: number,
  limit: number,
): Promise<number> {
  const expired = await ctx.db
    .query("sessions")
    .withIndex("by_expiry", (q) => q.lt("expiresAt", now))
    .take(limit);

  for (const row of expired) {
    await ctx.db.delete(row._id);
  }
  return expired.length;
}
