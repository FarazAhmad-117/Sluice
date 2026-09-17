import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

// serviceTokens

export async function getServiceToken(
  ctx: QueryCtx,
  id: Id<"serviceTokens">,
): Promise<Doc<"serviceTokens"> | null> {
  return await ctx.db.get(id);
}

/**
 * Turns a string into a `serviceTokens` id, or `null` if it is not one.
 *
 * The bundle subscription reads its subject out of a JWT this deployment
 * signed, so the value is not attacker chosen. It is normalised anyway, because
 * `ctx.db.get` THROWS on a string that is not a well-formed id rather than
 * returning null, and a throw there would turn one refusal path into two
 * observably different ones: a clean "refused" for a well-formed id that names
 * no row, and a server error for a malformed one. Two shapes of failure is an
 * oracle, and it would also be a crash on a path that should simply say no.
 */
export function normaliseServiceTokenId(
  ctx: QueryCtx,
  id: string,
): Id<"serviceTokens"> | null {
  return ctx.db.normalizeId("serviceTokens", id);
}

/**
 * The handshake lookup. The caller hashes the incoming plaintext token id and
 * passes the hash, because the plaintext id is never stored.
 */
export async function getServiceTokenByIdHash(
  ctx: QueryCtx,
  tokenIdHash: string,
): Promise<Doc<"serviceTokens"> | null> {
  return await ctx.db
    .query("serviceTokens")
    .withIndex("by_token_id_hash", (q) => q.eq("tokenIdHash", tokenIdHash))
    .unique();
}

export async function listServiceTokensByEnvironment(
  ctx: QueryCtx,
  environmentId: Id<"environments">,
): Promise<Doc<"serviceTokens">[]> {
  return await ctx.db
    .query("serviceTokens")
    .withIndex("by_environment", (q) => q.eq("environmentId", environmentId))
    .collect();
}

export async function insertServiceToken(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"serviceTokens">>,
): Promise<Id<"serviceTokens">> {
  return await ctx.db.insert("serviceTokens", doc);
}

export async function patchServiceToken(
  ctx: MutationCtx,
  id: Id<"serviceTokens">,
  patch: Partial<WithoutSystemFields<Doc<"serviceTokens">>>,
): Promise<void> {
  await ctx.db.patch(id, patch);
}

// revocations

/**
 * `tokenId` here is the plaintext id, not the hash. The SDK matches on it and
 * the signed notice covers it, so hashing it would break verification. Use
 * this when the caller already holds the plaintext id, which in practice means
 * the revocation path itself.
 */
export async function listRevocationsByTokenId(
  ctx: QueryCtx,
  tokenId: string,
): Promise<Doc<"revocations">[]> {
  return await ctx.db
    .query("revocations")
    .withIndex("by_token_id", (q) => q.eq("tokenId", tokenId))
    .collect();
}

/**
 * The join the bundle subscription needs. An authenticated token is known to
 * the server only by its hash, so this is the only way to reach its notice
 * without the plaintext id leaving the signed payload.
 */
export async function listRevocationsByTokenIdHash(
  ctx: QueryCtx,
  tokenIdHash: string,
): Promise<Doc<"revocations">[]> {
  return await ctx.db
    .query("revocations")
    .withIndex("by_token_id_hash", (q) => q.eq("tokenIdHash", tokenIdHash))
    .collect();
}

export async function insertRevocation(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"revocations">>,
): Promise<Id<"revocations">> {
  return await ctx.db.insert("revocations", doc);
}

// handshakeNonces

export async function getHandshakeNonce(
  ctx: QueryCtx,
  signatureHash: string,
): Promise<Doc<"handshakeNonces"> | null> {
  return await ctx.db
    .query("handshakeNonces")
    .withIndex("by_signature_hash", (q) => q.eq("signatureHash", signatureHash))
    .unique();
}

export async function insertHandshakeNonce(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"handshakeNonces">>,
): Promise<Id<"handshakeNonces">> {
  return await ctx.db.insert("handshakeNonces", doc);
}

/**
 * This table gains a row per successful handshake and nothing ever removed
 * them, so it grew without bound. The cron that calls this is a separate task.
 *
 * `limit` is not optional and the count is returned, because a cleanup that
 * tries to delete everything expired in one transaction will eventually exceed
 * Convex's per-transaction limits and then never succeed again. The caller
 * pages, and uses the returned count to decide whether to run again.
 */
export async function deleteExpiredHandshakeNonces(
  ctx: MutationCtx,
  now: number,
  limit: number,
): Promise<number> {
  const expired = await ctx.db
    .query("handshakeNonces")
    .withIndex("by_expiry", (q) => q.lt("expiresAt", now))
    .take(limit);

  for (const row of expired) {
    await ctx.db.delete(row._id);
  }
  return expired.length;
}
