import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

export async function getSecret(
  ctx: QueryCtx,
  id: Id<"secrets">,
): Promise<Doc<"secrets"> | null> {
  return await ctx.db.get(id);
}

/**
 * Returns soft-deleted rows too. Excluding `deletedAt` is a product rule and
 * belongs in the query that serves a listing, not here, because the bundle and
 * the audit view need different answers about a deleted secret.
 */
export async function listSecretsByEnvironment(
  ctx: QueryCtx,
  environmentId: Id<"environments">,
): Promise<Doc<"secrets">[]> {
  return await ctx.db
    .query("secrets")
    .withIndex("by_environment", (q) => q.eq("environmentId", environmentId))
    .collect();
}

export async function insertSecret(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"secrets">>,
): Promise<Id<"secrets">> {
  return await ctx.db.insert("secrets", doc);
}

export async function patchSecret(
  ctx: MutationCtx,
  id: Id<"secrets">,
  patch: Partial<WithoutSystemFields<Doc<"secrets">>>,
): Promise<void> {
  await ctx.db.patch(id, patch);
}
