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
 * Every row in the environment, every version, superseded and soft-deleted
 * included. This is the history and audit view, not the listing.
 */
export async function listSecretsByEnvironment(
  ctx: QueryCtx,
  environmentId: Id<"environments">,
): Promise<Doc<"secrets">[]> {
  return await ctx.db
    .query("secrets")
    .withIndex("by_environment_current", (q) =>
      q.eq("environmentId", environmentId),
    )
    .collect();
}

/**
 * The dashboard listing and the bundle fetch. A single indexed read: current
 * version, not soft-deleted. Both exclusions are index equalities rather than
 * a filter, because this runs on every page load and every token sync.
 */
export async function listCurrentSecretsByEnvironment(
  ctx: QueryCtx,
  environmentId: Id<"environments">,
): Promise<Doc<"secrets">[]> {
  return await ctx.db
    .query("secrets")
    .withIndex("by_environment_current", (q) =>
      q
        .eq("environmentId", environmentId)
        .eq("supersededAt", undefined)
        .eq("deletedAt", undefined),
    )
    .collect();
}

/**
 * Every version of one logical secret, oldest first. This is what makes
 * "the previous version remains readable" answerable at all.
 */
export async function listSecretVersions(
  ctx: QueryCtx,
  lineageId: string,
): Promise<Doc<"secrets">[]> {
  return await ctx.db
    .query("secrets")
    .withIndex("by_lineage_version", (q) => q.eq("lineageId", lineageId))
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
