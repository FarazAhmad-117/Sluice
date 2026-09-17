import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

export async function getEnvironment(
  ctx: QueryCtx,
  id: Id<"environments">,
): Promise<Doc<"environments"> | null> {
  return await ctx.db.get(id);
}

export async function listEnvironmentsByProject(
  ctx: QueryCtx,
  projectId: Id<"projects">,
): Promise<Doc<"environments">[]> {
  return await ctx.db
    .query("environments")
    .withIndex("by_project", (q) => q.eq("projectId", projectId))
    .collect();
}

export async function insertEnvironment(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"environments">>,
): Promise<Id<"environments">> {
  return await ctx.db.insert("environments", doc);
}

/**
 * Used to bump `pdkVersion` and `epoch`. Epochs are globally monotonic per
 * token id and must never reset, so a caller that writes a lower number than
 * the row already holds is a bug, not a policy choice this layer enforces.
 */
export async function patchEnvironment(
  ctx: MutationCtx,
  id: Id<"environments">,
  patch: Partial<WithoutSystemFields<Doc<"environments">>>,
): Promise<void> {
  await ctx.db.patch(id, patch);
}

export async function listPDKGrantsByEnvironment(
  ctx: QueryCtx,
  environmentId: Id<"environments">,
): Promise<Doc<"pdkGrants">[]> {
  return await ctx.db
    .query("pdkGrants")
    .withIndex("by_environment", (q) => q.eq("environmentId", environmentId))
    .collect();
}

export async function listPDKGrantsByGrantee(
  ctx: QueryCtx,
  granteeType: Doc<"pdkGrants">["granteeType"],
  granteeId: string,
): Promise<Doc<"pdkGrants">[]> {
  return await ctx.db
    .query("pdkGrants")
    .withIndex("by_grantee", (q) =>
      q.eq("granteeType", granteeType).eq("granteeId", granteeId),
    )
    .collect();
}

export async function insertPDKGrant(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"pdkGrants">>,
): Promise<Id<"pdkGrants">> {
  return await ctx.db.insert("pdkGrants", doc);
}
