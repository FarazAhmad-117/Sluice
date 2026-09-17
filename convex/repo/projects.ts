import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

export async function getProject(
  ctx: QueryCtx,
  id: Id<"projects">,
): Promise<Doc<"projects"> | null> {
  return await ctx.db.get(id);
}

export async function listProjectsByOrg(
  ctx: QueryCtx,
  orgId: Id<"orgs">,
): Promise<Doc<"projects">[]> {
  return await ctx.db
    .query("projects")
    .withIndex("by_org", (q) => q.eq("orgId", orgId))
    .collect();
}

export async function insertProject(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"projects">>,
): Promise<Id<"projects">> {
  return await ctx.db.insert("projects", doc);
}
