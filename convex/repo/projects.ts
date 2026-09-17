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
    .withIndex("by_org_slug", (q) => q.eq("orgId", orgId))
    .collect();
}

/**
 * Slugs are unique within an org, not globally. This is the check that makes
 * that true, so a create path that skips it is a bug.
 */
export async function getProjectBySlug(
  ctx: QueryCtx,
  orgId: Id<"orgs">,
  slug: string,
): Promise<Doc<"projects"> | null> {
  return await ctx.db
    .query("projects")
    .withIndex("by_org_slug", (q) => q.eq("orgId", orgId).eq("slug", slug))
    .unique();
}

export async function insertProject(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"projects">>,
): Promise<Id<"projects">> {
  return await ctx.db.insert("projects", doc);
}
