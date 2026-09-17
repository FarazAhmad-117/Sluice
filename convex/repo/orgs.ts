import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

export async function getOrg(
  ctx: QueryCtx,
  id: Id<"orgs">,
): Promise<Doc<"orgs"> | null> {
  return await ctx.db.get(id);
}

export async function getOrgBySlug(
  ctx: QueryCtx,
  slug: string,
): Promise<Doc<"orgs"> | null> {
  return await ctx.db
    .query("orgs")
    .withIndex("by_slug", (q) => q.eq("slug", slug))
    .unique();
}

export async function insertOrg(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"orgs">>,
): Promise<Id<"orgs">> {
  return await ctx.db.insert("orgs", doc);
}

/**
 * The membership lookup every org-scoped mutation authorises against. It
 * returns the row rather than a boolean so the caller can read `role`.
 */
export async function getOrgMember(
  ctx: QueryCtx,
  orgId: Id<"orgs">,
  userId: Id<"users">,
): Promise<Doc<"orgMembers"> | null> {
  return await ctx.db
    .query("orgMembers")
    .withIndex("by_org_user", (q) => q.eq("orgId", orgId).eq("userId", userId))
    .unique();
}

export async function listOrgMembersByUser(
  ctx: QueryCtx,
  userId: Id<"users">,
): Promise<Doc<"orgMembers">[]> {
  return await ctx.db
    .query("orgMembers")
    .withIndex("by_user", (q) => q.eq("userId", userId))
    .collect();
}

export async function insertOrgMember(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"orgMembers">>,
): Promise<Id<"orgMembers">> {
  return await ctx.db.insert("orgMembers", doc);
}
