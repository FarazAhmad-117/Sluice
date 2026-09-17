import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

export async function getUser(
  ctx: QueryCtx,
  id: Id<"users">,
): Promise<Doc<"users"> | null> {
  return await ctx.db.get(id);
}

export async function getUserByEmail(
  ctx: QueryCtx,
  email: string,
): Promise<Doc<"users"> | null> {
  return await ctx.db
    .query("users")
    .withIndex("by_email", (q) => q.eq("email", email))
    .unique();
}

export async function insertUser(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"users">>,
): Promise<Id<"users">> {
  return await ctx.db.insert("users", doc);
}

export async function patchUser(
  ctx: MutationCtx,
  id: Id<"users">,
  patch: Partial<WithoutSystemFields<Doc<"users">>>,
): Promise<void> {
  await ctx.db.patch(id, patch);
}
