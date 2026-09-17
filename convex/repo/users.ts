import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";
import type { NormalisedEmail } from "../lib/email";

/**
 * `by_email` is an exact-match index, so account identity depends entirely on
 * every writer and every reader agreeing on one spelling of an address. That
 * agreement is enforced here by type rather than by comment: the only way to
 * obtain a `NormalisedEmail` is `normaliseEmail`, so a caller that skips it
 * does not compile.
 *
 * This is the one piece of policy in the repo layer, and it is here because
 * putting it anywhere else makes it optional.
 */
type UserDoc = WithoutSystemFields<Doc<"users">>;
type UserDocWithNormalisedEmail = Omit<UserDoc, "email"> & {
  email: NormalisedEmail;
};

export async function getUser(
  ctx: QueryCtx,
  id: Id<"users">,
): Promise<Doc<"users"> | null> {
  return await ctx.db.get(id);
}

export async function getUserByEmail(
  ctx: QueryCtx,
  email: NormalisedEmail,
): Promise<Doc<"users"> | null> {
  return await ctx.db
    .query("users")
    .withIndex("by_email", (q) => q.eq("email", email))
    .unique();
}

export async function insertUser(
  ctx: MutationCtx,
  doc: UserDocWithNormalisedEmail,
): Promise<Id<"users">> {
  return await ctx.db.insert("users", doc);
}

export async function patchUser(
  ctx: MutationCtx,
  id: Id<"users">,
  patch: Partial<UserDocWithNormalisedEmail>,
): Promise<void> {
  await ctx.db.patch(id, patch);
}
