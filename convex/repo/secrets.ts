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
 * Every version of one logical secret, oldest first, by its permanent `sec_`
 * id. This is what makes "the previous version remains readable" answerable at
 * all.
 */
export async function listSecretVersions(
  ctx: QueryCtx,
  secretUid: string,
): Promise<Doc<"secrets">[]> {
  return await ctx.db
    .query("secrets")
    .withIndex("by_secret_version", (q) => q.eq("secretUid", secretUid))
    .collect();
}

/**
 * `createSecret`'s uniqueness check: does ANY row, in any environment,
 * superseded or deleted included, carry this `secretUid`?
 *
 * `.first()` on the same `by_secret_version` range `listSecretVersions` reads,
 * rather than collecting every version just to count them. The read set is the
 * same index range either way, so a concurrent insert under this id still
 * conflicts with this transaction and one of the two is retried: the
 * protection is the range read, not the number of rows fetched.
 */
export async function secretUidTaken(
  ctx: QueryCtx,
  secretUid: string,
): Promise<boolean> {
  const row = await ctx.db
    .query("secrets")
    .withIndex("by_secret_version", (q) => q.eq("secretUid", secretUid))
    .first();
  return row !== null;
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
