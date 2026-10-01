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

/**
 * `createSharedSecret`'s uniqueness check on the share id: does ANY row, in
 * any environment, superseded or deleted included, carry this `shareUid`?
 *
 * The same reasoning as `secretUidTaken`. A share id is client-chosen, and one
 * that is accepted while an old group still carries it would fold the new rows
 * into that group, so the dashboard would label and delete them together. The
 * `.first()` range read on `by_share` is what makes a concurrent insert under
 * the same id conflict with this transaction.
 */
export async function shareUidTaken(
  ctx: QueryCtx,
  shareUid: string,
): Promise<boolean> {
  const row = await ctx.db
    .query("secrets")
    .withIndex("by_share", (q) => q.eq("shareUid", shareUid))
    .first();
  return row !== null;
}

/**
 * The current, live rows of one shared secret, one per environment when the
 * group is intact. Every version of every row carries the share id (an update
 * copies it), so the history is filtered out here rather than by the index:
 * a shared secret has a handful of rows and this runs only on a delete.
 */
export async function listCurrentByShareUid(
  ctx: QueryCtx,
  shareUid: string,
): Promise<Doc<"secrets">[]> {
  const rows = await ctx.db
    .query("secrets")
    .withIndex("by_share", (q) => q.eq("shareUid", shareUid))
    .collect();
  return rows.filter(
    (row) => row.supersededAt === undefined && row.deletedAt === undefined,
  );
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
