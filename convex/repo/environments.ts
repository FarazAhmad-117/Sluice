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
    .withIndex("by_project_name", (q) => q.eq("projectId", projectId))
    .collect();
}

/**
 * How the SDK addresses a config: org, project, environment by name. Also the
 * uniqueness check when an environment is created.
 */
export async function getEnvironmentByName(
  ctx: QueryCtx,
  projectId: Id<"projects">,
  name: string,
): Promise<Doc<"environments"> | null> {
  return await ctx.db
    .query("environments")
    .withIndex("by_project_name", (q) =>
      q.eq("projectId", projectId).eq("name", name),
    )
    .unique();
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
    .withIndex("by_environment_grantee", (q) =>
      q.eq("environmentId", environmentId),
    )
    .collect();
}

/**
 * ONE GRANTEE'S GRANT ON ONE ENVIRONMENT. The bundle's lookup and the
 * dashboard's.
 *
 * `.unique()` rather than `.first()`, and that is deliberate. A second grant
 * for one grantee on one environment is not a tie to break silently: it means
 * two wrapped copies of a key are live at once and nothing says which is
 * current, which is exactly the two-homes failure `pdkGrants` was consolidated
 * to remove. Throwing makes it visible; picking one hides it until a re-key.
 *
 * `granteeId` is the `users` document id for a user and the `tokenIdHash` for a
 * token. See the note on the table.
 */
export async function getPDKGrant(
  ctx: QueryCtx,
  environmentId: Id<"environments">,
  granteeType: Doc<"pdkGrants">["granteeType"],
  granteeId: string,
): Promise<Doc<"pdkGrants"> | null> {
  return await ctx.db
    .query("pdkGrants")
    .withIndex("by_environment_grantee", (q) =>
      q
        .eq("environmentId", environmentId)
        .eq("granteeType", granteeType)
        .eq("granteeId", granteeId),
    )
    .unique();
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

/**
 * Used by a re-key, which must replace `wrappedPDK`, `nonce` and `pdkVersion`
 * together. Patching the blob without the version, or the version without the
 * blob, leaves a row that says it opens a key it does not, and nothing errors
 * until somebody decrypts.
 */
export async function patchPDKGrant(
  ctx: MutationCtx,
  id: Id<"pdkGrants">,
  patch: Partial<WithoutSystemFields<Doc<"pdkGrants">>>,
): Promise<void> {
  await ctx.db.patch(id, patch);
}
