import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id, TableNames } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

/**
 * Append only. There is no update and no delete here on purpose: an audit row
 * that can be edited is not evidence of anything.
 */
export async function insertAuditEvent(
  ctx: MutationCtx,
  doc: WithoutSystemFields<Doc<"auditLog">>,
): Promise<Id<"auditLog">> {
  return await ctx.db.insert("auditLog", doc);
}

/**
 * "Everything this actor did, in order." The first question asked during an
 * incident, and the reason `by_actor_ts` exists.
 */
export async function listAuditEventsByActor(
  ctx: QueryCtx,
  actorId: string,
  limit: number,
): Promise<Doc<"auditLog">[]> {
  return await ctx.db
    .query("auditLog")
    .withIndex("by_actor_ts", (q) => q.eq("actorId", actorId))
    .order("desc")
    .take(limit);
}

/**
 * The newest `limit` events of one org, newest first. The org is an index
 * equality, so another tenant's events are outside the range read rather
 * than filtered out afterwards.
 */
export async function listAuditEventsByOrg(
  ctx: QueryCtx,
  orgId: Id<"orgs">,
  limit: number,
): Promise<Doc<"auditLog">[]> {
  return await ctx.db
    .query("auditLog")
    .withIndex("by_org_ts", (q) => q.eq("orgId", orgId))
    .order("desc")
    .take(limit);
}

/**
 * The row an audit event's `targetId` or `actorId` names, in the table the
 * caller says it belongs to, or null.
 *
 * Both columns are plain strings, because one column holds ids from several
 * tables and, for a token actor, a hash that is no document id at all. So the
 * string is NORMALISED against the named table first: a string that is not an
 * id of that table resolves to null instead of reading a row from somewhere
 * else, and a row that has since gone resolves to null too.
 */
export async function getAuditSubject<T extends TableNames>(
  ctx: QueryCtx,
  table: T,
  id: string,
): Promise<Doc<T> | null> {
  const normalised = ctx.db.normalizeId(table, id);
  if (normalised === null) return null;
  return await ctx.db.get(normalised);
}
