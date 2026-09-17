import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
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
