import type { WithoutSystemFields } from "convex/server";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx } from "../_generated/server";

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
