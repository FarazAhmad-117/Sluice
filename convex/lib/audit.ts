import type { Id } from "../_generated/dataModel";
import type { MutationCtx } from "../_generated/server";
import { insertAuditEvent } from "../repo/audit";

/**
 * WHAT THIS TABLE IS ALLOWED TO CONTAIN.
 *
 * `auditLog` is append only, has no delete in the repo layer, and indexes
 * `actorId`. Everything written here is therefore permanent and queryable, so
 * the question is not "is this field useful" but "is this field something the
 * operator is willing to hold forever".
 *
 * The actor is a USER ID, never an email. An email in an append-only table is
 * plaintext personal data that cannot be erased on request, and it would be
 * erased from `users` and survive here, which is worse than never having
 * recorded it.
 *
 * `metadata` is NOT written by anything in this file. The backend plan
 * requires it to gain a discriminated validator per action type before it
 * carries anything, precisely because it is the field where a decrypted
 * secret name or a request body lands by accident and, since nothing reads it
 * back, nobody notices. Until that validator exists the honest value is
 * absent. The only strings available to put in it today are user-supplied
 * names, which is the exact leak.
 *
 * `ip` is not written either. A mutation context has no request metadata, so
 * anything written here would have to be forwarded by the caller, and a
 * caller-supplied IP address in an audit record is worse than no IP address:
 * it looks like evidence and is not.
 */
export async function recordUserEvent(
  ctx: MutationCtx,
  event: {
    orgId: Id<"orgs">;
    actorId: Id<"users">;
    action: string;
    targetId: string;
  },
): Promise<void> {
  await insertAuditEvent(ctx, {
    orgId: event.orgId,
    actorType: "user",
    actorId: event.actorId,
    action: event.action,
    targetId: event.targetId,
    ts: Date.now(),
  });
}
