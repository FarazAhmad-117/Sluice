import { ConvexError, v } from "convex/values";
import { query } from "./_generated/server";
import type { Doc, Id } from "./_generated/dataModel";
import type { QueryCtx } from "./_generated/server";
import { sessionArg, requireProject } from "./lib/authz";
import { getAuditSubject, listAuditEventsByOrg } from "./repo/audit";
import { listEnvironmentsByProject } from "./repo/environments";

/**
 * WHAT HAPPENED IN ONE PROJECT, READ BACK OUT OF THE AUDIT LOG.
 *
 * The audit log is the record, and this is a view of it, not a second
 * record. Nothing here writes, and nothing here returns a field the log does
 * not already hold except two things derived from rows the caller can already
 * reach: which environment a secret lives in, and the actor's email.
 *
 * WHAT IS NEVER RETURNED. No ciphertext, no nonce, no key material: an event
 * names its target by document id, and the dashboard decrypts a secret's name
 * from the rows it already holds, in the browser, exactly as it does for the
 * listing. `metadata` and `ip` are not read at all; see `lib/audit.ts` for
 * why nothing writes them yet.
 *
 * THE ACTOR'S EMAIL IS RESOLVED AT READ TIME, NEVER STORED. `lib/audit.ts`
 * keeps emails out of the append-only table so that erasing a person from
 * `users` erases them everywhere. Looking the address up here keeps that
 * true: once the user row is gone, its events answer `actorEmail: null`.
 * Only a member of the org sees it, and only for events in their own org.
 *
 * WHY THIS READS THE ORG'S EVENTS AND FILTERS, AND WHAT THAT COSTS. An event
 * carries its org and its target id, not its project, so there is no index
 * that answers "this project's events" directly. `by_org_ts` answers "this
 * org's events, newest first", and the org is an index equality there: another
 * tenant's events are outside the range read, not filtered out after it, so a
 * bug in the filter below cannot show one. The project is then decided per
 * event, from the target row, against the set of this project's environments
 * read in this query.
 *
 * The read is BOUNDED, at `SCAN_LIMIT` org events, so a busy org cannot turn
 * one page load into an unbounded scan. The consequence is stated plainly
 * rather than hidden: in an org whose other projects are much busier than
 * this one, events older than the newest `SCAN_LIMIT` org events do not
 * appear here, and the feed is shorter than `limit`. The fix, when it
 * matters, is a `projectId` on each event and a `by_project_ts` index, which
 * is a change to every writer and so its own piece of work.
 */

const DEFAULT_LIMIT = 30;
const MAX_LIMIT = 100;
const SCAN_LIMIT = 1000;

const LIMIT_OUT_OF_RANGE = `limit must be a whole number from 1 to ${MAX_LIMIT}.`;

type TargetKind = "secret" | "environment" | "project";

/**
 * Which table an event's target lives in, read off the action's prefix, which
 * every writer in this codebase spells as `<table>.<verb>`. Anything else --
 * an org event, a token event -- is not a project's activity and is skipped.
 */
function kindOf(action: string): TargetKind | null {
  if (action.startsWith("secret.")) return "secret";
  if (action.startsWith("environment.")) return "environment";
  if (action.startsWith("project.")) return "project";
  return null;
}

const eventShape = v.object({
  at: v.number(),
  action: v.string(),
  actorIsYou: v.boolean(),
  actorEmail: v.union(v.string(), v.null()),
  targetKind: v.union(
    v.literal("secret"),
    v.literal("environment"),
    v.literal("project"),
  ),
  targetId: v.string(),
  environmentId: v.union(v.id("environments"), v.null()),
});

export const listProjectActivity = query({
  args: {
    ...sessionArg,
    projectId: v.id("projects"),
    limit: v.optional(v.number()),
  },
  returns: v.array(eventShape),
  handler: async (ctx, args) => {
    // Membership first, before the limit is even looked at, so a caller who
    // is not a member learns nothing from which of their arguments was wrong.
    const { org, project, user } = await requireProject(
      ctx,
      args.sessionToken,
      args.projectId,
    );

    const limit = args.limit ?? DEFAULT_LIMIT;
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
      throw new ConvexError(LIMIT_OUT_OF_RANGE);
    }

    const environments = new Set<string>(
      (await listEnvironmentsByProject(ctx, project._id)).map((env) => env._id),
    );
    const events = await listAuditEventsByOrg(ctx, org._id, SCAN_LIMIT);

    const emails = new Map<string, string | null>();
    const out: Array<{
      at: number;
      action: string;
      actorIsYou: boolean;
      actorEmail: string | null;
      targetKind: TargetKind;
      targetId: string;
      environmentId: Id<"environments"> | null;
    }> = [];

    for (const event of events) {
      if (out.length >= limit) break;
      const placed = await placeInProject(ctx, event, project, environments);
      if (placed === null) continue;
      out.push({
        at: event.ts,
        action: event.action,
        // A token's actor id is a hash and a system actor is nobody, so only
        // a user actor can be the caller or have an email.
        actorIsYou: event.actorType === "user" && event.actorId === user._id,
        actorEmail:
          event.actorType === "user"
            ? await emailOf(ctx, emails, event.actorId)
            : null,
        targetKind: placed.kind,
        targetId: placed.targetId,
        environmentId: placed.environmentId,
      });
    }
    return out;
  },
});

/**
 * Whether one org event belongs to this project, and if so where.
 *
 * A secret belongs through its environment; an environment by being in the
 * set read from `by_project_name`; the project by being this project. The
 * target row is read, never trusted from the event alone, so an event whose
 * target is gone, or names a row in another project, is simply not shown.
 */
async function placeInProject(
  ctx: QueryCtx,
  event: Doc<"auditLog">,
  project: Doc<"projects">,
  environments: Set<string>,
): Promise<{
  kind: TargetKind;
  targetId: string;
  environmentId: Id<"environments"> | null;
} | null> {
  const kind = kindOf(event.action);
  const targetId = event.targetId;
  if (kind === null || targetId === undefined) return null;

  if (kind === "project") {
    return targetId === project._id
      ? { kind, targetId, environmentId: null }
      : null;
  }
  if (kind === "environment") {
    const environment = await getAuditSubject(ctx, "environments", targetId);
    return environment !== null && environments.has(environment._id)
      ? { kind, targetId, environmentId: environment._id }
      : null;
  }
  const secret = await getAuditSubject(ctx, "secrets", targetId);
  return secret !== null && environments.has(secret.environmentId)
    ? { kind, targetId, environmentId: secret.environmentId }
    : null;
}

async function emailOf(
  ctx: QueryCtx,
  cache: Map<string, string | null>,
  actorId: string,
): Promise<string | null> {
  const cached = cache.get(actorId);
  if (cached !== undefined) return cached;
  const actor = await getAuditSubject(ctx, "users", actorId);
  const email = actor === null ? null : actor.email;
  cache.set(actorId, email);
  return email;
}
