import { ConvexError, v } from "convex/values";
import type { Doc, Id } from "../_generated/dataModel";
import type { QueryCtx } from "../_generated/server";
import { getOrg, getOrgMember } from "../repo/orgs";
import { getProject } from "../repo/projects";
import { getEnvironment } from "../repo/environments";
import { getSecret } from "../repo/secrets";
import { getSessionByTokenHash } from "../repo/sessions";
import { getUser } from "../repo/users";
import { hashSessionToken } from "./session";

/**
 * WHO IS CALLING. THIS IS THE TRUST BOUNDARY.
 *
 * This file used to export `callerArg`, a `v.id("users")` that every handler
 * spread into its arguments, and the identity of the caller was therefore
 * whatever the client typed. That is gone. It is deleted rather than
 * deprecated so that any handler still resolving a caller from its own
 * arguments fails to compile, which is the only form of "do not do that again"
 * a build can enforce.
 *
 * What replaces it is `sessionArg`, and the difference is not cosmetic even
 * though both are arguments. `callerId` was a CLAIM: the server believed it.
 * `sessionToken` is a CREDENTIAL: the server hashes it, looks the hash up in
 * `sessions`, checks the deadline on the row it finds, loads the user that row
 * names, and derives the identity from the database. A client that supplies
 * another user's id now supplies nothing at all, because no handler takes one.
 *
 * It is an argument rather than an `Authorization` header because a Convex
 * query or mutation invoked through the client has no headers of its own; see
 * the investigation recorded at the top of `session.ts`. The consequence is a
 * rule with no exceptions: THE SESSION TOKEN NEVER APPEARS IN A LOG LINE, AN
 * ERROR MESSAGE, AN AUDIT ROW OR A URL. Nothing below echoes it, and the
 * refusal string is a constant precisely so that no future edit can
 * accidentally interpolate one.
 */
export const sessionArg = { sessionToken: v.string() } as const;

/**
 * The refusal for "you are not signed in", as distinct from the hierarchy's
 * refusal below.
 *
 * Distinguishing them leaks nothing. The caller already knows whether it
 * presented a token, so this tells it only what it told us, and in exchange
 * the dashboard can send the user to the sign in screen instead of showing an
 * error about a resource. It covers a token that was never issued, one that
 * has expired, one that was logged out, and one whose user is gone: four
 * causes, one string, because which of them it was is the server's business.
 */
export const NOT_AUTHENTICATED = "Your session is not valid. Sign in again.";

/**
 * Every refusal in the hierarchy says exactly this, whether the row is absent,
 * belongs to another organisation, or the caller is not a member.
 *
 * A distinct "not found" would confirm the existence of another tenant's org,
 * project, environment or secret one guessed id at a time, which is the same
 * account enumeration oracle `auth.ts` goes to lengths to close, applied to
 * rows instead of to addresses. Convex ids are unguessable in practice, so
 * this is defence in depth rather than the only defence, but a single string
 * costs nothing and removes the question.
 */
export const NOT_PERMITTED = "Not found, or you do not have access to it.";

function refuse(): never {
  throw new ConvexError(NOT_PERMITTED);
}

/**
 * The caller, resolved from the presented session token and from nothing else.
 *
 * The deadline is compared with `>=` rather than `>`: a session valid "until"
 * an instant is not valid at it, and the alternative leaves a one millisecond
 * window nobody would ever think about again.
 *
 * KNOWN LIMIT, recorded here because it is invisible at the call site. Convex
 * caches and reactively re-runs QUERIES based on the rows they read, not on
 * the passage of time, so a subscription that read a live session row is not
 * re-evaluated at the moment that row's deadline passes. What bounds that is
 * the row itself disappearing: logout deletes it, and the prune cron in
 * `sessions.ts` deletes expired ones, and either deletion invalidates every
 * query that read it. Any new mutation is checked against the wall clock at
 * execution time and is never affected.
 */
export async function requireSession(
  ctx: QueryCtx,
  sessionToken: string,
): Promise<Doc<"users">> {
  // No shape check and no decode. A presented token is hashed as the string it
  // arrived as, so a malformed one takes exactly the same path as an unknown
  // one: one index miss, one refusal, no second error message to tell the two
  // apart and no branch that could throw something else.
  const session = await getSessionByTokenHash(
    ctx,
    hashSessionToken(sessionToken),
  );
  if (session === null) throw new ConvexError(NOT_AUTHENTICATED);
  if (Date.now() >= session.expiresAt) {
    throw new ConvexError(NOT_AUTHENTICATED);
  }

  // A session naming a user that no longer exists is refused rather than
  // treated as an anonymous caller. It also means account deletion, whenever
  // it ships, cannot leave a usable credential behind by forgetting the
  // cascade: the sessions still resolve to nothing.
  const user = await getUser(ctx, session.userId);
  if (user === null) throw new ConvexError(NOT_AUTHENTICATED);
  return user;
}

export interface OrgScope {
  user: Doc<"users">;
  org: Doc<"orgs">;
  member: Doc<"orgMembers">;
}

export interface ProjectScope extends OrgScope {
  project: Doc<"projects">;
}

export interface EnvironmentScope extends ProjectScope {
  environment: Doc<"environments">;
}

export interface SecretScope extends EnvironmentScope {
  secret: Doc<"secrets">;
}

/**
 * AUTHENTICATION STRICTLY BEFORE ANY LOOKUP, WHICH IS WHY THE WALK IS SPLIT.
 *
 * Every exported `require*` below resolves the session first and only then
 * touches a row. The obvious shape, "fetch the secret, walk it back to an org,
 * then check the caller", was written that way at first and is wrong now that
 * there are two refusal strings: an attacker with no session at all would get
 * NOT_PERMITTED for an id that does not exist and NOT_AUTHENTICATED for one
 * that does, which turns the pair of messages into exactly the row
 * enumeration oracle a single message was chosen to avoid. It cost nothing
 * when identity came from an argument and there was only one string; it costs
 * the whole property now.
 *
 * The `*ScopeFor` helpers are not exported. They take an already resolved user
 * so that the chain never re-authenticates and never runs out of order.
 */
async function orgScopeFor(
  ctx: QueryCtx,
  user: Doc<"users">,
  orgId: Id<"orgs">,
): Promise<OrgScope> {
  const org = await getOrg(ctx, orgId);
  if (org === null) refuse();
  const member = await getOrgMember(ctx, orgId, user._id);
  if (member === null) refuse();
  return { user, org, member };
}

/**
 * A project id, an environment id or a secret id carries no organisation with
 * it, so every one of them has to be walked back to an org before membership
 * means anything. Each handler doing that walk itself is how one of them ends
 * up checking that the project exists and forgetting to check whose it is.
 */
async function projectScopeFor(
  ctx: QueryCtx,
  user: Doc<"users">,
  projectId: Id<"projects">,
): Promise<ProjectScope> {
  const project = await getProject(ctx, projectId);
  if (project === null) refuse();
  return { ...(await orgScopeFor(ctx, user, project.orgId)), project };
}

async function environmentScopeFor(
  ctx: QueryCtx,
  user: Doc<"users">,
  environmentId: Id<"environments">,
): Promise<EnvironmentScope> {
  const environment = await getEnvironment(ctx, environmentId);
  if (environment === null) refuse();
  return {
    ...(await projectScopeFor(ctx, user, environment.projectId)),
    environment,
  };
}

/**
 * Membership is the authorisation check for everything org-scoped, reads
 * included. A query that only returns "metadata" still answers whether a row
 * exists and what it is called, which is not the caller's business.
 */
export async function requireOrg(
  ctx: QueryCtx,
  sessionToken: string,
  orgId: Id<"orgs">,
): Promise<OrgScope> {
  return await orgScopeFor(ctx, await requireSession(ctx, sessionToken), orgId);
}

export async function requireProject(
  ctx: QueryCtx,
  sessionToken: string,
  projectId: Id<"projects">,
): Promise<ProjectScope> {
  return await projectScopeFor(
    ctx,
    await requireSession(ctx, sessionToken),
    projectId,
  );
}

export async function requireEnvironment(
  ctx: QueryCtx,
  sessionToken: string,
  environmentId: Id<"environments">,
): Promise<EnvironmentScope> {
  return await environmentScopeFor(
    ctx,
    await requireSession(ctx, sessionToken),
    environmentId,
  );
}

export async function requireSecret(
  ctx: QueryCtx,
  sessionToken: string,
  secretId: Id<"secrets">,
): Promise<SecretScope> {
  const user = await requireSession(ctx, sessionToken);
  const secret = await getSecret(ctx, secretId);
  if (secret === null) refuse();
  return {
    ...(await environmentScopeFor(ctx, user, secret.environmentId)),
    secret,
  };
}
