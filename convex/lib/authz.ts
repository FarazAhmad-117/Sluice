import { ConvexError, v } from "convex/values";
import type { Doc, Id } from "../_generated/dataModel";
import type { QueryCtx } from "../_generated/server";
import { getOrg, getOrgMember } from "../repo/orgs";
import { getProject } from "../repo/projects";
import { getEnvironment } from "../repo/environments";
import { getSecret } from "../repo/secrets";
import { getUser } from "../repo/users";

/**
 * WHO IS CALLING, AND WHY THIS IS NOT YET A TRUST BOUNDARY.
 *
 * `callerId` is an ARGUMENT. Any client that can reach this deployment can
 * pass any user id and be treated as that user. That is not a subtle hole, it
 * is the absence of a session layer: `auth.login` returns wrapped key material
 * and nothing that a later request can present as proof of who it is, and the
 * backend plan introduces bearer credentials only in Task 10, for service
 * tokens rather than for people.
 *
 * It is spelled this way, in one place, on purpose. Every public function in
 * `orgs.ts`, `projects.ts`, `environments.ts` and `secrets.ts` spreads
 * `callerArg` and resolves the caller through `resolveCaller`, so when real
 * sessions arrive, the identity moves from the argument to `ctx.auth` in this
 * file and nowhere else. The alternative, each handler reading an id out of
 * its own args, is the version where one handler gets missed.
 *
 * DO NOT expose this deployment to the public internet before that change.
 */
export const callerArg = { callerId: v.id("users") } as const;

/**
 * Every refusal in the hierarchy says exactly this, whether the row is absent,
 * belongs to another organisation, or the caller is not a user at all.
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
 * The caller's user row. Resolved rather than trusted: an id for a user that
 * does not exist must not be able to create an organisation, because the
 * membership and the revocation grant would then name a row nobody can ever
 * authenticate as, and the org would be unreachable and unrevocable forever.
 */
export async function resolveCaller(
  ctx: QueryCtx,
  callerId: Id<"users">,
): Promise<Doc<"users">> {
  const user = await getUser(ctx, callerId);
  if (user === null) refuse();
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
 * Membership is the authorisation check for everything org-scoped, reads
 * included. A query that only returns "metadata" still answers whether a row
 * exists and what it is called, which is not the caller's business.
 */
export async function requireOrg(
  ctx: QueryCtx,
  callerId: Id<"users">,
  orgId: Id<"orgs">,
): Promise<OrgScope> {
  const user = await resolveCaller(ctx, callerId);
  const org = await getOrg(ctx, orgId);
  if (org === null) refuse();
  const member = await getOrgMember(ctx, orgId, user._id);
  if (member === null) refuse();
  return { user, org, member };
}

/**
 * The chain below is the reason these live together. A project id, an
 * environment id or a secret id carries no organisation with it, so every one
 * of them has to be walked back to an org before membership means anything.
 * Each handler doing that walk itself is how one of them ends up checking that
 * the project exists and forgetting to check whose it is.
 */
export async function requireProject(
  ctx: QueryCtx,
  callerId: Id<"users">,
  projectId: Id<"projects">,
): Promise<ProjectScope> {
  const project = await getProject(ctx, projectId);
  if (project === null) refuse();
  const scope = await requireOrg(ctx, callerId, project.orgId);
  return { ...scope, project };
}

export async function requireEnvironment(
  ctx: QueryCtx,
  callerId: Id<"users">,
  environmentId: Id<"environments">,
): Promise<EnvironmentScope> {
  const environment = await getEnvironment(ctx, environmentId);
  if (environment === null) refuse();
  const scope = await requireProject(ctx, callerId, environment.projectId);
  return { ...scope, environment };
}

export async function requireSecret(
  ctx: QueryCtx,
  callerId: Id<"users">,
  secretId: Id<"secrets">,
): Promise<SecretScope> {
  const secret = await getSecret(ctx, secretId);
  if (secret === null) refuse();
  const scope = await requireEnvironment(ctx, callerId, secret.environmentId);
  return { ...scope, secret };
}
