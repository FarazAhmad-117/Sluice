import { ConvexError, v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Doc, Id } from "./_generated/dataModel";
import type { MutationCtx } from "./_generated/server";
import { recordUserEvent } from "./lib/audit";
import {
  sessionArg,
  NOT_PERMITTED,
  requireOrg,
  requireProject,
} from "./lib/authz";
import { insertEnvironmentWithGrant } from "./lib/environments";
import {
  PROJECT_NEEDS_DEVELOPMENT,
  TOO_MANY_ENVIRONMENTS,
} from "./lib/errors";
import { assertDisplayName, assertSlug } from "./lib/naming";
import {
  getProject as getProjectRow,
  getProjectBySlug,
  insertProject,
  listProjectsByOrg,
} from "./repo/projects";

/**
 * A project groups environments inside one organisation. It holds no key
 * material and no ciphertext, which is exactly why its read path is easy to
 * leave unauthorised: it looks like nothing but a name. It is not. Knowing
 * that a competitor has a project called `acquisition-modelling` is worth
 * something, and a project id is the route to its environments and from there
 * to its secrets.
 */

const DUPLICATE_SLUG =
  "A project with that slug already exists in this organisation.";

/**
 * Validates a project's name and slug and inserts it, with its audit event.
 * Shared by both creation paths so they cannot disagree about what a valid
 * project is. Not exported: every export of this module is part of its public
 * surface. It does not authorise; `scope` is what `requireOrg` returned.
 */
async function insertValidatedProject(
  ctx: MutationCtx,
  scope: { org: Doc<"orgs">; user: Doc<"users"> },
  input: { name: string; slug: string },
): Promise<Id<"projects">> {
  const { org, user } = scope;
  const name = assertDisplayName("name", input.name);
  const slug = assertSlug("slug", input.slug);

  // An indexed lookup on `by_org_slug`, not a scan and a filter. The index
  // is composite for this: slugs are unique within an org rather than
  // globally, so the first customer to take `api` does not take it from
  // everyone else.
  if ((await getProjectBySlug(ctx, org._id, slug)) !== null) {
    throw new ConvexError(DUPLICATE_SLUG);
  }

  const projectId = await insertProject(ctx, { orgId: org._id, name, slug });

  await recordUserEvent(ctx, {
    orgId: org._id,
    actorId: user._id,
    action: "project.create",
    targetId: projectId,
  });

  return projectId;
}

export const createProject = mutation({
  args: {
    ...sessionArg,
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
  },
  returns: v.id("projects"),
  handler: async (ctx, args): Promise<Id<"projects">> => {
    // Membership first, before any validation that could distinguish one org
    // from another by which error it returns.
    const scope = await requireOrg(ctx, args.sessionToken, args.orgId);
    return await insertValidatedProject(ctx, scope, args);
  },
});

/**
 * THE LARGEST STARTING SET OF ENVIRONMENTS. See `TOO_MANY_ENVIRONMENTS`.
 */
const MAX_INITIAL_ENVIRONMENTS = 10;

/**
 * A PROJECT AND ITS FIRST ENVIRONMENTS, ATOMICALLY.
 *
 * The dashboard's create-project flow mints one project data key per
 * environment in the browser, wraps each to the creator, and sends them all
 * here. Doing the same with `createProject` and then N `createEnvironment`
 * calls works until one of them fails part way, and then leaves a project
 * with some of its environments, or with none, which is a project nothing can
 * be stored in. One Convex mutation is one transaction: the project and every
 * environment and every grant land together, or nothing does.
 *
 * NOTHING HERE IS A SECOND WAY TO CREATE EITHER. The project goes through the
 * same validation as `createProject`, and every environment through
 * `insertEnvironmentWithGrant`, the one function that inserts into
 * `environments`, so each arrives with its creator's grant in the same
 * transaction, exactly as `createEnvironment` makes it. Duplicate names
 * within the call are refused by that function's own `by_project_name`
 * lookup, which sees the environments this mutation has already inserted.
 *
 * `development` is required because the dashboard always creates it and
 * opens a new project to it.
 */
export const createProjectWithEnvironments = mutation({
  args: {
    ...sessionArg,
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
    // Exactly `createEnvironment`'s fields for each environment, minus the
    // project id, which does not exist yet. See that mutation for what each
    // one is and why the key arrives wrapped.
    environments: v.array(
      v.object({
        environmentUid: v.string(),
        name: v.string(),
        wrappedPDK: v.string(),
        pdkNonce: v.string(),
        pdkVersion: v.number(),
      }),
    ),
  },
  returns: v.object({
    projectId: v.id("projects"),
    environmentIds: v.array(v.id("environments")),
  }),
  handler: async (ctx, args) => {
    // Membership first, as in `createProject`.
    const scope = await requireOrg(ctx, args.sessionToken, args.orgId);

    // The shape of the set, before anything is written. A refusal after the
    // inserts would be rolled back too, but there is no reason to write first.
    if (args.environments.length > MAX_INITIAL_ENVIRONMENTS) {
      throw new ConvexError(TOO_MANY_ENVIRONMENTS);
    }
    if (!args.environments.some((env) => env.name === "development")) {
      throw new ConvexError(PROJECT_NEEDS_DEVELOPMENT);
    }

    const projectId = await insertValidatedProject(ctx, scope, args);
    // Read back rather than assembled, so `insertEnvironmentWithGrant` is
    // handed a real row, the same kind `requireProject` would hand it.
    const project = await getProjectRow(ctx, projectId);
    if (project === null) throw new ConvexError(NOT_PERMITTED);

    const environmentIds: Id<"environments">[] = [];
    for (const environment of args.environments) {
      environmentIds.push(
        await insertEnvironmentWithGrant(
          ctx,
          { org: scope.org, project, user: scope.user },
          environment,
        ),
      );
    }
    return { projectId, environmentIds };
  },
});

export const getProject = query({
  args: { ...sessionArg, projectId: v.id("projects") },
  returns: v.object({
    projectId: v.id("projects"),
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
  }),
  handler: async (ctx, args) => {
    const { project } = await requireProject(
      ctx,
      args.sessionToken,
      args.projectId,
    );
    return {
      projectId: project._id,
      orgId: project.orgId,
      name: project.name,
      slug: project.slug,
    };
  },
});

export const listProjects = query({
  args: { ...sessionArg, orgId: v.id("orgs") },
  returns: v.array(
    v.object({
      projectId: v.id("projects"),
      orgId: v.id("orgs"),
      name: v.string(),
      slug: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const { org } = await requireOrg(ctx, args.sessionToken, args.orgId);
    const projects = await listProjectsByOrg(ctx, org._id);
    return projects.map((project) => ({
      projectId: project._id,
      orgId: project.orgId,
      name: project.name,
      slug: project.slug,
    }));
  },
});
