import { ConvexError, v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { recordUserEvent } from "./lib/audit";
import {
  sessionArg,
  requireEnvironment,
  requireProject,
} from "./lib/authz";
import { assertSlug } from "./lib/naming";
import {
  getEnvironmentByName,
  insertEnvironment,
  listEnvironmentsByProject,
} from "./repo/environments";

/**
 * An environment is the unit a project data key belongs to, the unit a service
 * token is issued for, and the unit a secret is bound to by its associated
 * data. Everything below it inherits its authorisation from here.
 *
 * `name` is the last segment of the address the SDK resolves a config by,
 * org/project/environment, which is why it obeys the slug rule rather than the
 * display-name rule. A name that renders one way and is typed another matches
 * neither in an exact-match index, and `by_project_name` is exact match.
 */

const DUPLICATE_NAME =
  "An environment with that name already exists in this project.";

/**
 * The starting values, and they are not arguments.
 *
 * `epoch` is the token replay defence: it is globally monotonic per token id
 * and must never reset, so the only safe starting point is one the caller
 * cannot choose. `pdkVersion` starts at 1 rather than 0 so that "which key
 * version encrypted this row" is never answered by a falsy number, which is
 * the value a partly written client leaves behind.
 */
const INITIAL_PDK_VERSION = 1;
const INITIAL_EPOCH = 0;

export const createEnvironment = mutation({
  args: {
    ...sessionArg,
    projectId: v.id("projects"),
    name: v.string(),
  },
  returns: v.id("environments"),
  handler: async (ctx, args): Promise<Id<"environments">> => {
    // Authorisation walks project -> org -> membership. Creating an
    // environment under someone else's project is the shortest path into
    // another tenancy, because every secret hangs off an environment id.
    const { org, project, user } = await requireProject(
      ctx,
      args.sessionToken,
      args.projectId,
    );

    const name = assertSlug("name", args.name);

    // An indexed lookup on `by_project_name`, which is what that index's
    // second column is for.
    if ((await getEnvironmentByName(ctx, project._id, name)) !== null) {
      throw new ConvexError(DUPLICATE_NAME);
    }

    const environmentId = await insertEnvironment(ctx, {
      projectId: project._id,
      name,
      pdkVersion: INITIAL_PDK_VERSION,
      epoch: INITIAL_EPOCH,
    });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "environment.create",
      targetId: environmentId,
    });

    return environmentId;
  },
});

export const getEnvironment = query({
  args: { ...sessionArg, environmentId: v.id("environments") },
  returns: v.object({
    environmentId: v.id("environments"),
    projectId: v.id("projects"),
    name: v.string(),
    pdkVersion: v.number(),
    epoch: v.number(),
  }),
  handler: async (ctx, args) => {
    const { environment } = await requireEnvironment(
      ctx,
      args.sessionToken,
      args.environmentId,
    );
    return {
      environmentId: environment._id,
      projectId: environment.projectId,
      name: environment.name,
      pdkVersion: environment.pdkVersion,
      epoch: environment.epoch,
    };
  },
});

export const listEnvironments = query({
  args: { ...sessionArg, projectId: v.id("projects") },
  returns: v.array(
    v.object({
      environmentId: v.id("environments"),
      projectId: v.id("projects"),
      name: v.string(),
      pdkVersion: v.number(),
      epoch: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const { project } = await requireProject(
      ctx,
      args.sessionToken,
      args.projectId,
    );
    const environments = await listEnvironmentsByProject(ctx, project._id);
    return environments.map((environment) => ({
      environmentId: environment._id,
      projectId: environment.projectId,
      name: environment.name,
      pdkVersion: environment.pdkVersion,
      epoch: environment.epoch,
    }));
  },
});
