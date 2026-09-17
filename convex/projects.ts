import { ConvexError, v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { recordUserEvent } from "./lib/audit";
import { callerArg, requireOrg, requireProject } from "./lib/authz";
import { assertDisplayName, assertSlug } from "./lib/naming";
import {
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

export const createProject = mutation({
  args: {
    ...callerArg,
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
  },
  returns: v.id("projects"),
  handler: async (ctx, args): Promise<Id<"projects">> => {
    // Membership first, before any validation that could distinguish one org
    // from another by which error it returns.
    const { org, user } = await requireOrg(ctx, args.callerId, args.orgId);

    const name = assertDisplayName("name", args.name);
    const slug = assertSlug("slug", args.slug);

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
  },
});

export const getProject = query({
  args: { ...callerArg, projectId: v.id("projects") },
  returns: v.object({
    projectId: v.id("projects"),
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
  }),
  handler: async (ctx, args) => {
    const { project } = await requireProject(
      ctx,
      args.callerId,
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
  args: { ...callerArg, orgId: v.id("orgs") },
  returns: v.array(
    v.object({
      projectId: v.id("projects"),
      orgId: v.id("orgs"),
      name: v.string(),
      slug: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const { org } = await requireOrg(ctx, args.callerId, args.orgId);
    const projects = await listProjectsByOrg(ctx, org._id);
    return projects.map((project) => ({
      projectId: project._id,
      orgId: project.orgId,
      name: project.name,
      slug: project.slug,
    }));
  },
});
