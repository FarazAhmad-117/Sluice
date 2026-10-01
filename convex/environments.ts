import { ConvexError, v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import {
  sessionArg,
  requireEnvironment,
  requireProject,
  NOT_PERMITTED,
} from "./lib/authz";
import { insertEnvironmentWithGrant } from "./lib/environments";
import {
  getPDKGrant,
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

/**
 * Validation, the uniqueness checks, the insert and the grant written in the
 * same transaction all live in `insertEnvironmentWithGrant`
 * (`lib/environments.ts`), shared with `projects.createProjectWithEnvironments`
 * so that the two creation paths cannot drift. Read it before changing what an
 * environment is created with.
 */
export const createEnvironment = mutation({
  args: {
    ...sessionArg,
    // The environment's permanent id, `env_` + 32 lowercase hex, minted by
    // the client with `newId("env")` BEFORE this call: the key below is
    // wrapped under associated data that names it, and every secret in the
    // environment will be sealed under it too. Client-chosen, so its shape is
    // checked and its uniqueness enforced here; see
    // `packages/crypto/src/ids.ts`.
    environmentUid: v.string(),
    projectId: v.id("projects"),
    name: v.string(),
    // THE PROJECT DATA KEY, WRAPPED TO THE CREATOR. The key itself is minted in
    // the browser and this server has never held it and must never be able to:
    // that is the zero-knowledge property, and it is why these two arrive as
    // arguments rather than being produced here, exactly as `createOrg` takes
    // `wrappedRevocationKey`.
    //
    // The client wraps under `pdkAssociatedData({ environmentUid,
    // pdkVersion: 1, granteeType: "user", granteeId: <the caller's usr_ uid>
    // })` from `@sluice/crypto`: this environment's uid above, the first key
    // version, and the uid `login` returned as `userUid`. All three exist
    // before this mutation runs, which is what lets the wrap name the
    // environment at all. Nothing on this server computes or checks that
    // associated data: the server cannot, and a server that could choose it
    // could hand a client the bytes of a different grant. What the server
    // does is store exactly the inputs the client wrapped under, so a reader
    // can rebuild them.
    wrappedPDK: v.string(),
    pdkNonce: v.string(),
    // The key version the client wrapped `wrappedPDK` under. Must be 1. See
    // `NEW_ENVIRONMENT_PDK_VERSION`.
    pdkVersion: v.number(),
  },
  returns: v.id("environments"),
  handler: async (ctx, args): Promise<Id<"environments">> => {
    // Authorisation walks project -> org -> membership. Creating an
    // environment under someone else's project is the shortest path into
    // another tenancy, because every secret hangs off an environment id.
    const scope = await requireProject(ctx, args.sessionToken, args.projectId);
    return await insertEnvironmentWithGrant(ctx, scope, args);
  },
});

export const getEnvironment = query({
  args: { ...sessionArg, environmentId: v.id("environments") },
  returns: v.object({
    environmentId: v.id("environments"),
    // The permanent id. Secret and grant associated data name this, never
    // `environmentId`.
    uid: v.string(),
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
      uid: environment.uid,
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
      uid: v.string(),
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
      uid: environment.uid,
      projectId: environment.projectId,
      name: environment.name,
      pdkVersion: environment.pdkVersion,
      epoch: environment.epoch,
    }));
  },
});

/**
 * The caller's own wrapped project data key for one environment, for unwrapping
 * on the client before any secret in that environment can be opened.
 *
 * IT TAKES NO GRANTEE ARGUMENT, AND THAT IS THE AUTHORISATION. The only grant
 * anybody can read is their own. A `granteeId` parameter would make this an
 * endpoint for fetching other people's wrapped key material, which is useless to
 * them and is exactly the kind of read that looks harmless in review.
 * `orgs.getMyRevocationGrant` is built the same way for the same reason.
 *
 * It returns ciphertext and a version number and nothing else. The server has
 * never held the key inside `wrappedPDK` and cannot derive it from anything it
 * stores: it is sealed to material derived from the caller's account, which
 * exists only in their browser after unlock.
 */
export const getMyPdkGrant = query({
  args: { ...sessionArg, environmentId: v.id("environments") },
  returns: v.object({
    // Echoed back so a client cannot pair this blob with the wrong
    // environment's secrets. The associated data those secrets are sealed
    // under names the environment's permanent uid, which `getEnvironment`
    // returns, not this document id.
    environmentId: v.id("environments"),
    wrappedPDK: v.string(),
    nonce: v.string(),
    // WHICH key this opens. It comes off the grant row, not the environment
    // row: mid re-key they differ, and the honest answer is the version of the
    // key the caller was actually handed.
    pdkVersion: v.number(),
  }),
  handler: async (ctx, args) => {
    // The full chain: environment to project to org to membership. An
    // environment id carries no organisation with it, so this is what stops a
    // member of one org reading a grant on another org's environment.
    const { environment, user } = await requireEnvironment(
      ctx,
      args.sessionToken,
      args.environmentId,
    );

    // Keyed by the caller's permanent uid, the value `createEnvironment`
    // stored and the client's associated data names.
    const grant = await getPDKGrant(ctx, environment._id, "user", user.uid);
    // A member of the right org holding no grant is a real state, and it is the
    // state every second member of an org is in today, because nothing wraps an
    // existing key to a new member. It answers with the SHARED refusal rather
    // than a distinct message, so the pair of strings cannot be used to map
    // which colleague can open which environment: a map of who to compromise.
    if (grant === null) throw new ConvexError(NOT_PERMITTED);

    return {
      environmentId: environment._id,
      wrappedPDK: grant.wrappedPDK,
      nonce: grant.nonce,
      pdkVersion: grant.pdkVersion,
    };
  },
});
