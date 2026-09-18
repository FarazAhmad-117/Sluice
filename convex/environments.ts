import { ConvexError, v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { recordUserEvent } from "./lib/audit";
import {
  sessionArg,
  requireEnvironment,
  requireProject,
  NOT_PERMITTED,
} from "./lib/authz";
import { assertHexAtLeast, assertHexBytes } from "./lib/hex";
import { assertSlug } from "./lib/naming";
import {
  getEnvironmentByName,
  getPDKGrant,
  insertEnvironment,
  insertPDKGrant,
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

// AES-GCM nonce, 96 bits, the only width `@sluice/crypto` produces.
const NONCE_BYTES = 12;
// AES-GCM appends a 16 byte tag, so nothing shorter can be output this product
// produced. The same floor `tokens.ts` and `secrets.ts` apply.
const MIN_CIPHERTEXT_BYTES = 16;

export const createEnvironment = mutation({
  args: {
    ...sessionArg,
    projectId: v.id("projects"),
    name: v.string(),
    // THE PROJECT DATA KEY, WRAPPED TO THE CREATOR. The key itself is minted in
    // the browser and this server has never held it and must never be able to:
    // that is the zero-knowledge property, and it is why these two arrive as
    // arguments rather than being produced here, exactly as `createOrg` takes
    // `wrappedRevocationKey`.
    //
    // The associated data the client wraps under is `pdkAssociatedData` from
    // `@sluice/crypto`. Nothing on this server computes or checks it: the
    // server cannot, and a server that could choose the associated data could
    // hand a client the bytes of a different grant.
    wrappedPDK: v.string(),
    pdkNonce: v.string(),
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

    // The nonce is checked by shape and the wrapped key is not, which looks
    // inconsistent and is not. A nonce has exactly one correct width: AES-GCM
    // accepts any length and derives its counter block through GHASH when the
    // nonce is not 96 bits, so a wrong-width nonce decrypts happily and
    // silently leaves the construction `@sluice/crypto` was reviewed under. The
    // wrapped key is an opaque blob whose internal format is the client's
    // business, and the server has no way to check it beyond a length floor.
    assertHexBytes("pdkNonce", args.pdkNonce, NONCE_BYTES);
    assertHexAtLeast("wrappedPDK", args.wrappedPDK, MIN_CIPHERTEXT_BYTES);

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

    // THE GRANT IS CREATED HERE, IN THIS MUTATION, AND THAT IS THE POINT OF
    // THIS HANDLER TAKING KEY MATERIAL AT ALL.
    //
    // `createEnvironment` used to take a project and a name. No grant was ever
    // written, no Convex function read or wrote `pdkGrants`, and the project
    // data key could therefore reach nobody: every secret in the product was
    // ciphertext under a key no client could obtain. Nothing errored. The
    // secrets table listed real rows with real metadata and showed every value
    // as sealed, for ever.
    //
    // The same argument `createOrg` makes for its revocation grant, and the
    // same remedy. Convex mutations are atomic, so the environment and its
    // first grant either both land or neither does. Never split this across two
    // mutations, and never add a second way to insert into `environments`: the
    // state between the two halves is an environment whose secrets nobody can
    // ever read, discovered long after creation with no error at any point.
    await insertPDKGrant(ctx, {
      environmentId,
      granteeType: "user",
      // The caller, resolved from the session. There is no grantee argument, so
      // an environment cannot be created with its only key wrapped to somebody
      // else, and nobody can plant a grant for a person who never asked for it.
      granteeId: user._id,
      wrappedPDK: args.wrappedPDK,
      nonce: args.pdkNonce,
      // Off the row this mutation just wrote, so the two cannot disagree.
      pdkVersion: INITIAL_PDK_VERSION,
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
    // environment's secrets, whose associated data binds the environment id.
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

    const grant = await getPDKGrant(ctx, environment._id, "user", user._id);
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
