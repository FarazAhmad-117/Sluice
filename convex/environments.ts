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
import { requireId } from "./lib/ids";
import { assertSlug } from "./lib/naming";
import {
  getEnvironmentByName,
  getEnvironmentByUid,
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
const DUPLICATE_UID = "An environment with that id already exists.";

/**
 * The starting values. Neither is chosen by the caller.
 *
 * `epoch` is the token replay defence: it is globally monotonic per token id
 * and must never reset, so the only safe starting point is one the caller
 * cannot choose, and it is not an argument at all. `pdkVersion` starts at 1
 * rather than 0 so that "which key version encrypted this row" is never
 * answered by a falsy number, which is the value a partly written client
 * leaves behind.
 *
 * `pdkVersion` IS an argument, and it is not a choice. The client wraps the
 * first grant under associated data that names the key version, so it must
 * state the version it wrapped under, and that must be 1. The server stores
 * exactly what the client sealed under, and the one way to guarantee that is
 * to refuse anything else rather than store 1 beside bytes that name 2: that
 * row would list, sync and never unwrap.
 */
const INITIAL_PDK_VERSION = 1;
const INITIAL_EPOCH = 0;

const NEW_ENVIRONMENT_PDK_VERSION =
  "A new environment's key starts at version 1.";

// AES-GCM nonce, 96 bits, the only width `@sluice/crypto` produces.
const NONCE_BYTES = 12;
// AES-GCM appends a 16 byte tag, so nothing shorter can be output this product
// produced. The same floor `tokens.ts` and `secrets.ts` apply.
const MIN_CIPHERTEXT_BYTES = 16;

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
    const { org, project, user } = await requireProject(
      ctx,
      args.sessionToken,
      args.projectId,
    );

    const uid = requireId("env", "environmentUid", args.environmentUid);
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
    if (args.pdkVersion !== INITIAL_PDK_VERSION) {
      throw new ConvexError(NEW_ENVIRONMENT_PDK_VERSION);
    }

    // An indexed lookup on `by_project_name`, which is what that index's
    // second column is for.
    if ((await getEnvironmentByName(ctx, project._id, name)) !== null) {
      throw new ConvexError(DUPLICATE_NAME);
    }
    // Deployment-wide, not per project or per org: the uid names the
    // environment in ciphertext bindings and must mean one environment
    // wherever it is read. A taken uid is a client reusing someone's id, not
    // a random collision, and it is refused, never upserted onto. The message
    // is the same whoever owns the existing row: it confirms the value is in
    // use and nothing about where. A uid is a label, not a secret, and a
    // caller only reaches this check by already holding one.
    if ((await getEnvironmentByUid(ctx, uid)) !== null) {
      throw new ConvexError(DUPLICATE_UID);
    }

    const environmentId = await insertEnvironment(ctx, {
      uid,
      projectId: project._id,
      // From the org `requireProject` resolved through the membership walk,
      // never from an argument: there is no orgId argument to take it from.
      orgId: org._id,
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
      orgId: org._id,
      granteeType: "user",
      // The caller, resolved from the session. There is no grantee argument, so
      // an environment cannot be created with its only key wrapped to somebody
      // else, and nobody can plant a grant for a person who never asked for it.
      //
      // Their PERMANENT uid, not `user._id`: it is the value the client named
      // in the associated data, and the lookup key must be that same string.
      granteeId: user.uid,
      wrappedPDK: args.wrappedPDK,
      nonce: args.pdkNonce,
      // Off the row this mutation just wrote, so the two cannot disagree, and
      // equal to the version the client stated it wrapped under, by the check
      // above.
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
