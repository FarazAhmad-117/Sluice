import { ConvexError } from "convex/values";
import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx } from "../_generated/server";
import { recordUserEvent } from "./audit";
import { assertHexAtLeast, assertHexBytes } from "./hex";
import { requireId } from "./ids";
import { assertSlug } from "./naming";
import {
  getEnvironmentByName,
  getEnvironmentByUid,
  insertEnvironment,
  insertPDKGrant,
} from "../repo/environments";

/**
 * ENVIRONMENT CREATION, SHARED BY BOTH PATHS THAT CREATE ONE.
 *
 * `environments.createEnvironment` adds one environment to an existing
 * project; `projects.createProjectWithEnvironments` creates a project and its
 * first environments in one mutation. Both go through
 * `insertEnvironmentWithGrant` below, so the validation, the uniqueness checks
 * and, above all, the grant written in the same transaction as the
 * environment are one piece of code rather than two that can drift.
 *
 * It lives here rather than in `environments.ts` because every export of a
 * Convex function module is part of that module's public surface, and the
 * suites pin those surfaces exactly (`environments.test.ts`,
 * `unauthenticated.test.ts`). A plain helper exported from there would be
 * enumerated as if it were an endpoint.
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

/**
 * Validates one environment's client-supplied fields and inserts the
 * environment AND its creator's key grant. The only code that inserts into
 * `environments`; both creation paths go through it, so an environment can
 * never exist without the grant that makes its secrets readable.
 *
 * IT DOES NOT AUTHORISE. `scope` is what the caller's membership walk
 * produced: `requireProject` for an existing project, or `requireOrg` plus the
 * project row inserted in the same mutation. The org, project and user below
 * are therefore never values read from an argument, which is what lets the
 * insert and the grant name them without checking them again.
 */
export async function insertEnvironmentWithGrant(
  ctx: MutationCtx,
  scope: { org: Doc<"orgs">; project: Doc<"projects">; user: Doc<"users"> },
  input: {
    environmentUid: string;
    name: string;
    wrappedPDK: string;
    pdkNonce: string;
    pdkVersion: number;
  },
): Promise<Id<"environments">> {
  const { org, project, user } = scope;

  const uid = requireId("env", "environmentUid", input.environmentUid);
  const name = assertSlug("name", input.name);

  // The nonce is checked by shape and the wrapped key is not, which looks
  // inconsistent and is not. A nonce has exactly one correct width: AES-GCM
  // accepts any length and derives its counter block through GHASH when the
  // nonce is not 96 bits, so a wrong-width nonce decrypts happily and
  // silently leaves the construction `@sluice/crypto` was reviewed under. The
  // wrapped key is an opaque blob whose internal format is the client's
  // business, and the server has no way to check it beyond a length floor.
  assertHexBytes("pdkNonce", input.pdkNonce, NONCE_BYTES);
  assertHexAtLeast("wrappedPDK", input.wrappedPDK, MIN_CIPHERTEXT_BYTES);
  if (input.pdkVersion !== INITIAL_PDK_VERSION) {
    throw new ConvexError(NEW_ENVIRONMENT_PDK_VERSION);
  }

  // An indexed lookup on `by_project_name`, which is what that index's
  // second column is for. It also sees environments inserted earlier in the
  // same mutation, which is what refuses a duplicate name inside one
  // `createProjectWithEnvironments` call.
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
    // From the org the caller's membership walk resolved (see `scope`),
    // never from an argument: there is no orgId argument to take it from.
    orgId: org._id,
    name,
    pdkVersion: INITIAL_PDK_VERSION,
    epoch: INITIAL_EPOCH,
  });

  // THE GRANT IS CREATED HERE, IN THE SAME MUTATION AS THE ENVIRONMENT, AND
  // THAT IS THE POINT OF ENVIRONMENT CREATION TAKING KEY MATERIAL AT ALL.
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
    wrappedPDK: input.wrappedPDK,
    nonce: input.pdkNonce,
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
}
