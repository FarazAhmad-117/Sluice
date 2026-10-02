import { ConvexError, v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Doc, Id } from "./_generated/dataModel";
import type { QueryCtx } from "./_generated/server";
import { recordUserEvent } from "./lib/audit";
import {
  sessionArg,
  NOT_PERMITTED,
  assertOrgLink,
  requireEnvironment,
  requireProject,
  requireSecret,
} from "./lib/authz";
import {
  DELETE_SHARED_ROW,
  DUPLICATE_SHARE_UID,
  SHARED_NEEDS_SHARED_ROW,
  SHARED_ROWS_MISMATCH,
} from "./lib/errors";
import { assertHexAtLeast, assertHexBytes } from "./lib/hex";
import { requireId } from "./lib/ids";
import { getPDKGrant, listEnvironmentsByProject } from "./repo/environments";
import {
  insertSecret,
  listCurrentByShareUid,
  listCurrentSecretsByEnvironment,
  listSecretVersions as listVersionsBySecretUid,
  patchSecret,
  secretUidTaken,
  shareUidTaken,
} from "./repo/secrets";

/**
 * THE SERVER STORES CIPHERTEXT AND NOTHING ELSE.
 *
 * Both the name and the value of every secret arrive sealed and leave sealed.
 * Nothing in this file decrypts, and nothing in this file can: the project
 * data key never reaches the server. The associated data rule that binds each
 * ciphertext to its environment and to the algorithm version is written out in
 * full on `secretAssociatedData` in `@sluice/crypto`, which is the one
 * definition of that rule and the file a client author should read. It is not
 * restated here: this server publishes the rule to nobody and computes it
 * nowhere, and a second copy that looked authoritative is exactly what was
 * just deleted.
 *
 * The server-side halves of that rule live here:
 *
 *   1. An environment id is accepted only when a row is CREATED. No mutation
 *      accepts one for a row that already exists, so a secret cannot be moved
 *      between environments through this API, and the environment its
 *      associated data names -- by permanent uid, read off the environment
 *      row, never by this document id -- is always the one its column points
 *      at.
 *   2. `pdkVersion` is the key generation the client unwrapped and sealed
 *      under, so the client STATES it, and it must equal the environment's
 *      current `pdkVersion` or the write is refused with nothing written (see
 *      `STALE_PDK_VERSION`). The value stored is the stated one, which by that
 *      check is also the environment's: a row can neither claim a key version
 *      that never existed nor be filed under a generation its bytes were not
 *      sealed under, which is what a server-assigned number would do the
 *      moment a re-key landed between the client's unwrap and its write.
 *   3. The associated data also names the secret's permanent `sec_` id and
 *      the VERSION the row was sealed under. The server never computes those
 *      bytes, but it MUST store exactly the `secretUid` and `version` the
 *      client sealed under and return both on every read, because a reader
 *      rebuilds the associated data from them. That is what makes a splice
 *      fail: ciphertext moved into another secret's row, or an old version
 *      replayed as the current one, names a slot it does not occupy and does
 *      not open. So the version is not assigned here behind the client's
 *      back. It is STATED by the client and checked as a compare-and-set:
 *      1 on create, exactly current + 1 on update, and anything else is
 *      refused with nothing written, so a stale write fails loudly instead of
 *      storing a row whose stored slot disagrees with its sealed one.
 */

// AES-GCM appends a 16 byte tag to every ciphertext, so nothing shorter than
// 16 bytes can be output this product produced. An empty string stored as
// ciphertext lists and syncs perfectly and fails only on the day someone tries
// to read it.
const MIN_CIPHERTEXT_BYTES = 16;
const NONCE_BYTES = 12;

/**
 * WHERE A SECRET'S PERMANENT ID COMES FROM, AND WHY THAT IS NOW THE CLIENT.
 *
 * `secrets.secretUid` is a plain string in the schema and every version of one
 * logical secret shares it, so two unrelated secrets carrying the same value
 * would silently merge their histories: one would appear as a version of the
 * other, an old value would be offered as the current one, and the listing
 * would lose a row. Nothing in the schema prevents it, so it is prevented
 * here.
 *
 * It used to be minted on this server and accepted from nobody, and that was
 * the right call while the id was only a grouping key. It is not any more. The
 * client now seals both fields under associated data that NAMES the id, so it
 * must exist before the first write, and only the client can choose it: the
 * server cannot hand it out in advance without a second round trip and a
 * reservation table, and it must never be the party choosing what ciphertext
 * is bound to.
 *
 * WHAT THE OLD DESIGN DEFENDED AGAINST STILL HOLDS, BY A DIFFERENT MECHANISM.
 * A client-chosen id is an argument, and an argument can name an EXISTING
 * secret, including one the caller can write to but whose history they should
 * not be able to rewrite. Accepted naively, that turns "create a secret" into
 * "add a version to that secret": a silent overwrite of the current value with
 * no update path called and no compare-and-set run. Randomness on the client
 * does not help, because the attack is a deliberate choice, not a collision.
 * So `createSecret` refuses ANY id that ANY row already carries, deployment
 * wide, with one indexed read in the same mutation as the insert. Convex
 * mutations are serialisable transactions, so read-then-insert is not a race.
 * The only way to add a version is `updateSecret`, which is where the
 * compare-and-set lives.
 *
 * The refusal is the same whichever environment or org owns the existing row:
 * it confirms the id is in use and nothing about where. An id is a label, not
 * a secret, and the same argument `createEnvironment` makes for `env_` ids
 * applies.
 */
const DUPLICATE_SECRET_UID = "A secret with that id already exists.";

/**
 * The client sealed a brand-new secret under version 1, because that is the
 * only version a new secret has. A create stating anything else is a client
 * whose ciphertext names a slot this row will not occupy, and storing it would
 * produce a row that lists and syncs and never opens. Refused, not corrected:
 * correcting the stored number cannot change what the bytes were sealed under.
 */
const NEW_SECRET_VERSION = "A new secret starts at version 1.";
const INITIAL_SECRET_VERSION = 1;

/**
 * THE COMPARE-AND-SET REFUSAL.
 *
 * `updateSecret` takes the version the client sealed the NEW ciphertext under,
 * and it must be exactly the current version plus one. Equal to the current
 * version means two writers raced from the same starting point and this one
 * lost; higher means the client skipped a version; lower or zero means a
 * client replaying something old. In every case the stored `version` would
 * disagree with the sealed one, or a concurrent edit would be silently
 * overwritten, so the write is refused with nothing written and the person is
 * told what to do about it.
 *
 * THE SAME SENTENCE ANSWERS A WRITE ADDRESSED TO A ROW THAT IS NO LONGER
 * CURRENT, and that is the case it mostly exists for. A real race loser opened
 * version N, holds THAT row's `secretId`, and sends N + 1; the winner already
 * saved N + 1, so the row the loser names has been superseded. A separate
 * "already replaced" message used to answer that case first, which meant the
 * one person who needed "reload" was the one person never told it. There is
 * now exactly one refusal for "you are not writing on top of the latest
 * version", whichever way the staleness shows, and `deleteSecret` uses it too.
 */
const STALE_VERSION =
  "This secret changed since you opened it. Reload to see the latest version.";

/**
 * THE COMPARE-AND-SET ON THE KEY GENERATION.
 *
 * The client seals both fields under the project data key it unwrapped, whose
 * version it learned from its grant, and states that version. If somebody
 * re-keyed the environment in between, the bytes are under a generation that
 * is no longer current; storing them would either label them with the new
 * version (they would never open) or keep a superseded key in service. Refused
 * with nothing written.
 *
 * Verbatim the sentence `tokens.ts` uses for the same refusal on a token's
 * grant, because it is one rule. It is repeated rather than imported for the
 * reason `tokens.ts` gives for `NO_GRANT`: hoisting the shared refusals into
 * `lib/authz.ts` is the right follow-up and is its own change.
 */
const STALE_PDK_VERSION =
  "This environment's key changed since you opened it. Reload and try again.";

/**
 * Two versions of one secret claiming to be current, or one secret's history
 * spanning two environments, is corruption rather than a state a caller can
 * reach. It says so instead of picking one, because picking one is exactly how
 * a merged history becomes invisible.
 */
const INCONSISTENT = "This secret's version history is inconsistent.";

function refuse(): never {
  throw new ConvexError(NOT_PERMITTED);
}

/**
 * MEMBERSHIP AUTHORISES A WRITE. A GRANT IS WHAT MAKES ONE MEANINGFUL, AND
 * BOTH MUST HOLD.
 *
 * A member of the org with no row in `pdkGrants` for this environment holds no
 * project data key, so whatever they seal is sealed under a key NOBODY IN THE
 * SYSTEM HOLDS. Nothing downstream notices. The row lands, `pdkVersion` is
 * checked against the environment so it claims a real key version, the listing shows
 * it beside rows that are fine, the bundle ships it to every workload, and the
 * whole thing fails exactly once: as a bare AEAD rejection, at read time, with
 * no indication of which input was wrong, possibly months later and possibly in
 * production. It is the same class of silent, unrecoverable write that
 * `createEnvironment` mints its grant in-transaction to avoid.
 *
 * It is not a hypothetical. Every SECOND member of an org is in this state
 * today, because nothing wraps an existing project data key to a new member:
 * `createEnvironment` mints exactly one grant and it belongs to its creator.
 *
 * THE SERVER CANNOT FIX IT, ONLY REFUSE IT. Minting the missing grant here is
 * the tempting repair and it is impossible: this deployment has never held the
 * plaintext project data key and never will, so any grant it wrote would be a
 * row whose ciphertext is not a key. Refusing is the whole of the remedy.
 *
 * THE MESSAGE IS DISTINCT FROM `NOT_PERMITTED`, DELIBERATELY. `getMyPdkGrant`
 * answers a missing grant with the shared refusal, because there a distinct
 * string would let someone map which colleague can open which environment: a
 * map of who to compromise. Here the caller has ALREADY passed
 * `requireEnvironment`, so they are a member of the org, and the only fact this
 * string discloses is one about the caller's own grant, which they can
 * establish anyway by calling `getMyPdkGrant` on themselves. Nothing is leaked
 * and, in exchange, a person gets a sentence they can act on instead of "not
 * found" about an environment they are looking at.
 *
 * `granteeType` is pinned to `"user"` and is not a parameter. A user uid and a
 * `tokenIdHash` are both opaque strings in one index, and the type column is
 * the only thing keeping the two namespaces apart. The user is looked up by
 * their permanent `usr_` uid, because that is what a user grant stores.
 */
const NO_GRANT =
  "You hold no key for this environment, so nothing you wrote here could ever be read.";

async function requirePDKGrant(
  ctx: QueryCtx,
  environmentId: Id<"environments">,
  userUid: string,
): Promise<void> {
  const grant = await getPDKGrant(ctx, environmentId, "user", userUid);
  if (grant === null) throw new ConvexError(NO_GRANT);
}

interface SealedFields {
  nameCiphertext: string;
  nameNonce: string;
  valueCiphertext: string;
  valueNonce: string;
}

function assertSealed(fields: SealedFields): void {
  assertHexAtLeast("nameCiphertext", fields.nameCiphertext, MIN_CIPHERTEXT_BYTES);
  assertHexAtLeast(
    "valueCiphertext",
    fields.valueCiphertext,
    MIN_CIPHERTEXT_BYTES,
  );
  assertHexBytes("nameNonce", fields.nameNonce, NONCE_BYTES);
  assertHexBytes("valueNonce", fields.valueNonce, NONCE_BYTES);

  // Both fields of a row are sealed under the same project data key, so one
  // nonce used twice is nonce reuse under one key: it leaks the XOR of the two
  // plaintexts and the GHASH authentication key, which is total loss of
  // authentication for that key. A conforming client cannot do this, because
  // `seal` generates its own nonce and never accepts one, so this catches a
  // client that has stopped being conforming.
  if (fields.nameNonce === fields.valueNonce) {
    throw new ConvexError(
      "nameNonce and valueNonce must not be the same nonce.",
    );
  }
}

/**
 * The same rule across one secret's history: a new version sealed under the
 * same key version must not repeat a nonce an earlier version used.
 *
 * This is NOT a complete nonce-reuse detector and must not be mistaken for
 * one. It cannot see reuse across two different secrets, and widening it to
 * the whole environment would mean reading every secret on every write. The
 * real defence is that `seal` generates the nonce itself; this is the cheap
 * check at the one place the server already holds the history.
 *
 * `pdkVersion` is the generation the NEW row is sealed under, as the client
 * stated it, because that is the key under which a repeat would be reuse.
 */
function assertNoncesAreNew(
  versions: Doc<"secrets">[],
  pdkVersion: number,
  fields: SealedFields,
): void {
  const used = new Set<string>();
  for (const version of versions) {
    if (version.pdkVersion !== pdkVersion) continue;
    used.add(version.nameNonce);
    used.add(version.valueNonce);
  }
  if (used.has(fields.nameNonce) || used.has(fields.valueNonce)) {
    throw new ConvexError(
      "A nonce may not be reused under one project data key.",
    );
  }
}

/**
 * Every version of the secret this row belongs to, oldest first, plus the one
 * current version.
 *
 * The environment check is the guard against one `secretUid` spanning two
 * environments. It cannot happen through this API, because `createSecret`
 * refuses an id any row already carries and `updateSecret` copies both the id
 * and the environment off the row being superseded, but this is the read path
 * that would quietly serve the result if it ever did.
 */
async function historyOf(
  ctx: QueryCtx,
  secret: Doc<"secrets">,
): Promise<{ versions: Doc<"secrets">[]; current: Doc<"secrets"> }> {
  const versions = await listVersionsBySecretUid(ctx, secret.secretUid);
  if (versions.some((row) => row.environmentId !== secret.environmentId)) {
    throw new ConvexError(INCONSISTENT);
  }
  const live = versions.filter((row) => row.supersededAt === undefined);
  if (live.length !== 1) throw new ConvexError(INCONSISTENT);
  return { versions, current: live[0] as Doc<"secrets"> };
}

const secretShape = {
  secretId: v.id("secrets"),
  environmentId: v.id("environments"),
  // The permanent id and the version, exactly as the client sealed under:
  // together with the environment's uid they are the inputs a reader needs to
  // rebuild `secretAssociatedData`. See the header, point 3.
  secretUid: v.string(),
  version: v.number(),
  pdkVersion: v.number(),
  nameCiphertext: v.string(),
  nameNonce: v.string(),
  valueCiphertext: v.string(),
  valueNonce: v.string(),
  supersededAt: v.optional(v.number()),
  // Present only on a row of a shared secret. Plaintext grouping metadata,
  // bound into nothing: see `shr_` in `packages/crypto/src/ids.ts`.
  shareUid: v.optional(v.string()),
  overridden: v.optional(v.boolean()),
};

/**
 * `deletedAt` is deliberately absent from the returned shape. Nothing here
 * ever returns a deleted secret, so a field for it would be permanently
 * undefined and would invite a caller to filter on it, which is the filtering
 * this file is supposed to be doing.
 */
function view(secret: Doc<"secrets">) {
  return {
    secretId: secret._id,
    environmentId: secret.environmentId,
    secretUid: secret.secretUid,
    version: secret.version,
    pdkVersion: secret.pdkVersion,
    nameCiphertext: secret.nameCiphertext,
    nameNonce: secret.nameNonce,
    valueCiphertext: secret.valueCiphertext,
    valueNonce: secret.valueNonce,
    ...(secret.supersededAt === undefined
      ? {}
      : { supersededAt: secret.supersededAt }),
    ...(secret.shareUid === undefined ? {} : { shareUid: secret.shareUid }),
    ...(secret.overridden === undefined
      ? {}
      : { overridden: secret.overridden }),
  };
}

export const createSecret = mutation({
  args: {
    ...sessionArg,
    // The only place an environment id is ever accepted. After this, a row's
    // environment is read from the row and never from a caller.
    environmentId: v.id("environments"),
    // The secret's permanent id, `sec_` + 32 lowercase hex, minted by the
    // client with `newId("sec")` BEFORE this call, because both fields below
    // are sealed under associated data that names it. Client-chosen, so its
    // shape is checked and its uniqueness enforced here. See the note above
    // `DUPLICATE_SECRET_UID`.
    secretUid: v.string(),
    // The version the client sealed both fields under. Must be 1. It is an
    // argument rather than a constant so that a client which sealed under
    // anything else is refused instead of having its row stored under a
    // version its bytes do not name.
    version: v.number(),
    // The project data key generation the client sealed both fields under:
    // the `pdkVersion` of the grant it unwrapped. Must equal the
    // environment's current one. See `STALE_PDK_VERSION`.
    pdkVersion: v.number(),
    nameCiphertext: v.string(),
    nameNonce: v.string(),
    valueCiphertext: v.string(),
    valueNonce: v.string(),
  },
  returns: v.object({
    secretId: v.id("secrets"),
    secretUid: v.string(),
    version: v.number(),
  }),
  handler: async (ctx, args) => {
    const { org, environment, user } = await requireEnvironment(
      ctx,
      args.sessionToken,
      args.environmentId,
    );
    // The copy of the org on the environment is about to be written onto the
    // new row, so it must be the org the walk authorised. See `authz.ts`.
    assertOrgLink(environment.orgId, org);
    // Before any validation and before the id is looked up, so a caller with
    // no key cannot probe which secret ids are taken or learn anything from
    // the order in which their arguments were rejected.
    await requirePDKGrant(ctx, environment._id, user.uid);

    const secretUid = requireId("sec", "secretUid", args.secretUid);
    if (args.version !== INITIAL_SECRET_VERSION) {
      throw new ConvexError(NEW_SECRET_VERSION);
    }
    assertSealed(args);
    // After the shape checks and before any lookup or insert, the position
    // `tokens.createServiceToken` gives the same check.
    if (args.pdkVersion !== environment.pdkVersion) {
      throw new ConvexError(STALE_PDK_VERSION);
    }

    // Deployment wide, and any row at all, superseded or deleted included: an
    // id that ever named a secret names that secret for ever, and reusing it
    // is how a create becomes an overwrite of somebody else's history.
    if (await secretUidTaken(ctx, secretUid)) {
      throw new ConvexError(DUPLICATE_SECRET_UID);
    }

    const secretId = await insertSecret(ctx, {
      environmentId: environment._id,
      // Off the environment row the authorisation walk loaded. There is no
      // orgId argument, so a caller cannot file a secret under another org.
      orgId: environment.orgId,
      // Exactly what the client sealed under. See the header, point 3.
      secretUid,
      nameCiphertext: args.nameCiphertext,
      nameNonce: args.nameNonce,
      valueCiphertext: args.valueCiphertext,
      valueNonce: args.valueNonce,
      // What the client sealed under, equal to the environment's current
      // generation by the check above. See the header, point 2.
      pdkVersion: args.pdkVersion,
      version: INITIAL_SECRET_VERSION,
    });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "secret.create",
      targetId: secretId,
    });

    return { secretId, secretUid, version: INITIAL_SECRET_VERSION };
  },
});

/**
 * An update is an insert. The previous row is marked superseded and keeps its
 * ciphertext exactly as it was, because a version history that rewrites rows
 * is not a history.
 *
 * The caller states the version it sealed the new ciphertext under, and the
 * write lands only if that is exactly the current version plus one. See
 * `STALE_VERSION`. The new row keeps the secret's `secretUid`, read off the
 * row being replaced.
 */
export const updateSecret = mutation({
  args: {
    ...sessionArg,
    secretId: v.id("secrets"),
    // The version the client sealed the NEW ciphertext under: the version it
    // opened, plus one. Compared, never assigned.
    version: v.number(),
    // The key generation the NEW ciphertext is sealed under. Must equal the
    // environment's current one. See `STALE_PDK_VERSION`.
    pdkVersion: v.number(),
    nameCiphertext: v.string(),
    nameNonce: v.string(),
    valueCiphertext: v.string(),
    valueNonce: v.string(),
  },
  returns: v.object({
    secretId: v.id("secrets"),
    secretUid: v.string(),
    version: v.number(),
  }),
  handler: async (ctx, args) => {
    const { org, environment, secret, user } = await requireSecret(
      ctx,
      args.sessionToken,
      args.secretId,
    );
    // The new version is filed under `secret.orgId`, and the walk reached the
    // org through `secret.environmentId`, never through that column. Both
    // denormalised copies on the path must name the org membership was checked
    // against, before anything is read further or written. See `authz.ts`.
    assertOrgLink(secret.orgId, org);
    assertOrgLink(environment.orgId, org);
    // On the environment the row ALREADY belongs to, read off the row, never
    // from an argument. A grant on some other environment is not a key for
    // this one, and `updateSecret` takes no environment id precisely so that
    // the two can never disagree.
    await requirePDKGrant(ctx, secret.environmentId, user.uid);

    const { versions, current } = await historyOf(ctx, secret);

    // Deleted is checked before staleness, so a deleted secret answers with
    // the same refusal as one that was never there rather than with a message
    // that confirms it exists and describes its state.
    if (current.deletedAt !== undefined) refuse();

    // THE COMPARE-AND-SET, against the current row read in this transaction,
    // in both of the forms staleness takes. The row named is not the current
    // one: the caller opened a version somebody else has since replaced,
    // which is what a real race loser looks like. Or the stated version is
    // not current + 1. Either way the same actionable refusal, before any
    // write, so a stale caller leaves no new row and no `supersededAt`
    // behind. Convex mutations are serialisable, so two writers racing from
    // the same version cannot both pass it.
    //
    // "Is this the current row" is asked by identity against `current`, not
    // by reading `secret.supersededAt`, so it does not lean on the
    // one-live-row invariant a second time: `historyOf` has already enforced
    // it, and this is the single form `deleteSecret` uses too.
    const nextVersion = current.version + 1;
    if (secret._id !== current._id || args.version !== nextVersion) {
      throw new ConvexError(STALE_VERSION);
    }

    assertSealed(args);
    // After the shape checks and before any insert, the position
    // `tokens.createServiceToken` gives the same check.
    if (args.pdkVersion !== environment.pdkVersion) {
      throw new ConvexError(STALE_PDK_VERSION);
    }
    assertNoncesAreNew(versions, args.pdkVersion, args);

    const secretId = await insertSecret(ctx, {
      // All three read from the row being replaced. None is an argument, which
      // is what stops an update relabelling a secret into another environment,
      // another org or another secret's history.
      environmentId: secret.environmentId,
      orgId: secret.orgId,
      secretUid: secret.secretUid,
      nameCiphertext: args.nameCiphertext,
      nameNonce: args.nameNonce,
      valueCiphertext: args.valueCiphertext,
      valueNonce: args.valueNonce,
      // What the client sealed under; equal to the environment's by the check
      // above.
      pdkVersion: args.pdkVersion,
      // Equal to `args.version` by the check above: exactly what was sealed.
      version: nextVersion,
      // A new version of a shared row stays in its group and keeps its
      // override state, read off the row being replaced for the same reason
      // as the three fields above. Spread only when present, so a plain
      // secret's new version stays plain rather than gaining `undefined`s.
      ...(secret.shareUid === undefined ? {} : { shareUid: secret.shareUid }),
      ...(secret.overridden === undefined
        ? {}
        : { overridden: secret.overridden }),
    });

    await patchSecret(ctx, current._id, { supersededAt: Date.now() });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "secret.update",
      targetId: secretId,
    });

    return { secretId, secretUid: secret.secretUid, version: nextVersion };
  },
});

/**
 * Soft delete, applied to the current version, which retires the whole
 * secret: every read path below asks the secret's history whether its current
 * version is deleted, so an earlier version does not become a back door to a secret
 * somebody deleted.
 *
 * The rows stay, because the value may need to be produced later for an
 * incident or an audit, and because deleting them would leave a service token
 * holding a bundle referencing rows that no longer exist. There is deliberately
 * no undelete: restoring a secret is a decision with an audit story of its own,
 * not a flag flip, and the honest way to bring one back today is to create it.
 */
export const deleteSecret = mutation({
  args: { ...sessionArg, secretId: v.id("secrets") },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { org, secret, user } = await requireSecret(
      ctx,
      args.sessionToken,
      args.secretId,
    );
    const { current } = await historyOf(ctx, secret);

    if (current.deletedAt !== undefined) refuse();
    // Deleting through a row somebody has since replaced would delete a value
    // the caller never saw. The same refusal, and the same identity test, as
    // `updateSecret`: one answer for "you are not looking at the latest".
    if (secret._id !== current._id) throw new ConvexError(STALE_VERSION);
    // A row of a shared secret is deleted with its group or not at all.
    // Deleting it alone would leave the rest of the group labelled "All
    // environments" over an environment that no longer has the value.
    if (current.shareUid !== undefined) {
      throw new ConvexError(DELETE_SHARED_ROW);
    }

    await patchSecret(ctx, current._id, { deletedAt: Date.now() });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "secret.delete",
      targetId: current._id,
    });

    return null;
  },
});

/**
 * A SECRET FOR "ALL ENVIRONMENTS" IS ONE ROW PER ENVIRONMENT, WRITTEN AT ONCE.
 *
 * Every environment has its own project data key, and that is not negotiable:
 * it is what lets a token for staging be issued without handing it the key to
 * production. So a value shared across environments cannot be one ciphertext.
 * The client seals it N times, once per environment, each row under that
 * environment's key and its own `sec_` id, and sends all N here together with
 * one `shr_` id that links them. Each row is then an ordinary secret in every
 * respect the rest of this file cares about: its own history, its own
 * compare-and-set, its own place in its environment's bundle.
 *
 * WHAT THIS MUTATION OWNS IS THE SHAPE OF THE GROUP, AND IT OWNS IT
 * ATOMICALLY. The rows must name exactly the project's environments, each
 * once: a missing one would leave an environment silently without a secret
 * the dashboard labels "All environments", an extra one would file a row in
 * an environment the group does not belong to, and a repeated one would give
 * an environment two current values under one label. All N land in one
 * Convex transaction or none does, so there is no half-written group to
 * clean up.
 *
 * WHAT THE SERVER CANNOT CHECK. Whether the N ciphertexts hold the same
 * plaintext, or whether an `overridden: false` row really carries the shared
 * value: the server cannot open any of them, by design. A client that lies
 * here mislabels its own data and nothing more, because the `shr_` id and the
 * flag are bound into no associated data (see `shr_` in
 * `packages/crypto/src/ids.ts`). Every row is still checked, one by one, by
 * every rule `createSecret` applies, in the same order, so none of the
 * properties that DO protect a value is weaker for arriving in a group.
 */
export const createSharedSecret = mutation({
  args: {
    ...sessionArg,
    // The project whose environments the group spans. Environment ids arrive
    // per row, and each must be one of THIS project's, checked below against
    // the set read from the database rather than walked one at a time.
    projectId: v.id("projects"),
    // The group's id, `shr_` + 32 lowercase hex, minted by the client with
    // `newId("shr")`. Client-chosen, so its shape is checked and its
    // uniqueness enforced here, as for `secretUid`.
    shareUid: v.string(),
    rows: v.array(
      v.object({
        environmentId: v.id("environments"),
        // Exactly the fields `createSecret` takes for one row, with the same
        // meaning and the same checks.
        secretUid: v.string(),
        version: v.number(),
        pdkVersion: v.number(),
        // True when this environment keeps its own value instead of the
        // shared one. Labelling only; see the header above.
        overridden: v.boolean(),
        nameCiphertext: v.string(),
        nameNonce: v.string(),
        valueCiphertext: v.string(),
        valueNonce: v.string(),
      }),
    ),
  },
  returns: v.array(
    v.object({
      secretId: v.id("secrets"),
      secretUid: v.string(),
      environmentId: v.id("environments"),
    }),
  ),
  handler: async (ctx, args) => {
    const { org, project, user } = await requireProject(
      ctx,
      args.sessionToken,
      args.projectId,
    );

    // THE SET CHECK, against the environments read in this transaction. An
    // environment from another project, another org, or one that does not
    // exist is simply not in this set, so it fails here with the same
    // sentence as a missing one, and without a per-row lookup that could
    // answer differently for "exists elsewhere" and "does not exist".
    const environments = await listEnvironmentsByProject(ctx, project._id);
    const byId = new Map(environments.map((env) => [env._id, env]));
    const named = new Set(args.rows.map((row) => row.environmentId));
    if (
      args.rows.length !== environments.length ||
      named.size !== args.rows.length ||
      args.rows.some((row) => !byId.has(row.environmentId))
    ) {
      throw new ConvexError(SHARED_ROWS_MISMATCH);
    }
    const pairs = args.rows.map((row) => ({
      row,
      environment: byId.get(row.environmentId) as Doc<"environments">,
    }));

    // Then, per environment, what `createSecret` checks before anything else:
    // the org copy each row will be filed under is the walked org, and the
    // caller holds a key for this environment, so nothing is sealed under a
    // key nobody holds. A caller missing a grant on ANY environment cannot
    // write the group at all, because the alternative is a group with a hole
    // in it.
    for (const { environment } of pairs) {
      assertOrgLink(environment.orgId, org);
      await requirePDKGrant(ctx, environment._id, user.uid);
    }

    // Shape checks, per row, in `createSecret`'s order.
    const shareUid = requireId("shr", "shareUid", args.shareUid);
    for (const { row, environment } of pairs) {
      requireId("sec", "secretUid", row.secretUid);
      if (row.version !== INITIAL_SECRET_VERSION) {
        throw new ConvexError(NEW_SECRET_VERSION);
      }
      assertSealed(row);
      if (row.pdkVersion !== environment.pdkVersion) {
        throw new ConvexError(STALE_PDK_VERSION);
      }
    }

    if (args.rows.every((row) => row.overridden)) {
      throw new ConvexError(SHARED_NEEDS_SHARED_ROW);
    }

    // Uniqueness. Within the call first, because `secretUidTaken` cannot see
    // a row this transaction has not inserted yet, and two rows of one group
    // sharing a `sec_` id would be one lineage spanning two environments:
    // exactly what `historyOf` treats as corruption. Then deployment wide,
    // for the reason given above `DUPLICATE_SECRET_UID`.
    const uids = new Set(args.rows.map((row) => row.secretUid));
    if (uids.size !== args.rows.length) {
      throw new ConvexError(DUPLICATE_SECRET_UID);
    }
    for (const uid of uids) {
      if (await secretUidTaken(ctx, uid)) {
        throw new ConvexError(DUPLICATE_SECRET_UID);
      }
    }
    if (await shareUidTaken(ctx, shareUid)) {
      throw new ConvexError(DUPLICATE_SHARE_UID);
    }

    const created: Array<{
      secretId: Id<"secrets">;
      secretUid: string;
      environmentId: Id<"environments">;
    }> = [];
    for (const { row, environment } of pairs) {
      const secretId = await insertSecret(ctx, {
        environmentId: environment._id,
        // Off the environment row read above and checked against the walked
        // org. There is no orgId argument.
        orgId: environment.orgId,
        secretUid: row.secretUid,
        nameCiphertext: row.nameCiphertext,
        nameNonce: row.nameNonce,
        valueCiphertext: row.valueCiphertext,
        valueNonce: row.valueNonce,
        pdkVersion: row.pdkVersion,
        version: INITIAL_SECRET_VERSION,
        shareUid,
        overridden: row.overridden,
      });
      // One event per row, the same event `createSecret` writes, so "what was
      // created in this environment" answers the same way however it was
      // created.
      await recordUserEvent(ctx, {
        orgId: org._id,
        actorId: user._id,
        action: "secret.create",
        targetId: secretId,
      });
      created.push({
        secretId,
        secretUid: row.secretUid,
        environmentId: environment._id,
      });
    }
    return created;
  },
});

/**
 * Soft-deletes every current row of one shared secret, in every environment,
 * in one transaction: the group's counterpart to `deleteSecret`, with the
 * same retention reasoning.
 *
 * Addressed by project and share id. The project is what the authorisation
 * walk starts from; the share id is then only a label, so every row it finds
 * must belong to one of that project's environments, or the call is refused
 * with the shared not-found sentence. A share id copied from another project
 * therefore deletes nothing and confirms nothing.
 */
export const deleteSharedSecret = mutation({
  args: {
    ...sessionArg,
    projectId: v.id("projects"),
    shareUid: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { org, project, user } = await requireProject(
      ctx,
      args.sessionToken,
      args.projectId,
    );

    const rows = await listCurrentByShareUid(ctx, args.shareUid);
    if (rows.length === 0) refuse();
    const environments = await listEnvironmentsByProject(ctx, project._id);
    const inProject = new Set(environments.map((env) => env._id));
    if (rows.some((row) => !inProject.has(row.environmentId))) refuse();

    // No grant check, deliberately, as in `deleteSecret`: a delete seals
    // nothing, so there is no key a missing grant would make it write under.
    // Membership, checked by `requireProject`, is the authorisation.
    const now = Date.now();
    for (const row of rows) {
      await patchSecret(ctx, row._id, { deletedAt: now });
      await recordUserEvent(ctx, {
        orgId: org._id,
        actorId: user._id,
        action: "secret.delete",
        targetId: row._id,
      });
    }
    return null;
  },
});

export const getSecret = query({
  args: { ...sessionArg, secretId: v.id("secrets") },
  returns: v.object(secretShape),
  handler: async (ctx, args) => {
    const { secret } = await requireSecret(ctx, args.sessionToken, args.secretId);
    // A superseded version is readable. A version of a DELETED secret is not,
    // whichever version was asked for.
    const { current } = await historyOf(ctx, secret);
    if (current.deletedAt !== undefined) refuse();
    return view(secret);
  },
});

/**
 * The current, live secrets of one environment. A single indexed read on
 * `by_environment_current`, with both exclusions as index equalities rather
 * than as a filter applied afterwards, because this is the dashboard load and
 * the bundle fetch.
 */
export const listSecrets = query({
  args: { ...sessionArg, environmentId: v.id("environments") },
  returns: v.array(v.object(secretShape)),
  handler: async (ctx, args) => {
    const { environment } = await requireEnvironment(
      ctx,
      args.sessionToken,
      args.environmentId,
    );
    const secrets = await listCurrentSecretsByEnvironment(ctx, environment._id);
    return secrets.map(view);
  },
});

/**
 * Every version of one logical secret, oldest first, addressed by any one of
 * its rows, each carrying the `secretUid` and `version` it was sealed under.
 *
 * It is addressed by a row id rather than by `secretUid` on purpose. The
 * authorisation walk (`requireSecret`) starts from a row, so a row id is what
 * proves the caller may read this history at all; a lookup by uid would need
 * its own walk, and the uid is a label anybody holding a bundle can see.
 */
export const listSecretVersions = query({
  args: { ...sessionArg, secretId: v.id("secrets") },
  returns: v.array(v.object(secretShape)),
  handler: async (ctx, args) => {
    const { secret } = await requireSecret(ctx, args.sessionToken, args.secretId);
    const { versions, current } = await historyOf(ctx, secret);
    if (current.deletedAt !== undefined) refuse();
    return versions.map(view);
  },
});
