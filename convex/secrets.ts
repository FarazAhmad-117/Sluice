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
  requireSecret,
} from "./lib/authz";
import { assertHexAtLeast, assertHexBytes } from "./lib/hex";
import { requireId } from "./lib/ids";
import { getPDKGrant } from "./repo/environments";
import {
  insertSecret,
  listCurrentSecretsByEnvironment,
  listSecretVersions as listVersionsBySecretUid,
  patchSecret,
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
 *   2. `pdkVersion` is copied from the environment rather than accepted from
 *      the caller, so a row cannot claim a key version that never existed.
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
 */
const STALE_VERSION =
  "This secret changed since you opened it. Reload to see the latest version.";

const ALREADY_REPLACED = "This version of the secret has already been replaced.";

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
 * copied off the environment so it claims a real key version, the listing shows
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

    // Deployment wide, and any row at all, superseded or deleted included: an
    // id that ever named a secret names that secret for ever, and reusing it
    // is how a create becomes an overwrite of somebody else's history.
    if ((await listVersionsBySecretUid(ctx, secretUid)).length > 0) {
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
      // From the environment, never from the caller. See the header.
      pdkVersion: environment.pdkVersion,
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

    // Deleted is checked before superseded, so a deleted secret answers with
    // the same refusal as one that was never there rather than with a message
    // that confirms it exists and describes its state.
    if (current.deletedAt !== undefined) refuse();
    if (secret.supersededAt !== undefined) {
      throw new ConvexError(ALREADY_REPLACED);
    }

    // THE COMPARE-AND-SET, against the current row read in this transaction.
    // Before any write, so a stale caller leaves no new row and no
    // `supersededAt` behind. Convex mutations are serialisable, so two writers
    // racing from the same version cannot both pass it.
    const nextVersion = current.version + 1;
    if (args.version !== nextVersion) {
      throw new ConvexError(STALE_VERSION);
    }

    assertSealed(args);
    assertNoncesAreNew(versions, environment.pdkVersion, args);

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
      pdkVersion: environment.pdkVersion,
      // Equal to `args.version` by the check above: exactly what was sealed.
      version: nextVersion,
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
    if (secret._id !== current._id) throw new ConvexError(ALREADY_REPLACED);

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
