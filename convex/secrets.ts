import { ConvexError, v } from "convex/values";
import { randomBytes, toHex } from "@sluice/crypto";
import { mutation, query } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import type { MutationCtx, QueryCtx } from "./_generated/server";
import { recordUserEvent } from "./lib/audit";
import {
  callerArg,
  NOT_PERMITTED,
  requireEnvironment,
  requireSecret,
} from "./lib/authz";
import { assertHexAtLeast, assertHexBytes } from "./lib/hex";
import {
  insertSecret,
  listCurrentSecretsByEnvironment,
  listSecretVersions as listVersionsByLineage,
  patchSecret,
} from "./repo/secrets";

/**
 * THE SERVER STORES CIPHERTEXT AND NOTHING ELSE.
 *
 * Both the name and the value of every secret arrive sealed and leave sealed.
 * Nothing in this file decrypts, and nothing in this file can: the project
 * data key never reaches the server. The associated data rule that binds each
 * ciphertext to its environment and to the algorithm version is written out in
 * full in `lib/aad.ts`, which is the file a client author should read.
 *
 * The two server-side halves of that rule live here:
 *
 *   1. An environment id is accepted only when a row is CREATED. No mutation
 *      accepts one for a row that already exists, so a secret cannot be moved
 *      between environments through this API and its associated data can never
 *      disagree with the column it is bound to.
 *   2. `pdkVersion` is copied from the environment rather than accepted from
 *      the caller, so a row cannot claim a key version that never existed.
 */

// AES-GCM appends a 16 byte tag to every ciphertext, so nothing shorter than
// 16 bytes can be output this product produced. An empty string stored as
// ciphertext lists and syncs perfectly and fails only on the day someone tries
// to read it.
const MIN_CIPHERTEXT_BYTES = 16;
const NONCE_BYTES = 12;

/**
 * WHERE LINEAGE IDS COME FROM, AND WHY IT IS THIS.
 *
 * `secrets.lineageId` is a plain string in the schema and every version of one
 * logical secret shares it, so two unrelated secrets carrying the same value
 * would silently merge their histories: one would appear as a version of the
 * other, an old value would be offered as the current one, and the listing
 * would lose a row. Nothing in the schema prevents it, so it is prevented
 * here.
 *
 * THE DECISION: the server mints it, from 16 bytes of `randomBytes` in
 * `@sluice/crypto`, hex encoded, and NO function in this file accepts a
 * lineage id as an argument.
 *
 * Minting on the server rather than on the client is the part that matters,
 * and it is not the obvious choice, so here is the reasoning. A client-minted
 * id would be an argument, and an argument can name an EXISTING lineage,
 * including one in an environment the caller can write to but whose history
 * they should not be able to rewrite. That turns "create a secret" into "add a
 * version to that secret", which is a silent overwrite of the current value
 * with no update path having been called and no version check having run.
 * Randomness on the client does not help, because the attack is not a
 * collision, it is a deliberate choice. Making it unaddressable is the only
 * defence that does not depend on the client behaving.
 *
 * 16 bytes rather than 32 because this is a grouping key and not a
 * capability: it is returned to any member of the org, so its secrecy buys
 * nothing, and 128 bits of collision resistance is already far beyond the
 * number of secrets that will ever exist. The uniqueness check below is what
 * makes it an invariant rather than a probability argument.
 */
const LINEAGE_ID_BYTES = 16;

const ALREADY_REPLACED = "This version of the secret has already been replaced.";

/**
 * Two versions of one lineage claiming to be current, or one lineage spanning
 * two environments, is corruption rather than a state a caller can reach. It
 * says so instead of picking one, because picking one is exactly how a merged
 * history becomes invisible.
 */
const INCONSISTENT = "This secret's version history is inconsistent.";

function refuse(): never {
  throw new ConvexError(NOT_PERMITTED);
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
 * The same rule across a lineage: a new version sealed under the same key
 * version must not repeat a nonce an earlier version used.
 *
 * This is NOT a complete nonce-reuse detector and must not be mistaken for
 * one. It cannot see reuse across two different lineages, and widening it to
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

async function mintLineageId(ctx: MutationCtx): Promise<string> {
  const lineageId = toHex(randomBytes(LINEAGE_ID_BYTES));
  // The assertion that makes uniqueness an invariant instead of an argument
  // about birthdays. It is one indexed read, it will never fire, and the day
  // it does the alternative was a silently merged history.
  if ((await listVersionsByLineage(ctx, lineageId)).length > 0) {
    throw new ConvexError("Could not allocate a secret lineage. Try again.");
  }
  return lineageId;
}

/**
 * Every version of the lineage this row belongs to, oldest first, plus the one
 * current version.
 *
 * The environment check is the guard against a lineage that spans two
 * environments. It cannot happen through this API, because a lineage id is
 * never an argument and an environment id is only ever read from the row being
 * superseded, but this is the read path that would quietly serve the result if
 * it ever did.
 */
async function lineageOf(
  ctx: QueryCtx,
  secret: Doc<"secrets">,
): Promise<{ versions: Doc<"secrets">[]; current: Doc<"secrets"> }> {
  const versions = await listVersionsByLineage(ctx, secret.lineageId);
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
  lineageId: v.string(),
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
    lineageId: secret.lineageId,
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
    ...callerArg,
    // The only place an environment id is ever accepted. After this, a row's
    // environment is read from the row and never from a caller.
    environmentId: v.id("environments"),
    nameCiphertext: v.string(),
    nameNonce: v.string(),
    valueCiphertext: v.string(),
    valueNonce: v.string(),
  },
  returns: v.object({
    secretId: v.id("secrets"),
    lineageId: v.string(),
    version: v.number(),
  }),
  handler: async (ctx, args) => {
    const { org, environment, user } = await requireEnvironment(
      ctx,
      args.callerId,
      args.environmentId,
    );
    assertSealed(args);

    const lineageId = await mintLineageId(ctx);
    const secretId = await insertSecret(ctx, {
      environmentId: environment._id,
      lineageId,
      nameCiphertext: args.nameCiphertext,
      nameNonce: args.nameNonce,
      valueCiphertext: args.valueCiphertext,
      valueNonce: args.valueNonce,
      // From the environment, never from the caller. See the header.
      pdkVersion: environment.pdkVersion,
      version: 1,
    });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "secret.create",
      targetId: secretId,
    });

    return { secretId, lineageId, version: 1 };
  },
});

/**
 * An update is an insert. The previous row is marked superseded and keeps its
 * ciphertext exactly as it was, because a version history that rewrites rows
 * is not a history.
 */
export const updateSecret = mutation({
  args: {
    ...callerArg,
    secretId: v.id("secrets"),
    nameCiphertext: v.string(),
    nameNonce: v.string(),
    valueCiphertext: v.string(),
    valueNonce: v.string(),
  },
  returns: v.object({
    secretId: v.id("secrets"),
    lineageId: v.string(),
    version: v.number(),
  }),
  handler: async (ctx, args) => {
    const { org, environment, secret, user } = await requireSecret(
      ctx,
      args.callerId,
      args.secretId,
    );
    const { versions, current } = await lineageOf(ctx, secret);

    // Deleted is checked before superseded, so a deleted secret answers with
    // the same refusal as one that was never there rather than with a message
    // that confirms it exists and describes its state.
    if (current.deletedAt !== undefined) refuse();
    if (secret.supersededAt !== undefined) {
      throw new ConvexError(ALREADY_REPLACED);
    }

    assertSealed(args);
    assertNoncesAreNew(versions, environment.pdkVersion, args);

    const secretId = await insertSecret(ctx, {
      // Both read from the row being replaced. Neither is an argument, which
      // is what stops an update relabelling a secret into another environment
      // or another lineage.
      environmentId: secret.environmentId,
      lineageId: secret.lineageId,
      nameCiphertext: args.nameCiphertext,
      nameNonce: args.nameNonce,
      valueCiphertext: args.valueCiphertext,
      valueNonce: args.valueNonce,
      pdkVersion: environment.pdkVersion,
      version: current.version + 1,
    });

    await patchSecret(ctx, current._id, { supersededAt: Date.now() });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "secret.update",
      targetId: secretId,
    });

    return { secretId, lineageId: secret.lineageId, version: current.version + 1 };
  },
});

/**
 * Soft delete, applied to the current version, which retires the whole
 * lineage: every read path below asks the lineage whether its current version
 * is deleted, so an earlier version does not become a back door to a secret
 * somebody deleted.
 *
 * The rows stay, because the value may need to be produced later for an
 * incident or an audit, and because deleting them would leave a service token
 * holding a bundle referencing rows that no longer exist. There is deliberately
 * no undelete: restoring a secret is a decision with an audit story of its own,
 * not a flag flip, and the honest way to bring one back today is to create it.
 */
export const deleteSecret = mutation({
  args: { ...callerArg, secretId: v.id("secrets") },
  returns: v.null(),
  handler: async (ctx, args) => {
    const { org, secret, user } = await requireSecret(
      ctx,
      args.callerId,
      args.secretId,
    );
    const { current } = await lineageOf(ctx, secret);

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
  args: { ...callerArg, secretId: v.id("secrets") },
  returns: v.object(secretShape),
  handler: async (ctx, args) => {
    const { secret } = await requireSecret(ctx, args.callerId, args.secretId);
    // A superseded version is readable. A version of a DELETED lineage is not,
    // whichever version was asked for.
    const { current } = await lineageOf(ctx, secret);
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
  args: { ...callerArg, environmentId: v.id("environments") },
  returns: v.array(v.object(secretShape)),
  handler: async (ctx, args) => {
    const { environment } = await requireEnvironment(
      ctx,
      args.callerId,
      args.environmentId,
    );
    const secrets = await listCurrentSecretsByEnvironment(ctx, environment._id);
    return secrets.map(view);
  },
});

/**
 * Every version of one logical secret, oldest first, addressed by any one of
 * its rows. It does not take a lineage id, because a lineage id is not a thing
 * a caller is allowed to name: see the note above `LINEAGE_ID_BYTES`.
 */
export const listSecretVersions = query({
  args: { ...callerArg, secretId: v.id("secrets") },
  returns: v.array(v.object(secretShape)),
  handler: async (ctx, args) => {
    const { secret } = await requireSecret(ctx, args.callerId, args.secretId);
    const { versions, current } = await lineageOf(ctx, secret);
    if (current.deletedAt !== undefined) refuse();
    return versions.map(view);
  },
});
