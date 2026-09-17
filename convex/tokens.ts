import { ConvexError, v } from "convex/values";
import {
  fromHex,
  tokenIdHash,
  verifyRevocation,
} from "@sluice/crypto";
import { mutation } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { recordUserEvent } from "./lib/audit";
import { sessionArg, NOT_PERMITTED, requireEnvironment, requireSession } from "./lib/authz";
import { assertHexAtLeast, assertHexBytes } from "./lib/hex";
import {
  getServiceTokenByIdHash,
  insertRevocation,
  insertServiceToken,
  listRevocationsByTokenIdHash,
  patchServiceToken,
} from "./repo/tokens";

/**
 * THE TWO WRITE SITES FOR `tokenIdHash`, IN ONE FILE, ON PURPOSE.
 *
 * `serviceTokens.tokenIdHash` is written when a token is registered and
 * `revocations.tokenIdHash` when it is revoked, and the bundle subscription
 * joins the two on equality. If the two ever disagree, NOTHING THROWS: the join
 * returns an empty list, the notice never reaches the bundle, the revoked token
 * keeps working, and every test that seeds both rows by hand still passes,
 * because a hand-seeded fixture agrees with itself.
 *
 * Both sites below call `tokenIdHash` from `@sluice/crypto`. Neither computes
 * a digest of its own, and there is no second place in this codebase that
 * writes either column. Keeping them adjacent is not tidiness: a reviewer has
 * to be able to see both constructions at once to know they are the same one.
 *
 * WHY `revocations` STORES BOTH FORMS. The plaintext id is what the notice is
 * SIGNED over, so hashing it would break `verifyRevocation` in every SDK. The
 * hash is what the bundle can reach, because an authenticated token is known to
 * this server only by its hash. Do not "clean up" the duplication.
 */

// The token id `mintToken` produces, and the width `tokenIdHash` enforces.
const TOKEN_ID_BYTES = 16;
// Ed25519.
const PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
// AES-GCM, 96 bits, the only width `@sluice/crypto` produces.
const NONCE_BYTES = 12;
// AES-GCM appends a 16 byte tag, so nothing shorter can be output this product
// produced. See the identical rule in `secrets.ts`.
const MIN_CIPHERTEXT_BYTES = 16;

const DUPLICATE_TOKEN = "A service token with that id already exists.";

/**
 * The refusal when the presented notice is not signed by the organisation's
 * revocation key.
 *
 * The server verifies this even though it can neither produce nor forge the
 * signature and even though the SDK verifies it again. Storing a notice no SDK
 * would ever honour is the worst possible outcome of a revocation: the console
 * says the token is revoked, `serviceTokens.status` says revoked, the bundle
 * ships the notice, and every process ignores it. That is a kill switch that
 * reports success and does nothing, discovered during the incident it exists
 * for.
 */
const NOT_SIGNED =
  "This revocation notice is not signed by the organisation's revocation key.";

/**
 * Epochs are globally monotonic per token id and must never reset. The SDK's
 * whole replay defence is a floor on the highest epoch it has acted on, so a
 * notice at or below an epoch already issued is one an updated SDK will
 * correctly ignore. Refusing to store it here is what stops an operator
 * believing a revocation took effect when no conforming SDK will act on it.
 */
const EPOCH_NOT_MONOTONIC =
  "This token has already been revoked at that epoch or a later one.";

function refuse(): never {
  throw new ConvexError(NOT_PERMITTED);
}

function assertNonNegativeSafeInteger(field: string, value: number): number {
  // `Object.is(value, -0)` is the clause that looks pedantic and is not:
  // `-0 < 0` is false and `Number.isSafeInteger(-0)` is true, and `String(-0)`
  // is `"0"`, so a `-0` epoch would sign the same bytes as `0` while comparing
  // as a different value. `@sluice/crypto` rejects it on the signing path for
  // exactly this reason; this keeps the two ends agreeing.
  if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
    throw new ConvexError(`${field} must be a non-negative safe integer.`);
  }
  return value;
}

export const createServiceToken = mutation({
  args: {
    ...sessionArg,
    environmentId: v.id("environments"),
    // The PLAINTEXT id, which the server hashes and does not keep. It arrives
    // once, here, because the client just minted it and the server cannot
    // derive it from anything it stores.
    tokenId: v.string(),
    publicKey: v.string(),
    // The project data key, wrapped to this token's unwrap key. The server
    // cannot open it and must never be able to: the unwrap key is derived on
    // the client from the token secret and never transmitted.
    wrappedPDK: v.string(),
    pdkNonce: v.string(),
    expiresAt: v.optional(v.number()),
  },
  returns: v.id("serviceTokens"),
  handler: async (ctx, args): Promise<Id<"serviceTokens">> => {
    const { org, environment, user } = await requireEnvironment(
      ctx,
      args.sessionToken,
      args.environmentId,
    );

    assertHexBytes("tokenId", args.tokenId, TOKEN_ID_BYTES);
    assertHexBytes("publicKey", args.publicKey, PUBLIC_KEY_BYTES);
    assertHexBytes("pdkNonce", args.pdkNonce, NONCE_BYTES);
    assertHexAtLeast("wrappedPDK", args.wrappedPDK, MIN_CIPHERTEXT_BYTES);
    if (args.expiresAt !== undefined) {
      assertNonNegativeSafeInteger("expiresAt", args.expiresAt);
    }

    // THE HASH, FROM THE SHARED PACKAGE. See the header.
    const hash = tokenIdHash({ tokenId: fromHex(args.tokenId) });

    // `by_token_id_hash` is read with `.unique()` on the handshake path, so a
    // second row under one hash would not merely be wrong, it would make the
    // lookup THROW and take the token offline. Convex mutations are
    // serialisable transactions, so read-then-insert here is not a race.
    if ((await getServiceTokenByIdHash(ctx, hash)) !== null) {
      throw new ConvexError(DUPLICATE_TOKEN);
    }

    const serviceTokenId = await insertServiceToken(ctx, {
      environmentId: environment._id,
      tokenIdHash: hash,
      publicKey: args.publicKey,
      wrappedPDK: args.wrappedPDK,
      nonce: args.pdkNonce,
      // From the environment, never from the caller, exactly as `secrets.ts`
      // copies `pdkVersion`. This records WHICH project data key the wrapped
      // blob above opens. A re-key must bump this and re-wrap in the same
      // mutation that bumps `environments.epoch`, or a token is handed a
      // wrapped key for a version the stored ciphertext is no longer under.
      epoch: environment.epoch,
      status: "active",
      ...(args.expiresAt === undefined ? {} : { expiresAt: args.expiresAt }),
    });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "token.create",
      targetId: serviceTokenId,
    });

    // The plaintext token id is NOT returned and NOT stored. The client already
    // has it; echoing it would put it in one more response body and one more
    // log.
    return serviceTokenId;
  },
});

/**
 * Records a signed revocation notice and marks the token dead.
 *
 * The signature is produced in the admin's browser by the organisation's
 * revocation key, which this server has never held: `orgs` stores only the
 * public half and `revocationGrants` stores the private half wrapped to each
 * signer's master unlock key. That is what stops a compromised Sluice
 * deployment from mass-killing customer fleets, and it is why this mutation
 * takes a signature rather than producing one.
 */
export const revokeServiceToken = mutation({
  args: {
    ...sessionArg,
    tokenId: v.string(),
    epoch: v.number(),
    revokedAt: v.number(),
    reason: v.string(),
    signature: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    // AUTHENTICATION STRICTLY BEFORE ANY LOOKUP. `authz.ts` explains at length
    // why: with two refusal strings, an attacker with no session at all would
    // otherwise get one message for a token id that exists and another for one
    // that does not, which is a row enumeration oracle built out of the pair.
    await requireSession(ctx, args.sessionToken);

    assertHexBytes("tokenId", args.tokenId, TOKEN_ID_BYTES);
    assertHexBytes("signature", args.signature, SIGNATURE_BYTES);
    assertNonNegativeSafeInteger("epoch", args.epoch);
    assertNonNegativeSafeInteger("revokedAt", args.revokedAt);

    // THE HASH, FROM THE SHARED PACKAGE, AT THE SECOND WRITE SITE.
    const hash = tokenIdHash({ tokenId: fromHex(args.tokenId) });

    const token = await getServiceTokenByIdHash(ctx, hash);
    if (token === null) refuse();

    const { org, user } = await requireEnvironment(
      ctx,
      args.sessionToken,
      token.environmentId,
    );

    // The notice as the SDK will see it, verified against the same public key
    // the customer pinned in their own configuration. `reason` is signed, so
    // it cannot be edited afterwards: whatever is stored is what was signed.
    //
    // A REMINDER THAT BELONGS AT THIS CALL SITE: `reason` is broadcast to every
    // live subscription for this token and lands in every customer's logs. It
    // must never carry secret-derived text. Nothing here can check that, which
    // is exactly why it is written down where an operator's text arrives.
    const notice = {
      tokenId: args.tokenId,
      epoch: args.epoch,
      revokedAt: args.revokedAt,
      reason: args.reason,
    };
    if (
      !verifyRevocation(
        org.revocationPublicKey,
        notice,
        fromHex(args.signature),
      )
    ) {
      throw new ConvexError(NOT_SIGNED);
    }

    // Read through the hash, not the plaintext id, so this check and the bundle
    // join agree by construction rather than by coincidence.
    const existing = await listRevocationsByTokenIdHash(ctx, hash);
    if (existing.some((row) => row.epoch >= args.epoch)) {
      throw new ConvexError(EPOCH_NOT_MONOTONIC);
    }

    const revocationId = await insertRevocation(ctx, {
      tokenId: args.tokenId,
      tokenIdHash: hash,
      epoch: args.epoch,
      signature: args.signature,
      signedBy: user._id,
      revokedAt: args.revokedAt,
      reason: args.reason,
    });

    // Belt and braces, and the two do different jobs. The status stops the
    // token getting a NEW bundle token from the handshake; the `revocations`
    // row is what reaches the processes already running. Neither replaces the
    // other, and they land in one transaction so no state exists where a token
    // is revoked by one measure and live by the other.
    await patchServiceToken(ctx, token._id, { status: "revoked" });

    await recordUserEvent(ctx, {
      orgId: org._id,
      actorId: user._id,
      action: "token.revoke",
      targetId: revocationId,
    });

    return null;
  },
});
