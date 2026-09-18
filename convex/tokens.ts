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
import { getPDKGrant, insertPDKGrant } from "./repo/environments";
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

/**
 * MEMBERSHIP AUTHORISES A REGISTRATION. A GRANT IS WHAT MAKES ONE MEANINGFUL,
 * AND BOTH MUST HOLD.
 *
 * `requireEnvironment` proves the caller is in the org. It proves nothing about
 * whether they hold the environment's project data key, and a member who does
 * not hold it cannot produce a real `wrappedPDK`: whatever they send is a wrap
 * of something else, or of nothing. The row lands, `pdkVersion` is copied off
 * the environment so it claims a real key version, the bundle ships it to the
 * workload, and the whole thing fails exactly once -- as a bare AEAD rejection
 * at boot, with no indication of which input was wrong, in production and
 * possibly months later.
 *
 * It is not hypothetical. Every SECOND member of an org is in this state today,
 * because nothing wraps an existing project data key to a new member:
 * `createEnvironment` mints exactly one grant and it belongs to its creator.
 *
 * THE SERVER CANNOT FIX IT, ONLY REFUSE IT. Minting the missing grant here is
 * the tempting repair and it is impossible: this deployment has never held the
 * plaintext project data key and never will, so any grant it wrote would be a
 * row whose ciphertext is not a key.
 *
 * THE SENTENCE IS VERBATIM THE ONE `secrets.ts` USES, deliberately. It is one
 * rule -- "you hold no key for this environment" -- and one rule with two
 * spellings is the drift `@sluice/crypto/protocol.ts` exists to delete. It is
 * repeated rather than imported because `secrets.ts` keeps it private and this
 * change does not own that file; hoisting both into `lib/authz.ts` is the right
 * follow-up and is a change to a file this one must not edit. The message stays
 * distinct from `NOT_PERMITTED` for the reason `secrets.ts` gives: the caller
 * has already passed `requireEnvironment`, so the only fact disclosed is one
 * about their own grant, which they can establish by asking about themselves.
 */
const NO_GRANT =
  "You hold no key for this environment, so nothing you wrote here could ever be read.";

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

    // Before any validation and before the token id is hashed, so a caller with
    // no key cannot learn anything from the order in which their arguments were
    // rejected, and cannot probe which token ids are already taken. Same
    // position, for the same reason, as in `secrets.createSecret`.
    //
    // `granteeType` is pinned to `"user"`: this is the CALLER'S grant, and the
    // caller is a person. A `tokenIdHash` and a `users` id are both opaque
    // strings in one index, and the type column is all that separates them.
    if ((await getPDKGrant(ctx, environment._id, "user", user._id)) === null) {
      throw new ConvexError(NO_GRANT);
    }

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
      // From the environment, never from the caller. This is the token's
      // REVOCATION epoch floor, and it is not the project data key version:
      // that lives on the grant below, where the wrapped blob it describes
      // lives too.
      epoch: environment.epoch,
      status: "active",
      ...(args.expiresAt === undefined ? {} : { expiresAt: args.expiresAt }),
    });

    // THE GRANT IS WRITTEN HERE, IN THIS MUTATION, for the same reason
    // `createOrg` writes its revocation grant in one transaction: a token
    // registered without one is a token that can never open a secret, with no
    // error at any point until a workload starts and cannot decrypt.
    //
    // THE GRANTEE IS THE HASH, NOT `serviceTokenId`. The bundle knows an
    // authenticated token only by its hash, and the client had to compute the
    // same identifier to build the associated data it wrapped under, before
    // this document existed. A document id satisfies neither.
    await insertPDKGrant(ctx, {
      environmentId: environment._id,
      granteeType: "token",
      granteeId: hash,
      wrappedPDK: args.wrappedPDK,
      nonce: args.pdkNonce,
      // Off the environment row, exactly as `secrets.ts` copies it. A re-key
      // must bump `environments.pdkVersion` and re-wrap every grant in the one
      // mutation, or a token is handed a key the stored ciphertext is not
      // under.
      pdkVersion: environment.pdkVersion,
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
