import { v } from "convex/values";
import { fromHex, tokenIdHash, verifyHandshake } from "@sluice/crypto";
import { internalMutation } from "./_generated/server";
import { recordTokenEvent } from "./lib/audit";
import {
  HANDSHAKE_NONCE_LIFETIME_MS,
  handshakeSignatureHash,
} from "./lib/handshake";
import {
  BUNDLE_TOKEN_LIFETIME_MS,
  assertBundleSigningKey,
  signBundleToken,
} from "./lib/jwt";
import { getEnvironment } from "./repo/environments";
import { getProject } from "./repo/projects";
import {
  getHandshakeNonce,
  getServiceTokenByIdHash,
  insertHandshakeNonce,
  patchServiceToken,
} from "./repo/tokens";

/**
 * THE HANDSHAKE, AS ONE TRANSACTION. `http.ts` IS THE DOOR; THIS IS THE LOCK.
 *
 * The timestamp window is checked in `http.ts`, before this runs and before any
 * cryptography, so an attacker cannot make this deployment do Ed25519 work by
 * sending nonsense. Everything that needs the database is here, and it is ALL
 * here, in one mutation, which is the part that is not a stylistic choice:
 *
 *   THE REPLAY CHECK MUST BE ONE MUTATION THAT INSERTS AND FAILS ON CONFLICT.
 *   Split across two calls it is a time-of-check-to-time-of-use race: two
 *   concurrent presentations of the identical signature both read "absent",
 *   both then insert, and both succeed. That is not a theoretical ordering, it
 *   is precisely the attack `handshakeNonces` exists to stop, and it is the one
 *   this table would appear to be defending against while doing nothing.
 *   Convex mutations are serialisable transactions, so read-then-insert INSIDE
 *   one of them is atomic. Across two of them it is not.
 *
 * The checks run in this order and the order is load bearing:
 *
 *   1. (in `http.ts`) the timestamp is a non-negative safe integer inside the
 *      acceptance window. Before any curve operation.
 *   2. the signature verifies against the stored public key.
 *   3. the signature has not been seen before.
 *   4. the token is active and not past its expiry.
 *
 * Three cannot come before two, because an unverified signature is attacker
 * chosen and letting it write a row would let anyone fill this table. Four
 * cannot come before three for a subtler reason: it would answer "is this token
 * revoked" for any signature an attacker had ever OBSERVED, without that
 * attacker holding the token secret, which is a free liveness oracle over the
 * fleet. Behind the replay check, a captured signature buys exactly one
 * answer, and it has already been spent.
 */

/**
 * A fixed, valid Ed25519 public key, used ONLY to make an unknown token id cost
 * the same as a known one.
 *
 * WHAT THIS CLOSES. Without it, an unknown token id skips verification entirely
 * and answers in an index miss, while a known token id with a bad signature
 * pays a full Ed25519 verification first. The two refusals are byte identical
 * and the difference is still perfectly measurable from outside, which turns
 * "the error messages reveal nothing" into a statement about the strings and
 * not about the endpoint. An attacker with a list of candidate token ids could
 * sort it into "registered" and "not" without holding a single secret.
 *
 * It is the public key of the all-zero Ed25519 seed, so it is a genuine curve
 * point that `verify` decompresses and does real work against, rather than a
 * malformed value that would be rejected early and restore the very timing
 * difference this removes. Its private half is public knowledge and that is
 * fine: the result of this verification is DISCARDED. Nothing is ever
 * authenticated against this key, and the branch that uses it always refuses.
 */
const DECOY_PUBLIC_KEY =
  "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

/**
 * Every refusal is this value, whatever the cause.
 *
 * The caller learns that the handshake failed and nothing else: not whether the
 * token id exists, not whether it was the signature, not whether the token was
 * revoked, not whether this exact request had already been used. A revoked
 * token in particular must NOT be told it is revoked here, because the signed
 * revocation notice travels through the bundle where the SDK can verify it, and
 * an unsigned hint from this endpoint is something a compromised server could
 * fabricate.
 */
const REFUSED = { ok: false } as const;

export const completeHandshake = internalMutation({
  args: {
    // Shapes are validated in `http.ts`, which is this function's only caller.
    // `tokenId` is 32 lowercase hex characters and `signature` is 128, so the
    // `fromHex` calls below cannot throw.
    tokenId: v.string(),
    unixSeconds: v.number(),
    signature: v.string(),
  },
  returns: v.union(
    v.object({
      ok: v.literal(true),
      token: v.string(),
      expiresAt: v.number(),
    }),
    v.object({ ok: v.literal(false) }),
  ),
  handler: async (ctx, args) => {
    // Before anything is read or written. See `assertBundleSigningKey`.
    assertBundleSigningKey();

    const now = Date.now();
    const tokenId = fromHex(args.tokenId);
    const signature = fromHex(args.signature);

    // The plaintext id is hashed here and never stored, never logged and never
    // returned. `tokenIdHash` comes from `@sluice/crypto` so that this lookup
    // and the two write sites in `tokens.ts` cannot drift.
    const token = await getServiceTokenByIdHash(ctx, tokenIdHash({ tokenId }));

    // CHECK 2: the signature.
    if (token === null) {
      // Equal work, discarded result. See `DECOY_PUBLIC_KEY`.
      verifyHandshake(DECOY_PUBLIC_KEY, tokenId, args.unixSeconds, signature);
      return REFUSED;
    }
    if (
      !verifyHandshake(token.publicKey, tokenId, args.unixSeconds, signature)
    ) {
      return REFUSED;
    }

    // CHECK 3: freshness. Ed25519 signatures are DETERMINISTIC, so everything
    // above proves only that whoever produced these bytes once held the token
    // secret. It says nothing whatever about when, or about who is presenting
    // them now.
    const signatureHash = handshakeSignatureHash({ signature });
    if ((await getHandshakeNonce(ctx, signatureHash)) !== null) return REFUSED;
    await insertHandshakeNonce(ctx, {
      signatureHash,
      expiresAt: now + HANDSHAKE_NONCE_LIFETIME_MS,
    });

    // CHECK 4: the token is still allowed to exist.
    if (token.status !== "active") return REFUSED;
    // `>=` rather than `>`: a token valid "until" an instant is not valid at
    // it. The same rule as `requireSession` and as the bundle token.
    if (token.expiresAt !== undefined && now >= token.expiresAt) return REFUSED;

    // The org, for the audit row. A token that cannot be walked back to one is
    // a broken row rather than a caller error, and it refuses rather than
    // writing an audit event under a guessed organisation.
    const environment = await getEnvironment(ctx, token.environmentId);
    if (environment === null) return REFUSED;
    const project = await getProject(ctx, environment.projectId);
    if (project === null) return REFUSED;

    await patchServiceToken(ctx, token._id, { lastSeenAt: now });

    await recordTokenEvent(ctx, {
      orgId: project.orgId,
      tokenIdHash: token.tokenIdHash,
      action: "token.handshake",
      targetId: token._id,
    });

    // The subject is the DOCUMENT ID, not the token id. See the header of
    // `lib/jwt.ts` for why the plaintext id stays out of the bearer token.
    return {
      ok: true as const,
      token: signBundleToken({ subject: token._id, now }),
      expiresAt: now + BUNDLE_TOKEN_LIFETIME_MS,
    };
  },
});
