import { ConvexError, v } from "convex/values";
import { mutation } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import type { NormalisedEmail } from "./lib/email";
import {
  assertCanonicalHex32,
  decoyVerifierHash,
  hashAuthVerifier,
  verifierHashEquals,
} from "./lib/verifier";
import { getUserByEmail, insertUser } from "./repo/users";

/**
 * Nothing here ever sees a password.
 *
 * The client derives the master unlock key with Argon2id, wraps its X25519 and
 * Ed25519 private keys under it, and derives a separate auth verifier from the
 * same password by a different path. What arrives is public key material plus
 * opaque blobs the server cannot open, and a verifier that authenticates the
 * account without unlocking anything.
 */

const DUPLICATE_EMAIL = "An account already exists for that email.";

export const signup = mutation({
  args: {
    email: v.string(),
    // Hex, checked against the canonical rule below. The validator cannot
    // express "64 lowercase hex characters", so `v.string()` here is the outer
    // shape and `assertCanonicalHex32` is the actual constraint.
    authVerifier: v.string(),
    publicKey: v.string(),
    verifyKey: v.string(),
    // Ciphertext produced by the client. Deliberately unconstrained beyond
    // being a string: the server has no way to check them and no business
    // knowing their internal format.
    wrappedPrivateKey: v.string(),
    wrappedSigningKey: v.string(),
    recoveryBlob: v.optional(v.string()),
  },
  returns: v.id("users"),
  handler: async (ctx, args): Promise<Id<"users">> => {
    const email = normaliseEmail(args.email);

    // The key fields are validated even though the server never uses them,
    // because they are handed straight back to clients as the material other
    // people encrypt to. A malformed public key is a value nobody can use and
    // nobody would notice until a share failed months later.
    assertCanonicalHex32("publicKey", args.publicKey);
    assertCanonicalHex32("verifyKey", args.verifyKey);

    if (args.wrappedPrivateKey.length === 0) {
      throw new ConvexError("wrappedPrivateKey must not be empty.");
    }
    if (args.wrappedSigningKey.length === 0) {
      throw new ConvexError("wrappedSigningKey must not be empty.");
    }

    const authVerifierHash = hashAuthVerifier(args.authVerifier);

    // `getUserByEmail` uses `.unique()`, so this throws rather than resolving
    // if the table somehow already holds two rows for one address. That is the
    // intended failure mode for an auth table and it is pinned by a test.
    const existing = await getUserByEmail(ctx, email);
    if (existing !== null) {
      throw new ConvexError(DUPLICATE_EMAIL);
    }

    return await insertUser(ctx, {
      email,
      authVerifierHash,
      publicKey: args.publicKey,
      verifyKey: args.verifyKey,
      wrappedPrivateKey: args.wrappedPrivateKey,
      wrappedSigningKey: args.wrappedSigningKey,
      ...(args.recoveryBlob === undefined
        ? {}
        : { recoveryBlob: args.recoveryBlob }),
    });
  },
});

/**
 * Every way login can fail says exactly this, and the tests assert the two
 * failures are byte-identical rather than merely both failures. An error that
 * distinguishes "no such account" from "wrong verifier" is an account
 * enumeration oracle: anyone can ask this server whether an address has signed
 * up, one request at a time, and get a reliable answer.
 */
const AUTH_FAILED = "Invalid email or verifier.";

export const login = mutation({
  args: {
    email: v.string(),
    authVerifier: v.string(),
  },
  returns: v.object({
    userId: v.id("users"),
    publicKey: v.string(),
    verifyKey: v.string(),
    wrappedPrivateKey: v.string(),
    wrappedSigningKey: v.string(),
    recoveryBlob: v.optional(v.string()),
  }),
  // A mutation rather than a query even though it writes nothing yet. Convex
  // caches query results by argument, and an authentication attempt is not a
  // cacheable read. Rate limiting and an audit row both belong here and both
  // need a transaction.
  handler: async (ctx, args) => {
    // Misconfiguration is checked first and is the one failure login does NOT
    // hide behind the generic message. A deployment with no pepper would
    // otherwise be indistinguishable from every password on earth being wrong,
    // and the person debugging it would look everywhere except the one place.
    const decoy = decoyVerifierHash();

    // A malformed address and a malformed verifier are the other two ways to
    // probe the shape of this endpoint, so they answer the same way as a wrong
    // one. Nothing legitimate sends either: the client derives the verifier
    // itself and normalises the address before it gets here. The pepper error
    // above is already past, so this cannot swallow it.
    let email: NormalisedEmail;
    let candidate: string;
    try {
      email = normaliseEmail(args.email);
      candidate = hashAuthVerifier(args.authVerifier);
    } catch {
      throw new ConvexError(AUTH_FAILED);
    }

    const user = await getUserByEmail(ctx, email);

    // The comparison runs whether or not an account exists. Returning early on
    // a miss would make this endpoint answer measurably faster for an address
    // nobody has registered, which is the same oracle as a distinct error
    // message, only harder to notice.
    const matches = verifierHashEquals(
      candidate,
      user?.authVerifierHash ?? decoy,
      decoy,
    );

    if (user === null || !matches) {
      throw new ConvexError(AUTH_FAILED);
    }

    // Only wrapped material and public keys. The server cannot open any of it,
    // and the stored hash never leaves this function.
    return {
      userId: user._id,
      publicKey: user.publicKey,
      verifyKey: user.verifyKey,
      wrappedPrivateKey: user.wrappedPrivateKey,
      wrappedSigningKey: user.wrappedSigningKey,
      ...(user.recoveryBlob === undefined
        ? {}
        : { recoveryBlob: user.recoveryBlob }),
    };
  },
});
