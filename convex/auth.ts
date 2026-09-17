import { ConvexError, v } from "convex/values";
import { mutation } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { assertCanonicalHex32, hashAuthVerifier } from "./lib/verifier";
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
