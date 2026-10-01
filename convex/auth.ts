import { ConvexError, v } from "convex/values";
import { ACCOUNT_SALT_BYTES } from "@sluice/crypto";
import { mutation, query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import type { NormalisedEmail } from "./lib/email";
import { assertHexBytes } from "./lib/hex";
import { requireId } from "./lib/ids";
import { decoySalt } from "./lib/salt";
import {
  assertCanonicalHex32,
  decoyVerifierHash,
  hashAuthVerifier,
  verifierHashEquals,
} from "./lib/verifier";
import {
  SESSION_LIFETIME_MS,
  hashSessionToken,
  issueSessionToken,
} from "./lib/session";
import { deleteSession, getSessionByTokenHash, insertSession } from "./repo/sessions";
import { getUserByEmail, getUserByUid, insertUser } from "./repo/users";

/**
 * Nothing here ever sees a password.
 *
 * The client derives the master unlock key with Argon2id, wraps its X25519 and
 * Ed25519 private keys under it, and derives a separate auth verifier from the
 * same password by a different path. What arrives is public key material plus
 * opaque blobs the server cannot open, and a verifier that authenticates the
 * account without unlocking anything.
 *
 * LOGIN IS TWO CALLS. The MUK is salted with a random per-account value, not
 * the address, so a client cannot derive anything until it knows that salt:
 * it calls `getLoginSalt` first, runs Argon2id, and then calls `login` with
 * the verifier. Signup is one call, because the client minted the salt itself.
 */

const DUPLICATE_EMAIL = "An account already exists for that email.";
const DUPLICATE_UID = "An account already exists with that uid.";

export const signup = mutation({
  args: {
    // The account's permanent id, `usr_` + 32 lowercase hex, minted by the
    // client with `newId("usr")` before this call. It is what other people's
    // wraps to this user bind to, so it is fixed here and never changes.
    // Client-chosen, so its shape is checked and its uniqueness enforced
    // below; see `packages/crypto/src/ids.ts`.
    uid: v.string(),
    // `newAccountSalt()`, lowercase hex: the salt the client just derived this
    // account's MUK under. Stored verbatim and handed back by `getLoginSalt`.
    accountSalt: v.string(),
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

    const uid = requireId("usr", "uid", args.uid);
    // Exactly the width `deriveMUK` accepts. A salt stored at any other width
    // is an account the client refuses to derive for, and so one nobody can
    // ever log in to; refusing it here turns that into an error at signup.
    assertHexBytes("accountSalt", args.accountSalt, ACCOUNT_SALT_BYTES);

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

    // After the email check, so a plain double signup keeps reporting the
    // address. In the same mutation as the insert, so two concurrent signups
    // claiming one uid cannot both pass: Convex serialises the conflicting
    // read of `by_uid` and retries the loser, which then sees the winner.
    if ((await getUserByUid(ctx, uid)) !== null) {
      throw new ConvexError(DUPLICATE_UID);
    }

    return await insertUser(ctx, {
      uid,
      accountSalt: args.accountSalt,
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
 * THE FIRST HALF OF LOGIN: THE SALT TO DERIVE UNDER.
 *
 * For an address with an account, the salt stored at signup. For any other
 * well-formed address, `decoySalt` of it: the same width, the same alphabet,
 * the same answer on every call, so the response does not say whether the
 * account exists. The client then derives under whatever it got and `login`
 * fails with its one generic message.
 *
 * WHAT THIS DOES AND DOES NOT PROTECT. Account existence is already public:
 * signup's duplicate-email message gives it away, and SECURITY.md publishes
 * that limit. The decoy only stops this endpoint making the question cheaper
 * and quieter to automate than it already is. And the REAL salt is public by
 * design: anyone who asks for a known address receives it, so a targeted
 * attacker can fetch one account's salt and precompute against it before any
 * breach. What the salt buys is that one table of guesses cannot be run
 * against every account at once; the password stays the only secret input.
 *
 * The decoy is computed FIRST, before the lookup, for two reasons. A missing
 * or malformed pepper then fails loudly for every address, rather than only
 * for unknown ones, which would itself distinguish them. And both branches do
 * the same HMAC, so the known-address path is not measurably cheaper.
 *
 * A query, not a mutation: it writes nothing, and caching by argument is
 * harmless because the answer for an address is fixed until it signs up.
 */
export const getLoginSalt = query({
  args: { email: v.string() },
  returns: v.object({ accountSalt: v.string() }),
  handler: async (ctx, args) => {
    const email = normaliseEmail(args.email);
    const decoy = decoySalt(email);
    const user = await getUserByEmail(ctx, email);
    return { accountSalt: user?.accountSalt ?? decoy };
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
    // The bearer credential for every later call. This is the ONLY place it is
    // ever returned, and the only place it exists in plaintext on this server:
    // the row stores its hash. It must not be logged, must not be put in a
    // URL, and must not be written to `auditLog`.
    sessionToken: v.string(),
    sessionExpiresAt: v.number(),
    userId: v.id("users"),
    // The permanent id. The client needs it to build the associated data of
    // any wrap addressed to this user, starting with the first environment's
    // project data key, and the Convex `userId` must never stand in for it.
    userUid: v.string(),
    publicKey: v.string(),
    verifyKey: v.string(),
    wrappedPrivateKey: v.string(),
    wrappedSigningKey: v.string(),
    recoveryBlob: v.optional(v.string()),
  }),
  // A mutation, not a query. Convex caches query results by argument, and an
  // authentication attempt is not a cacheable read. It now also writes the
  // session row, so it needs a transaction anyway. Rate limiting and an audit
  // row still belong here and still need one.
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

    // THE SESSION IS CREATED HERE, AFTER THE COMPARISON AND NOWHERE ELSE.
    //
    // Every throw above happens before this line, so a failed login leaves no
    // row behind: there is no path that authenticates partially. This is also
    // the reason `login` was already a mutation rather than a query, so
    // nothing about the transaction story changes by writing here.
    const sessionToken = issueSessionToken();
    const sessionExpiresAt = Date.now() + SESSION_LIFETIME_MS;
    await insertSession(ctx, {
      userId: user._id,
      tokenHash: hashSessionToken(sessionToken),
      createdAt: Date.now(),
      expiresAt: sessionExpiresAt,
    });

    // Only wrapped material and public keys. The server cannot open any of it,
    // and the stored hash never leaves this function.
    return {
      sessionToken,
      sessionExpiresAt,
      userId: user._id,
      userUid: user.uid,
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

/**
 * End one session, now.
 *
 * The row is DELETED rather than flagged, which is what makes "now" true. A
 * `revoked` boolean would leave a credential in the table that every future
 * reader has to remember to check, and would keep the table growing with
 * entries that are only conditionally dead. Deleting also drops the row that
 * `requireSession` read, so every Convex query subscription that resolved this
 * session is invalidated and re-runs, and the ones that re-run refuse.
 *
 * It never throws and never reports whether the token was real. Answering
 * would turn sign out into an oracle for whether a guessed token is live, at
 * an endpoint that deliberately demands no proof of anything, and it would
 * turn a double click on the sign out button into an error the user has to
 * read. Logging out a session you do not hold is not an attack: you needed the
 * token, and holding it you would use it rather than end it.
 *
 * This takes only the token. There is no `userId` argument and there must
 * never be one, because a handler that accepts an id here accepts an id for
 * somebody else's session.
 */
export const logout = mutation({
  args: { sessionToken: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    // Hashed, not decoded, so a malformed token takes the same path as an
    // unknown one. The token itself is never written anywhere and never
    // appears in the return value.
    const session = await getSessionByTokenHash(
      ctx,
      hashSessionToken(args.sessionToken),
    );
    if (session !== null) await deleteSession(ctx, session._id);
    return null;
  },
});
