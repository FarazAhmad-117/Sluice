import type { ConvexReactClient } from "convex/react";
import { assertId, fromHex, newAccountSalt, newId, toHex } from "@sluice/crypto";
import type { MasterUnlockKey } from "@sluice/crypto";
import { api } from "@convex/_generated/api";
import { decodeLoginSalt } from "./auth-errors";
import { normaliseEmail } from "./email";
import {
  createIdentity,
  deriveAuthVerifier,
  identityMatches,
  unwrapIdentity,
} from "./identity";
import type { PrivateIdentity } from "./identity";
import type { PersistedSession } from "./session-store";

/**
 * SIGNUP, LOGIN AND UNLOCK, AS PLAIN FUNCTIONS OVER A CLIENT.
 *
 * These are the three sequences whose ORDER is a security property: which
 * calls reach the server, in what order, carrying what, and which reach it not
 * at all. They used to live inside `AuthProvider`'s callbacks, where the only
 * way to observe them was to render a React tree, and this application's tests
 * run in Node with no DOM. Here they take the Convex client and two hooks as
 * arguments, so a test can hand them a stub that records every call and assert
 * on the sequence itself.
 *
 * WHAT STAYS IN `auth-context.tsx`: React state, the persisted record, and
 * turning a failure into an `AuthFlowError`. These functions throw raw errors
 * and return what was opened; they never touch storage, and they never retain
 * the password -- it is an argument, passed to `derive`, and dropped.
 */

/** Phases a sign-in passes through, so the button can say something true. */
export type AuthPhase =
  | "idle"
  /**
   * Login only: asking `auth.getLoginSalt` for the salt to derive under. A
   * network round trip, so it gets its own phase rather than being reported
   * as "deriving" while no Argon2 has started.
   */
  | "fetching-salt"
  | "deriving"
  | "generating-keys"
  | "contacting-server"
  | "unwrapping";

/** The two methods the flows call. The real thing is a `ConvexReactClient`. */
export type AuthClient = Pick<ConvexReactClient, "query" | "mutation">;

export interface AuthFlowHooks {
  /**
   * Derives the master unlock key. In the app this is `deriveMasterUnlockKey`
   * wrapped to record the route it took and set the "deriving" phase.
   */
  derive(password: string, accountSalt: Uint8Array): Promise<MasterUnlockKey>;
  setPhase(phase: AuthPhase): void;
}

/** A session and the vault it opened, for the provider to store. */
export interface OpenedSession {
  readonly session: PersistedSession;
  readonly identity: PrivateIdentity;
  readonly muk: MasterUnlockKey;
}

export interface OpenedVault {
  readonly identity: PrivateIdentity;
  readonly muk: MasterUnlockKey;
}

export interface AuthFlows {
  signup(input: { email: string; password: string }): Promise<OpenedSession>;
  login(input: { email: string; password: string }): Promise<OpenedSession>;
  unlock(session: PersistedSession, password: string): Promise<OpenedVault>;
}

/**
 * `client` is `null` in a build with no Convex deployment URL. Signup and login
 * refuse then; unlock does not need it, and that is the point of unlock.
 */
export function createAuthFlows(client: AuthClient | null, hooks: AuthFlowHooks): AuthFlows {
  const { derive, setPhase } = hooks;

  const requireClient = (): AuthClient => {
    if (client === null) throw new Error("This build has no Convex deployment URL.");
    return client;
  };

  async function signup({ email, password }: { email: string; password: string }) {
    const convex = requireClient();
    // Normalised first, so a malformed address is refused before 64 MiB of
    // Argon2 is spent on it. The address is only the lookup key for login; it
    // no longer feeds the derivation.
    const normalised = normaliseEmail(email);

    // BOTH MINTED HERE, BEFORE ANYTHING IS DERIVED OR SENT. The salt is the
    // account's, random and permanent: the server stores it verbatim and hands
    // it back from `getLoginSalt`, so it is public, and the password remains
    // the only secret input to the key. The uid is the account's permanent id,
    // which every wrap addressed to this user will bind to. It is client-minted
    // like every permanent id in this protocol, so it is fixed before anything
    // bound to it exists; the server checks only its shape and that no other
    // account already holds it.
    //
    // A fresh salt per submit also means a second submit is NOT deduplicated
    // by `deriveMasterUnlockKey`'s single-flight slot -- different salt,
    // different request. The disabled submit button is what stops that.
    const accountSalt = newAccountSalt();
    const uid = newId("usr");
    const muk = await derive(password, accountSalt);

    setPhase("generating-keys");
    const { wrapped, pub } = await createIdentity(muk);
    const authVerifier = deriveAuthVerifier(muk);

    setPhase("contacting-server");
    // Only public material, two opaque blobs and a verifier. No password, no
    // master unlock key, no private key.
    await convex.mutation(api.auth.signup, {
      uid,
      accountSalt: toHex(accountSalt),
      email: normalised,
      authVerifier,
      publicKey: wrapped.publicKey,
      verifyKey: wrapped.verifyKey,
      wrappedPrivateKey: wrapped.wrappedPrivateKey,
      wrappedSigningKey: wrapped.wrappedSigningKey,
    });

    // `signup` returns a user id and nothing else: it does not sign the user
    // in. Logging in immediately is the only way to obtain a session, and it
    // deliberately reuses the SAME master unlock key rather than deriving a
    // second time, which would cost another 64 MiB and another 1.6 seconds for
    // an identical result.
    //
    // It also skips `getLoginSalt`: the salt is the one minted above, and
    // asking the server for it back would only add a round trip.
    const result = await convex.mutation(api.auth.login, { email: normalised, authVerifier });

    setPhase("unwrapping");
    // The round trip is checked rather than assumed. If what came back does not
    // open under the key that sealed it, the account is broken NOW, which is
    // far better than finding out at the first secret read.
    const restored = await unwrapIdentity(muk, result);
    if (!identityMatches(restored, pub)) {
      throw new Error("The server returned key material that does not match this account.");
    }
    // The uid too. A server that answered with a different account's uid would
    // have every later wrap bound to the wrong user.
    if (result.userUid !== uid) {
      throw new Error("The server returned an account id that does not match this account.");
    }

    const session: PersistedSession = {
      sessionToken: result.sessionToken,
      sessionExpiresAt: result.sessionExpiresAt,
      userId: result.userId,
      userUid: uid,
      accountSalt: toHex(accountSalt),
      email: normalised,
      publicKey: result.publicKey,
      verifyKey: result.verifyKey,
      wrappedPrivateKey: result.wrappedPrivateKey,
      wrappedSigningKey: result.wrappedSigningKey,
    };
    return { session, identity: restored, muk };
  }

  async function login({ email, password }: { email: string; password: string }) {
    const convex = requireClient();
    const normalised = normaliseEmail(email);

    // THE SALT FIRST. The key is derived under the account's random salt, so
    // nothing can be derived until the server says what it is. For an address
    // with no account the answer is a decoy of the same shape, which derives
    // like any other salt and then fails `login` with the same generic message
    // as a wrong password; nothing here inspects it or could tell. A `query`,
    // not a mutation: it writes nothing.
    setPhase("fetching-salt");
    const reply: { accountSalt?: unknown } | null | undefined = await convex.query(
      api.auth.getLoginSalt,
      { email: normalised },
    );
    // `reply?.` so a null or empty reply is an `AccountSaltError` too, rather
    // than a `TypeError` with a message nobody can act on.
    const accountSalt = decodeLoginSalt(reply?.accountSalt);

    const muk = await derive(password, accountSalt);
    const authVerifier = deriveAuthVerifier(muk);

    setPhase("contacting-server");
    const result = await convex.mutation(api.auth.login, { email: normalised, authVerifier });

    setPhase("unwrapping");
    const priv = await unwrapIdentity(muk, result);
    if (!identityMatches(priv, result)) {
      throw new Error("The server returned key material that does not match this account.");
    }

    const session: PersistedSession = {
      sessionToken: result.sessionToken,
      sessionExpiresAt: result.sessionExpiresAt,
      userId: result.userId,
      // Checked now rather than at the next reload, where `loadSession` would
      // discard the record and send the user back here anyway.
      userUid: assertId("usr", "userUid", result.userUid),
      // Re-encoded from the decoded bytes rather than copied from the reply,
      // so what is stored is exactly what was derived under.
      accountSalt: toHex(accountSalt),
      email: normalised,
      publicKey: result.publicKey,
      verifyKey: result.verifyKey,
      wrappedPrivateKey: result.wrappedPrivateKey,
      wrappedSigningKey: result.wrappedSigningKey,
    };
    return { session, identity: priv, muk };
  }

  /**
   * Re-opens the vault after a refresh, using the session that survived and
   * the wrapped blobs stored beside it. NO NETWORK CALL and no new session:
   * the token is still live, so this is purely local work, and the client in
   * scope here is deliberately never used.
   *
   * A wrong password fails at `unwrapIdentity` with a message that does not
   * say which input was wrong, because AES-GCM cannot tell us and guessing
   * would be a decryption oracle.
   */
  async function unlock(session: PersistedSession, password: string) {
    // The stored salt, which `loadSession` has already checked against
    // `ACCOUNT_SALT_HEX`. No `getLoginSalt` call: the record is the only
    // source of the salt after a reload.
    const muk = await derive(password, fromHex(session.accountSalt));
    setPhase("unwrapping");
    const identity = await unwrapIdentity(muk, session);
    if (!identityMatches(identity, session)) {
      throw new Error("The stored key material does not match this account.");
    }
    return { identity, muk };
  }

  return { signup, login, unlock };
}
