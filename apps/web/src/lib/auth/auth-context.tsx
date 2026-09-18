"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { ConvexError } from "convex/values";
import type { MasterUnlockKey } from "@sluice/crypto";
import { api } from "@convex/_generated/api";
import { convexClient } from "@/lib/convex-provider";
import {
  DerivationBusyError,
  deriveMasterUnlockKey,
  probeDerivationCapability,
} from "@/lib/crypto/derive";
import type { Degradation, DerivationPath } from "@/lib/crypto/derive";
import { normaliseEmail } from "./email";
import {
  createIdentity,
  deriveAuthVerifier,
  identityMatches,
  unwrapIdentity,
} from "./identity";
import type { PrivateIdentity } from "./identity";
import { clearSession, loadSession, saveSession } from "./session-store";
import type { PersistedSession } from "./session-store";

/**
 * THE AUTHENTICATION AND VAULT STATE FOR THE WHOLE DASHBOARD.
 *
 * TWO PIECES OF STATE, AND THEY ARE NOT THE SAME PIECE. Conflating them is the
 * mistake this file is shaped to prevent.
 *
 *   SESSION   the server-side credential. Persisted, survives a refresh,
 *             readable by injected script. See `session-store.ts`.
 *   VAULT     the master unlock key and the unwrapped private keys. In memory
 *             only, dies with the page, and is what actually opens anything.
 *             Nothing writes it to `sessionStorage`, `localStorage`, IndexedDB,
 *             a cookie or the network, here or anywhere else.
 *
 * A refresh therefore leaves the user SIGNED IN AND LOCKED: the shell, the
 * project tree and the secret listing all work, because those need only the
 * token, and every secret stays sealed until the password is entered again.
 * That is not a gap in the implementation. `convex/lib/session.ts` states it as
 * the intended consequence of never persisting the master unlock key, and a
 * dashboard that stayed unlocked across a refresh would be one that had written
 * the key down somewhere.
 *
 * THE PASSWORD IS NEVER RETAINED. It is an argument to the three functions
 * below and is not copied into state, into a ref, or into the persisted record.
 * `deriveMasterUnlockKey` holds one reference for the duration of a single
 * derivation and clears it in a `finally`; that is documented in `derive.ts`.
 */

/** What the derivation actually did, surfaced so a fallback cannot pass unseen. */
export interface DerivationReport {
  readonly path: DerivationPath;
  readonly elapsedMs: number;
  readonly degradations: readonly Degradation[];
}

export interface DeviceCapability {
  readonly workerAvailable: boolean;
  readonly memoryAvailable: boolean;
  readonly wasmUsable: boolean;
  readonly reasons: readonly string[];
}

/** Phases a sign-in passes through, so the button can say something true. */
export type AuthPhase =
  | "idle"
  | "deriving"
  | "generating-keys"
  | "contacting-server"
  | "unwrapping";

export interface AuthState {
  readonly session: PersistedSession | null;
  readonly identity: PrivateIdentity | null;
  /**
   * The master unlock key, for as long as the vault is open.
   *
   * IT IS HERE BECAUSE A PROJECT DATA KEY GRANT IS WRAPPED UNDER IT. Reading
   * any secret means fetching `environments.getMyPdkGrant` and unwrapping the
   * blob it returns, and that unwrap needs this key. It is also what wraps a
   * NEW environment's project data key at creation.
   *
   * An earlier revision dropped it after the identity unwrap and said a feature
   * that needed it again must re-derive it from the password. That was the
   * right call while nothing needed it; it is the wrong one now. Re-deriving
   * costs 64 MiB and about 1.6 seconds, and it would have to happen on every
   * environment the user clicks, which means a password prompt in the middle of
   * browsing a list.
   *
   * WHAT HOLDING IT ADDS TO THE EXPOSURE, honestly. Not much, and that is the
   * argument rather than a shrug: the unwrapped X25519 and Ed25519 private keys
   * are ALREADY in this same state and already open everything the account can
   * reach. The MUK additionally re-derives the auth verifier, so it is also a
   * login credential. Both live in memory in this tab, for this tab, and die on
   * refresh with everything else. `MasterUnlockKey` keeps the bytes in a
   * `#private` field, so a spread or a `structuredClone` yields an EMPTY object
   * and `JSON.stringify` and `console.log` are redacted on the prototype.
   */
  readonly muk: MasterUnlockKey | null;
  /** True when a session exists but the vault is empty. Refresh lands here. */
  readonly locked: boolean;
  /**
   * False until the persisted session has been read out of `sessionStorage`.
   *
   * `sessionStorage` does not exist during server rendering, so the first
   * client render always reports "no session". A route that redirects on that
   * render bounces every signed-in user to the login page on every refresh.
   * Every guard must wait for this.
   */
  readonly hydrated: boolean;
  readonly phase: AuthPhase;
  readonly derivation: DerivationReport | null;
  readonly capability: DeviceCapability | null;
  readonly configured: boolean;
  signup(input: { email: string; password: string }): Promise<void>;
  login(input: { email: string; password: string }): Promise<void>;
  unlock(input: { password: string }): Promise<void>;
  logout(): Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

/**
 * Turns anything thrown by a Convex call into a sentence for the form.
 *
 * `ConvexError.data` is where the server's own message arrives. Everything else
 * gets a generic line: a raw transport error string on a login form is noise at
 * best and an information leak at worst.
 */
function messageForUser(cause: unknown): string {
  if (cause instanceof ConvexError) {
    const data: unknown = cause.data;
    if (typeof data === "string" && data.length > 0) return data;
  }
  if (cause instanceof DerivationBusyError) {
    return "A key derivation is already running. Wait for it to finish.";
  }
  if (cause instanceof Error && cause.name.startsWith("Derivation")) return cause.message;
  if (cause instanceof Error && cause.name === "EmailFormatError") return cause.message;
  if (cause instanceof Error && cause.name === "UnwrapFailedError") return cause.message;
  if (cause instanceof Error && cause.name === "WrappedKeyFormatError") return cause.message;
  return "Something went wrong. Try again.";
}

export class AuthFlowError extends Error {
  constructor(cause: unknown) {
    super(messageForUser(cause));
    this.name = "AuthFlowError";
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [{ session, hydrated }, setStored] = useState<{
    session: PersistedSession | null;
    hydrated: boolean;
  }>({ session: null, hydrated: false });
  /**
   * ONE PIECE OF STATE FOR THE WHOLE VAULT, not two.
   *
   * The private identity and the master unlock key are set and cleared
   * together, always. Two `useState` calls would make "unwrapped keys but no
   * master key" and "master key but no keys" representable, and `locked` would
   * then have to pick one of them to believe. It is closed here instead.
   */
  const [vault, setVault] = useState<{
    identity: PrivateIdentity;
    muk: MasterUnlockKey;
  } | null>(null);
  const [phase, setPhase] = useState<AuthPhase>("idle");
  const [derivation, setDerivation] = useState<DerivationReport | null>(null);
  const [capability, setCapability] = useState<DeviceCapability | null>(null);

  /**
   * THE PASSWORD IS STILL NEVER RETAINED, AND THAT HAS NOT CHANGED.
   *
   * What changed is the master unlock key, which is now held for the life of
   * the vault; the reasoning is on `AuthState.muk`. The password remains an
   * argument to the three functions below, is never copied into state, into a
   * ref, or into the persisted record, and `deriveMasterUnlockKey` clears its
   * one reference in a `finally`.
   */

  // Rehydrate the persisted session on mount. This runs in an effect rather
  // than in `useState`'s initialiser because `sessionStorage` does not exist
  // during server rendering, and reading it in the initialiser would make the
  // first client render disagree with the server's.
  //
  // One `setState`, carrying both the session and the fact that the read has
  // happened, so no consumer can observe a state where they disagree.
  //
  // The lint rule below is suppressed rather than satisfied, and this is the
  // one place in this surface where that is the right answer. Reading a
  // browser-only store after mount is exactly the external-system
  // synchronisation an effect is for, and there is no render-time form of it
  // that does not break hydration. It costs one extra render, once per page.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setStored({ session: loadSession(), hydrated: true });
  }, []);

  /**
   * Probe the device BEFORE the user has typed anything, which is what
   * `probeDerivationCapability` is for. Discovering at submit time that this
   * browser cannot start a worker means an eight second frozen tab the user was
   * never warned about, and on signup it can mean an account row that exists
   * and cannot be opened.
   */
  useEffect(() => {
    let cancelled = false;
    void probeDerivationCapability().then((result) => {
      if (!cancelled) setCapability(result);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  /**
   * One derivation, with its route recorded.
   *
   * `onDegraded` fires BEFORE the slow work starts, which is the only moment at
   * which a warning is still useful: a page that reports the fallback after the
   * fact has already frozen for eight seconds.
   */
  const derive = useCallback(async (password: string, salt: string) => {
    setPhase("deriving");
    const seen: Degradation[] = [];
    const result = await deriveMasterUnlockKey(password, salt, {
      onDegraded: (degradation) => {
        seen.push(degradation);
        setDerivation({ path: degradation.to, elapsedMs: 0, degradations: [...seen] });
      },
    });
    setDerivation({
      path: result.path,
      elapsedMs: result.elapsedMs,
      degradations: result.degradations,
    });
    return result.key;
  }, []);

  const requireClient = useCallback(() => {
    if (convexClient === null) {
      throw new AuthFlowError(new Error("This build has no Convex deployment URL."));
    }
    return convexClient;
  }, []);

  const signup = useCallback(
    async ({ email, password }: { email: string; password: string }) => {
      const client = requireClient();
      try {
        // Normalised FIRST, because this exact string is the Argon2id salt
        // input and the server will normalise the address the same way. A
        // mismatch here produces an account whose key cannot be re-derived.
        const salt = normaliseEmail(email);
        const muk = await derive(password, salt);

        setPhase("generating-keys");
        const { wrapped, pub } = await createIdentity(muk);
        const authVerifier = await deriveAuthVerifier(muk);

        setPhase("contacting-server");
        // Only public material, two opaque blobs and a verifier. No password,
        // no master unlock key, no private key.
        await client.mutation(api.auth.signup, {
          email: salt,
          authVerifier,
          publicKey: wrapped.publicKey,
          verifyKey: wrapped.verifyKey,
          wrappedPrivateKey: wrapped.wrappedPrivateKey,
          wrappedSigningKey: wrapped.wrappedSigningKey,
        });

        // `signup` returns a user id and nothing else: it does not sign the
        // user in. Logging in immediately is the only way to obtain a session,
        // and it deliberately reuses the SAME master unlock key rather than
        // deriving a second time, which would cost another 64 MiB and another
        // 1.6 seconds for an identical result.
        const result = await client.mutation(api.auth.login, {
          email: salt,
          authVerifier,
        });

        setPhase("unwrapping");
        // The round trip is checked rather than assumed. If what came back does
        // not open under the key that sealed it, the account is broken NOW,
        // which is far better than finding out at the first secret read.
        const restored = await unwrapIdentity(muk, result);
        if (!identityMatches(restored, pub)) {
          throw new Error("The server returned key material that does not match this account.");
        }

        const persisted: PersistedSession = {
          sessionToken: result.sessionToken,
          sessionExpiresAt: result.sessionExpiresAt,
          userId: result.userId,
          email: salt,
          publicKey: result.publicKey,
          verifyKey: result.verifyKey,
          wrappedPrivateKey: result.wrappedPrivateKey,
          wrappedSigningKey: result.wrappedSigningKey,
        };
        saveSession(persisted);
        setStored({ session: persisted, hydrated: true });
        setVault({ identity: restored, muk });
      } catch (cause) {
        throw new AuthFlowError(cause);
      } finally {
        setPhase("idle");
      }
    },
    [derive, requireClient],
  );

  const login = useCallback(
    async ({ email, password }: { email: string; password: string }) => {
      const client = requireClient();
      try {
        const salt = normaliseEmail(email);
        const muk = await derive(password, salt);
        const authVerifier = await deriveAuthVerifier(muk);

        setPhase("contacting-server");
        const result = await client.mutation(api.auth.login, { email: salt, authVerifier });

        setPhase("unwrapping");
        const priv = await unwrapIdentity(muk, result);
        if (!identityMatches(priv, result)) {
          throw new Error("The server returned key material that does not match this account.");
        }

        const persisted: PersistedSession = {
          sessionToken: result.sessionToken,
          sessionExpiresAt: result.sessionExpiresAt,
          userId: result.userId,
          email: salt,
          publicKey: result.publicKey,
          verifyKey: result.verifyKey,
          wrappedPrivateKey: result.wrappedPrivateKey,
          wrappedSigningKey: result.wrappedSigningKey,
        };
        saveSession(persisted);
        setStored({ session: persisted, hydrated: true });
        setVault({ identity: priv, muk });
      } catch (cause) {
        throw new AuthFlowError(cause);
      } finally {
        setPhase("idle");
      }
    },
    [derive, requireClient],
  );

  /**
   * Re-opens the vault after a refresh, using the session that survived and the
   * wrapped blobs stored beside it. No network call and no new session: the
   * token is still live, so this is purely local work.
   *
   * A wrong password fails at `unwrapIdentity` with a message that does not say
   * which input was wrong, because AES-GCM cannot tell us and guessing would be
   * a decryption oracle.
   */
  const unlock = useCallback(
    async ({ password }: { password: string }) => {
      const current = session;
      if (current === null) throw new AuthFlowError(new Error("There is no session to unlock."));
      try {
        const muk = await derive(password, current.email);
        setPhase("unwrapping");
        const priv = await unwrapIdentity(muk, current);
        if (!identityMatches(priv, current)) {
          throw new Error("The stored key material does not match this account.");
        }
        setVault({ identity: priv, muk });
      } catch (cause) {
        throw new AuthFlowError(cause);
      } finally {
        setPhase("idle");
      }
    },
    [derive, session],
  );

  /**
   * Ends the session server side and drops every local trace of it.
   *
   * The local state is cleared FIRST and unconditionally, so a failed network
   * call cannot leave a browser holding a credential it believes is gone. The
   * server call is best effort; `auth.logout` never throws and never reports
   * whether the token was real.
   */
  const logout = useCallback(async () => {
    const current = session;
    setVault(null);
    setStored({ session: null, hydrated: true });
    setDerivation(null);
    clearSession();
    if (current !== null && convexClient !== null) {
      try {
        await convexClient.mutation(api.auth.logout, { sessionToken: current.sessionToken });
      } catch {
        // The row may outlive the browser's belief by up to its absolute
        // expiry. Reporting this to the user would be noise: there is nothing
        // they can do, and the local credential is already gone.
      }
    }
  }, [session]);

  const value = useMemo<AuthState>(
    () => ({
      session,
      identity: vault?.identity ?? null,
      muk: vault?.muk ?? null,
      // One source of truth. "Signed in but locked" is the normal state after
      // every refresh: the session survived in `sessionStorage` and the vault,
      // which is memory only, did not.
      locked: session !== null && vault === null,
      hydrated,
      phase,
      derivation,
      capability,
      configured: convexClient !== null,
      signup,
      login,
      unlock,
      logout,
    }),
    [session, vault, hydrated, phase, derivation, capability, signup, login, unlock, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (value === null) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}
