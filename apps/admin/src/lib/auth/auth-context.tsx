import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { MasterUnlockKey } from "@sluice/crypto";
import { api } from "@convex/_generated/api";
import { convexClient } from "@/lib/convex-provider";
import { deriveMasterUnlockKey, probeDerivationCapability } from "@/lib/crypto/derive";
import type { Degradation, DerivationPath } from "@/lib/crypto/derive";
import { AuthFlowError } from "./auth-errors";
import { createAuthFlows } from "./auth-flows";
import type { AuthPhase } from "./auth-flows";
import type { PrivateIdentity } from "./identity";
import { clearSession, loadSession, saveSession } from "./session-store";
import type { PersistedSession } from "./session-store";

export type { AuthPhase } from "./auth-flows";

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

/**
 * THERE IS NO `hydrated` FLAG HERE, AND ITS ABSENCE IS DELIBERATE.
 *
 * The Next version of this file carried one. It had to: `sessionStorage` does
 * not exist during server rendering, so the first client render always
 * reported "no session", and a route guard that redirected on that render
 * bounced every signed-in user to the login page on every refresh. The flag
 * held the guard back until the stored session had actually been looked for.
 *
 * This application has no server render. The very first render happens in the
 * browser with `sessionStorage` already present, so the session is read in the
 * `useState` initialiser below and `session` is correct from the first render
 * onwards. A flag that was always true by the time anybody could read it would
 * be a guard against a hazard this build does not have, and the next person to
 * touch a route would have to work out which.
 *
 * IF SERVER RENDERING IS EVER ADDED TO THIS APPLICATION, THE FLAG COMES BACK
 * WITH IT, and every guard has to wait on it again.
 */
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
  readonly phase: AuthPhase;
  readonly derivation: DerivationReport | null;
  readonly capability: DeviceCapability | null;
  readonly configured: boolean;
  signup(input: { email: string; password: string }): Promise<void>;
  login(input: { email: string; password: string }): Promise<void>;
  unlock(input: { password: string }): Promise<void>;
  logout(): Promise<void>;
}

/**
 * `setTimeout` stores its delay in a signed 32-bit integer. A larger delay
 * overflows and fires on the NEXT TICK, which for the session expiry timer
 * would mean signing the user out immediately. Anything beyond this is treated
 * as "do not arm a timer" instead.
 */
const MAX_TIMEOUT_MS = 2_147_483_647;

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  /**
   * The persisted session, read once, synchronously, before the first render.
   *
   * The initialiser form is legal here and was not legal under Next: there is
   * no server render to disagree with, so `sessionStorage` is already present
   * when this runs. `loadSession` is itself total -- a blocked or absent store,
   * a malformed record and an expired one all come back as `null` -- so there
   * is nothing here that can throw during the initial render.
   */
  const [session, setSession] = useState<PersistedSession | null>(() => loadSession());
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

  /**
   * THE SESSION EXPIRES WHILE THE TAB IS STILL OPEN, SO SOMETHING HAS TO NOTICE.
   *
   * `loadSession` drops a spent record, but it only runs once, at startup. A
   * dashboard left open past its absolute expiry would otherwise sit there
   * looking signed in while every Convex query behind it started refusing, and
   * the user would read that as the product being broken rather than as their
   * session having ended.
   *
   * So the expiry is armed as a timer. When it fires, the local state is
   * dropped and the route guard sends the user to the sign-in page on the next
   * render. The server has already stopped honouring the token by then; this
   * only makes the browser agree.
   *
   * THE CLIENT CLOCK IS NOT AUTHORITY, and this does not treat it as one. A
   * machine whose clock is slow keeps a dead session on screen until the next
   * query refuses; a machine whose clock is fast signs the user out early. Both
   * are better than the alternative, and the server's answer remains the one
   * that decides anything. `setTimeout` is clamped to a 32-bit delay, so a
   * nonsense expiry far in the future would fire immediately: it is clamped
   * here instead, which turns that case into "never fires" rather than "signs
   * out at once".
   *
   * The VAULT goes with it. Keeping the master unlock key and the unwrapped
   * private keys in memory after the credential that reached the data is dead
   * would leave the most valuable material in this application alive for no
   * remaining purpose.
   */
  useEffect(() => {
    if (session === null) return;

    const expire = () => {
      setSession(null);
      setVault(null);
      clearSession();
    };

    const remaining = session.sessionExpiresAt - Date.now();
    if (remaining <= 0) {
      expire();
      return;
    }
    if (remaining > MAX_TIMEOUT_MS) return;
    const handle = setTimeout(expire, remaining);
    return () => clearTimeout(handle);
  }, [session]);

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
  const derive = useCallback(async (password: string, accountSalt: Uint8Array) => {
    setPhase("deriving");
    const seen: Degradation[] = [];
    const result = await deriveMasterUnlockKey(password, accountSalt, {
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

  /**
   * The three flows, as plain functions over the client: `auth-flows.ts`
   * carries the sequences and the reasons for their order. What stays here is
   * storing what they open and turning any failure into one `AuthFlowError`.
   */
  const flows = useMemo(() => createAuthFlows(convexClient, { derive, setPhase }), [derive]);

  const signup = useCallback(
    async (input: { email: string; password: string }) => {
      try {
        const opened = await flows.signup(input);
        saveSession(opened.session);
        setSession(opened.session);
        setVault({ identity: opened.identity, muk: opened.muk });
      } catch (cause) {
        throw new AuthFlowError(cause);
      } finally {
        setPhase("idle");
      }
    },
    [flows],
  );

  const login = useCallback(
    async (input: { email: string; password: string }) => {
      try {
        const opened = await flows.login(input);
        saveSession(opened.session);
        setSession(opened.session);
        setVault({ identity: opened.identity, muk: opened.muk });
      } catch (cause) {
        throw new AuthFlowError(cause);
      } finally {
        setPhase("idle");
      }
    },
    [flows],
  );

  /**
   * Re-opens the vault after a refresh. Local work only; see
   * `createAuthFlows().unlock`.
   */
  const unlock = useCallback(
    async ({ password }: { password: string }) => {
      const current = session;
      if (current === null) throw new AuthFlowError(new Error("There is no session to unlock."));
      try {
        setVault(await flows.unlock(current, password));
      } catch (cause) {
        throw new AuthFlowError(cause);
      } finally {
        setPhase("idle");
      }
    },
    [flows, session],
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
    setSession(null);
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
      phase,
      derivation,
      capability,
      configured: convexClient !== null,
      signup,
      login,
      unlock,
      logout,
    }),
    [session, vault, phase, derivation, capability, signup, login, unlock, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (value === null) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}
