/**
 * WHERE THE SESSION TOKEN LIVES, AND WHAT THAT EXPOSES IT TO. READ THIS BEFORE
 * CHANGING ANYTHING IN THIS FILE.
 *
 * THE TOKEN IS IN `sessionStorage`. IT IS READABLE BY ANY SCRIPT THAT RUNS ON
 * THIS ORIGIN, INCLUDING AN INJECTED ONE. A cross-site scripting bug anywhere
 * in the dashboard, or in any dependency it loads, reads this record with three
 * lines of JavaScript and walks away with a live 12 hour credential. There is
 * no obfuscation here and there must not be: an encoding that only looks like
 * protection is worse than none, because it changes what a reviewer believes.
 *
 * WHY NOT AN httpOnly COOKIE. This was the intended answer and it is
 * ARCHITECTURALLY UNAVAILABLE, not merely unimplemented. Convex functions are
 * called from the browser and carry no headers of their own, so every query and
 * mutation in this product takes `sessionToken` as a FUNCTION ARGUMENT --
 * `convex/lib/session.ts` says so at length and explains why the design is
 * correct. An argument has to be readable by the code that builds the call. A
 * cookie the JavaScript cannot read is a cookie the JavaScript cannot put in
 * the argument list. Routing every Convex call through a Next route handler
 * that attaches the cookie server side would fix it, and would also throw away
 * Convex's reactive subscriptions, which is the thing the right hand panel of
 * this dashboard exists to demonstrate. That trade is a decision for a human,
 * and it is the single biggest open security question in this surface.
 *
 * WHY `sessionStorage` RATHER THAN `localStorage`. Against XSS they are
 * identical: both are readable by injected script on the origin. They differ in
 * two ways that are worth something and are not worth much:
 *
 *   - `sessionStorage` is per TAB, so the credential does not silently appear
 *     in every other tab the person opens, and a background tab compromised
 *     later does not find it.
 *   - `sessionStorage` is cleared when the tab closes, so the credential's real
 *     lifetime is the shorter of the tab and the server's absolute 12 hours,
 *     rather than always the full 12.
 *
 * It survives a page refresh, which is the requirement. It does not survive
 * closing the tab, which is a feature.
 *
 * WHAT ELSE IS STORED, AND WHY IT IS NOT AS BAD AS IT LOOKS. The record carries
 * the two WRAPPED key blobs. They are AES-256-GCM ciphertext under the master
 * unlock key, which is not stored anywhere and never has been. They are here so
 * that a refresh can offer an "unlock" prompt -- password only -- instead of a
 * full re-login. An attacker who reads them gets an offline Argon2id target,
 * which is a real cost; they also get the session token in the same read, which
 * is strictly worse and immediate. The blobs are not the weak link.
 *
 * WHAT IS NEVER STORED. The master unlock key. The unwrapped private keys. The
 * password. Any decrypted secret. All of those live in React state and die with
 * the page, which is why a refresh locks the vault and asks for the password
 * again. `convex/lib/session.ts` already states this consequence as intended:
 * "A page reload therefore costs a password re-entry no matter how long this
 * server side session lasts."
 */

const STORAGE_KEY = "sluice.session.v1";

/**
 * The persisted half of a signed-in session. Every field here is either public
 * material or opaque ciphertext or the bearer token discussed above. Nothing
 * added to this interface may be plaintext key material.
 */
export interface PersistedSession {
  /** The bearer credential. See the header for exactly what holds it. */
  readonly sessionToken: string;
  /** Absolute, from the server. Never extended client side. */
  readonly sessionExpiresAt: number;
  readonly userId: string;
  /** The normalised address. It is the Argon2id salt input, so it must match. */
  readonly email: string;
  readonly publicKey: string;
  readonly verifyKey: string;
  readonly wrappedPrivateKey: string;
  readonly wrappedSigningKey: string;
}

function storage(): Storage | null {
  // Absent during server rendering, and it throws rather than returning null
  // in a Safari private window with storage disabled.
  try {
    if (typeof window === "undefined") return null;
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** True when the shape is right AND the absolute expiry has not passed. */
function isLive(value: unknown): value is PersistedSession {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  const stringFields = [
    "sessionToken",
    "userId",
    "email",
    "publicKey",
    "verifyKey",
    "wrappedPrivateKey",
    "wrappedSigningKey",
  ];
  for (const field of stringFields) {
    if (typeof record[field] !== "string" || (record[field] as string).length === 0) return false;
  }
  if (typeof record.sessionExpiresAt !== "number") return false;
  // The client's clock is not authority over the server's, and it is not
  // treated as one: this only drops a record that is obviously spent, so the
  // user is not sent into a shell whose every query will refuse. The server
  // re-checks on every call and its answer is the one that counts.
  return (record.sessionExpiresAt as number) > Date.now();
}

export function loadSession(): PersistedSession | null {
  const store = storage();
  if (store === null) return null;
  let raw: string | null;
  try {
    raw = store.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
  if (raw === null) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isLive(parsed)) {
      clearSession();
      return null;
    }
    return parsed;
  } catch {
    clearSession();
    return null;
  }
}

export function saveSession(session: PersistedSession): void {
  const store = storage();
  if (store === null) return;
  try {
    store.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // A full or disabled store means the session simply does not survive a
    // refresh. That is a degraded experience, not a security problem, and it
    // must not break the sign-in that just succeeded.
  }
}

export function clearSession(): void {
  const store = storage();
  if (store === null) return;
  try {
    store.removeItem(STORAGE_KEY);
  } catch {
    // Nothing useful to do, and throwing here would break sign out.
  }
}
