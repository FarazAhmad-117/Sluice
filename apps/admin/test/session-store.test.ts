import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { newAccountSalt, newId, toHex } from "@sluice/crypto";
import { clearSession, loadSession, saveSession } from "../src/lib/auth/session-store";
import type { PersistedSession } from "../src/lib/auth/session-store";

/**
 * THE PERSISTED SESSION IS THE ONLY COPY OF TWO VALUES AFTER A RELOAD.
 *
 * No query returns the caller's permanent uid or account salt once they are
 * signed in: `auth.login` hands both back once, and `auth.getLoginSalt` wants
 * an email and a fresh login behind it. So after a refresh, the record in
 * `sessionStorage` is the only place the dashboard can find
 *
 *   - `accountSalt`, without which the unlock prompt cannot re-derive the
 *     master unlock key at all, and
 *   - `userUid`, which every wrap addressed to this user is bound to.
 *
 * A record missing either, or holding a malformed one, is therefore not a
 * "degraded" session. It is a session that cannot be unlocked and cannot be
 * repaired from where it sits, and the only honest thing to do is discard it
 * and send the user to log in again. These tests pin exactly that.
 *
 * Node has no `window`, so a minimal in-memory `sessionStorage` is installed
 * for each test. It is the one surface `session-store.ts` touches.
 */

const STORAGE_KEY = "sluice.session.v1";

class MemoryStorage {
  #items = new Map<string, string>();
  getItem(key: string): string | null {
    return this.#items.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.#items.set(key, value);
  }
  removeItem(key: string): void {
    this.#items.delete(key);
  }
}

let store: MemoryStorage;

beforeEach(() => {
  store = new MemoryStorage();
  vi.stubGlobal("window", { sessionStorage: store });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const HEX64 = "ab".repeat(32);

function validSession(): PersistedSession {
  return {
    sessionToken: "token",
    sessionExpiresAt: Date.now() + 60_000,
    userId: "convex-user-id",
    userUid: newId("usr"),
    accountSalt: toHex(newAccountSalt()),
    email: "user@example.com",
    publicKey: HEX64,
    verifyKey: HEX64,
    wrappedPrivateKey: "wrapped-private",
    wrappedSigningKey: "wrapped-signing",
  };
}

/** Writes a raw record, bypassing `saveSession`, as an old build would have. */
function storeRaw(record: unknown): void {
  store.setItem(STORAGE_KEY, JSON.stringify(record));
}

describe("session store", () => {
  it("round-trips userUid and accountSalt", () => {
    const session = validSession();
    saveSession(session);
    const loaded = loadSession();
    expect(loaded).toEqual(session);
    expect(loaded?.userUid).toBe(session.userUid);
    expect(loaded?.accountSalt).toBe(session.accountSalt);
  });

  it("returns null and leaves nothing behind after clearSession", () => {
    saveSession(validSession());
    clearSession();
    expect(loadSession()).toBeNull();
    expect(store.getItem(STORAGE_KEY)).toBeNull();
  });

  /**
   * A record written by the build before this one has neither field. It must
   * not be loaded as a session the dashboard then fails to unlock: it is
   * discarded, and the stored copy is removed so the next load does not meet
   * it again.
   */
  it.each(["userUid", "accountSalt"] as const)(
    "discards a stored session missing %s",
    (field) => {
      const record: Partial<PersistedSession> = { ...validSession() };
      delete record[field];
      storeRaw(record);
      expect(loadSession()).toBeNull();
      expect(store.getItem(STORAGE_KEY)).toBeNull();
    },
  );

  it.each([
    ["not a usr id at all", "u1"],
    ["an org id", newId("org")],
    ["uppercase hex", newId("usr").toUpperCase().replace("USR_", "usr_")],
    ["a number", 42],
  ])("discards a stored session whose userUid is %s", (_label, userUid) => {
    storeRaw({ ...validSession(), userUid });
    expect(loadSession()).toBeNull();
    expect(store.getItem(STORAGE_KEY)).toBeNull();
  });

  /**
   * Thirty-two LOWERCASE hex characters, nothing else. Fifteen or seventeen
   * bytes would be refused by `deriveMUK` only after the user had typed their
   * password into the unlock prompt; uppercase is not what the server stores
   * or what `toHex` produces, so its presence means the record did not come
   * from this code.
   */
  it.each([
    ["15 bytes", "ab".repeat(15)],
    ["17 bytes", "ab".repeat(17)],
    ["uppercase", "AB".repeat(16)],
    ["not hex", "zz".repeat(16)],
    ["empty", ""],
    ["an array of bytes", Array.from(newAccountSalt())],
  ])("discards a stored session whose accountSalt is %s", (_label, accountSalt) => {
    storeRaw({ ...validSession(), accountSalt });
    expect(loadSession()).toBeNull();
    expect(store.getItem(STORAGE_KEY)).toBeNull();
  });

  it("still discards an expired session", () => {
    storeRaw({ ...validSession(), sessionExpiresAt: Date.now() - 1 });
    expect(loadSession()).toBeNull();
  });
});
