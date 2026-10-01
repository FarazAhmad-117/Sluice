import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { ConvexError } from "convex/values";
import { getFunctionName } from "convex/server";
import type { FunctionReference } from "convex/server";
import { MasterUnlockKey, newId, toHex } from "@sluice/crypto";
import { messageForUser } from "../src/lib/auth/auth-errors";
import { createAuthFlows } from "../src/lib/auth/auth-flows";
import type { AuthClient, AuthFlows, AuthPhase } from "../src/lib/auth/auth-flows";
import type { PersistedSession } from "../src/lib/auth/session-store";

/**
 * THE LOGIN FLOW'S SECURITY PROPERTIES, PINNED AS A SEQUENCE OF CALLS.
 *
 * `createAuthFlows` is the code `AuthProvider` runs for signup, login and
 * unlock. It is given a stub Convex client that plays a tiny in-memory server
 * and RECORDS every call, and a fast stand-in for Argon2. What is asserted is
 * the order of events -- what reached the server, when, and what never did:
 *
 *  (a) THE DECOY PATH. Logging in to an address with no account makes exactly
 *      the same two calls as a wrong password on a real account, with nothing
 *      in between but the derivation, and ends in the same sentence. The
 *      client derives under the decoy without looking at it.
 *  (b) UNLOCK IS LOCAL. Zero queries, zero mutations, right password or wrong.
 *  (c) SIGNUP checks the uid the server echoes back.
 *  (d) LOGIN refuses a malformed uid before it can be stored.
 *
 * WHY A FAKE DERIVATION IS SOUND HERE. None of these properties is about the
 * key's value -- `argon2-agreement.test.ts` and `worker-protocol.test.ts` own
 * that. The stand-in is still a function of BOTH the password and the salt,
 * so a wrong password really does produce a different key and a different
 * verifier, and a substituted salt really would.
 */

const PASSWORD = "a long and entirely adequate passphrase";
const EMAIL = "someone@example.com";
const AUTH_FAILED = "Invalid email or verifier.";
const DECOY_SALT = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

type Event = string;

interface Account {
  uid: string;
  accountSalt: string;
  authVerifier: string;
  publicKey: string;
  verifyKey: string;
  wrappedPrivateKey: string;
  wrappedSigningKey: string;
}

let events: Event[];
let derivedSalts: string[];
let accounts: Map<string, Account>;
/** Lets a test corrupt what `auth.login` returns, as a hostile server would. */
let tamperLogin: ((reply: Record<string, unknown>) => Record<string, unknown>) | null;

function fakeKey(password: string, salt: Uint8Array): MasterUnlockKey {
  const digest = createHash("sha256").update(password, "utf8").update(salt).digest();
  return new MasterUnlockKey(new Uint8Array(digest));
}

function name(ref: unknown): string {
  return getFunctionName(ref as FunctionReference<"query" | "mutation">);
}

async function serve(kind: "query" | "mutation", fn: string, args: Record<string, unknown>) {
  if (kind === "query" && fn === "auth:getLoginSalt") {
    return { accountSalt: accounts.get(args.email as string)?.accountSalt ?? DECOY_SALT };
  }
  if (kind === "mutation" && fn === "auth:signup") {
    accounts.set(args.email as string, {
      uid: args.uid as string,
      accountSalt: args.accountSalt as string,
      authVerifier: args.authVerifier as string,
      publicKey: args.publicKey as string,
      verifyKey: args.verifyKey as string,
      wrappedPrivateKey: args.wrappedPrivateKey as string,
      wrappedSigningKey: args.wrappedSigningKey as string,
    });
    return "convex-user-id";
  }
  if (kind === "mutation" && fn === "auth:login") {
    const account = accounts.get(args.email as string);
    if (account === undefined || account.authVerifier !== args.authVerifier) {
      throw new ConvexError(AUTH_FAILED);
    }
    const reply: Record<string, unknown> = {
      sessionToken: "token",
      sessionExpiresAt: Date.now() + 60_000,
      userId: "convex-user-id",
      userUid: account.uid,
      publicKey: account.publicKey,
      verifyKey: account.verifyKey,
      wrappedPrivateKey: account.wrappedPrivateKey,
      wrappedSigningKey: account.wrappedSigningKey,
    };
    return tamperLogin ? tamperLogin(reply) : reply;
  }
  throw new Error(`stub server has no ${kind} ${fn}`);
}

const client = {
  query: (ref: unknown, args: Record<string, unknown>) => {
    events.push(`query ${name(ref)}`);
    return serve("query", name(ref), args);
  },
  mutation: (ref: unknown, args: Record<string, unknown>) => {
    events.push(`mutation ${name(ref)}`);
    return serve("mutation", name(ref), args);
  },
} as unknown as AuthClient;

const flows: AuthFlows = createAuthFlows(client, {
  derive: async (password, accountSalt) => {
    events.push("derive");
    derivedSalts.push(toHex(accountSalt));
    return fakeKey(password, accountSalt);
  },
  setPhase: (phase: AuthPhase) => {
    events.push(`phase ${phase}`);
  },
});

/** Runs `fn`, expecting it to reject, and returns the sentence the form shows. */
async function shownError(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (cause) {
    return messageForUser(cause);
  }
  throw new Error("expected the flow to reject");
}

async function signUp(): Promise<PersistedSession> {
  const { session } = await flows.signup({ email: EMAIL, password: PASSWORD });
  events = [];
  derivedSalts = [];
  return session;
}

beforeEach(() => {
  events = [];
  derivedSalts = [];
  accounts = new Map();
  tamperLogin = null;
});

describe("login", () => {
  it("fetches the salt, derives under it, then logs in, and stores what it derived under", async () => {
    const signedUp = await signUp();
    const { session } = await flows.login({ email: EMAIL, password: PASSWORD });

    expect(events).toEqual([
      "phase fetching-salt",
      "query auth:getLoginSalt",
      "derive",
      "phase contacting-server",
      "mutation auth:login",
      "phase unwrapping",
    ]);
    expect(derivedSalts).toEqual([signedUp.accountSalt]);
    expect(session.accountSalt).toBe(signedUp.accountSalt);
    expect(session.userUid).toBe(signedUp.userUid);
  });

  /**
   * (a) THE DECOY PATH. Exactly getLoginSalt then login, with only the
   * derivation between them -- no second lookup, no retry, no extra call that
   * would let the server or an observer tell an unknown address from a wrong
   * password. And the derivation ran under the decoy itself: the client did
   * not refuse it or treat it differently.
   */
  it("treats an unknown address exactly like a wrong password", async () => {
    const signedUp = await signUp();

    const decoyMessage = await shownError(() =>
      flows.login({ email: "nobody@example.com", password: PASSWORD }),
    );
    const decoyEvents = events;
    const decoySalts = derivedSalts;

    events = [];
    derivedSalts = [];
    const wrongPasswordMessage = await shownError(() =>
      flows.login({ email: EMAIL, password: "not the passphrase at all, sorry" }),
    );

    const expected = [
      "phase fetching-salt",
      "query auth:getLoginSalt",
      "derive",
      "phase contacting-server",
      "mutation auth:login",
    ];
    expect(decoyEvents).toEqual(expected);
    expect(events).toEqual(expected);
    expect(decoySalts).toEqual([DECOY_SALT]);
    expect(derivedSalts).toEqual([signedUp.accountSalt]);

    expect(decoyMessage).toBe(AUTH_FAILED);
    expect(decoyMessage).toBe(wrongPasswordMessage);
  });

  /** (d) A malformed uid never reaches the persisted session. */
  it.each([
    ["missing", undefined],
    ["not a usr id", "u1"],
    ["an org id", newId("org")],
    ["uppercase", newId("usr").toUpperCase().replace("USR_", "usr_")],
  ])("refuses a userUid that is %s", async (_label, userUid) => {
    await signUp();
    tamperLogin = (reply) => ({ ...reply, userUid });
    const message = await shownError(() => flows.login({ email: EMAIL, password: PASSWORD }));
    expect(message).toBe("Something went wrong. Try again.");
    if (typeof userUid === "string") expect(message).not.toContain(userUid);
  });
});

describe("signup", () => {
  it("sends the uid and salt it minted and keeps them in the session", async () => {
    const { session } = await flows.signup({ email: EMAIL, password: PASSWORD });
    expect(events).toEqual([
      "derive",
      "phase generating-keys",
      "phase contacting-server",
      "mutation auth:signup",
      "mutation auth:login",
      "phase unwrapping",
    ]);
    const stored = accounts.get(EMAIL);
    expect(stored?.uid).toBe(session.userUid);
    expect(stored?.accountSalt).toBe(session.accountSalt);
    expect(derivedSalts).toEqual([session.accountSalt]);
  });

  /**
   * (c) A server that echoes a different account's uid would have every later
   * wrap bound to the wrong user. The check fires even though the key material
   * itself round-trips, and the form shows nothing of either uid.
   */
  it("rejects a login reply carrying a different uid", async () => {
    const other = newId("usr");
    tamperLogin = (reply) => ({ ...reply, userUid: other });
    let caught: unknown;
    try {
      await flows.signup({ email: EMAIL, password: PASSWORD });
    } catch (cause) {
      caught = cause;
    }
    expect((caught as Error).message).toMatch(/account id that does not match/);
    const shown = messageForUser(caught);
    expect(shown).toBe("Something went wrong. Try again.");
    expect(shown).not.toContain(other);
    expect(shown).not.toContain(accounts.get(EMAIL)?.uid ?? "unreachable");
  });

  it("mints a fresh salt and uid on every submit", async () => {
    const first = await flows.signup({ email: EMAIL, password: PASSWORD });
    accounts.clear();
    const second = await flows.signup({ email: EMAIL, password: PASSWORD });
    expect(second.session.accountSalt).not.toBe(first.session.accountSalt);
    expect(second.session.userUid).not.toBe(first.session.userUid);
  });
});

describe("unlock", () => {
  /** (b) Unlock is local: the client is in scope and is never touched. */
  it("makes zero queries and zero mutations, and derives under the stored salt", async () => {
    const session = await signUp();
    const opened = await flows.unlock(session, PASSWORD);
    expect(opened.identity).toBeDefined();
    expect(events.filter((e) => e.startsWith("query") || e.startsWith("mutation"))).toEqual([]);
    expect(events).toEqual(["derive", "phase unwrapping"]);
    expect(derivedSalts).toEqual([session.accountSalt]);
  });

  it("makes zero calls on a wrong password too", async () => {
    const session = await signUp();
    await expect(flows.unlock(session, "the wrong passphrase, typed in haste")).rejects.toThrow();
    expect(events.filter((e) => e.startsWith("query") || e.startsWith("mutation"))).toEqual([]);
  });
});
