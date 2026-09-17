import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api, internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession, listSessionsByUser } from "./repo/sessions";

export const modules = import.meta.glob("./**/*.ts");

type Harness = ReturnType<typeof convexTest>;

const VERIFIER =
  "3f2a91c0d4b7e65a18cc0fd3b2a94e7710f5c86d2b41a9e3c7d508f6b1a2c3d4";
const TEST_PEPPER =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

beforeEach(() => {
  process.env.AUTH_PEPPER = TEST_PEPPER;
});

afterEach(() => {
  delete process.env.AUTH_PEPPER;
  vi.useRealTimers();
});

function signupArgs(overrides: Record<string, unknown> = {}) {
  return {
    email: "ada@example.test",
    authVerifier: VERIFIER,
    publicKey: "11".repeat(32),
    verifyKey: "22".repeat(32),
    wrappedPrivateKey: "wrapped-private-key-blob",
    wrappedSigningKey: "wrapped-signing-key-blob",
    ...overrides,
  };
}

async function signIn(t: Harness): Promise<string> {
  await t.mutation(api.auth.signup, signupArgs());
  const result = await t.mutation(api.auth.login, {
    email: "ada@example.test",
    authVerifier: VERIFIER,
  });
  return result.sessionToken;
}

/**
 * A well formed id for a row that does not exist, borrowed from the hierarchy
 * suites. It carries the table tag Convex's id validator checks, which is the
 * only way to get past the validator and reach the handler.
 */
function absentIdLike<T extends string>(id: T): T {
  const digits = "0123456789";
  return id
    .split("")
    .map((c) => (digits.includes(c) ? (c === "9" ? "0" : "9") : c))
    .join("") as T;
}

/**
 * Seeded through the repo layer, like every other fixture here: the scan in
 * `repo/repo.test.ts` reads test files too.
 */
async function seedSession(
  t: Harness,
  userId: Id<"users">,
  expiresAt: number,
): Promise<string> {
  const token = "ab".repeat(32);
  await t.run(async (ctx) =>
    insertSession(ctx, {
      userId,
      tokenHash: hashSessionToken(token),
      createdAt: Date.now(),
      expiresAt,
    }),
  );
  return token;
}

/**
 * The refusal every unauthenticated path shares. It is distinct from the
 * hierarchy's "Not found, or you do not have access to it." on purpose: the
 * client already knows whether it presented a token, so telling it that the
 * token is the problem leaks nothing and is the difference between a redirect
 * to the sign in screen and an incomprehensible error.
 */
const NOT_AUTHENTICATED = "Your session is not valid. Sign in again.";

describe("login issues a session", () => {
  it("returns an opaque token of 32 bytes", async () => {
    const t = convexTest(schema, modules);
    const token = await signIn(t);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns an absolute expiry one lifetime ahead", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const before = Date.now();
    const result = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });

    expect(result.sessionExpiresAt).toBeGreaterThanOrEqual(
      before + SESSION_LIFETIME_MS,
    );
    expect(result.sessionExpiresAt).toBeLessThanOrEqual(
      Date.now() + SESSION_LIFETIME_MS,
    );
  });

  it("stores the hash and never the token", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.mutation(api.auth.signup, signupArgs());
    const result = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });

    const rows = await t.run(async (ctx) => listSessionsByUser(ctx, userId));
    expect(rows).toHaveLength(1);
    // The point of the table. Someone who reads it holds digests, not
    // credentials.
    expect(JSON.stringify(rows)).not.toContain(result.sessionToken);
    expect(rows[0]?.tokenHash).toBe(hashSessionToken(result.sessionToken));
  });

  it("issues a different token every time and honours both", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const first = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });
    const second = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });

    expect(first.sessionToken).not.toBe(second.sessionToken);
    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: first.sessionToken }),
    ).resolves.toEqual([]);
    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: second.sessionToken }),
    ).resolves.toEqual([]);
  });

  it("does not issue a session when the verifier is wrong", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.mutation(api.auth.signup, signupArgs());

    await expect(
      t.mutation(api.auth.login, {
        email: "ada@example.test",
        authVerifier: "ff".repeat(32),
      }),
    ).rejects.toThrow();

    expect(await t.run(async (ctx) => listSessionsByUser(ctx, userId))).toEqual(
      [],
    );
  });
});

describe("a presented token is verified against the table", () => {
  it("refuses a token that was never issued", async () => {
    const t = convexTest(schema, modules);
    await signIn(t);

    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: "cd".repeat(32) }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  it("refuses a token that is not even the right shape", async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: "" }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: "not a token" }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  it("refuses a token whose case was changed", async () => {
    // The stored hash is over the exact bytes issued, so a client that
    // upper-cases the hex it was handed is a client that does not match.
    const t = convexTest(schema, modules);
    const token = await signIn(t);

    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: token.toUpperCase() }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  it("refuses a session whose user no longer exists", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.run(async (ctx) =>
      insertUser(ctx, {
        email: normaliseEmail("ghost@example.test"),
        authVerifierHash: "hash",
        publicKey: "11".repeat(32),
        verifyKey: "22".repeat(32),
        wrappedPrivateKey: "wrapped-private-key-blob",
        wrappedSigningKey: "wrapped-signing-key-blob",
      }),
    );

    const token = await seedSession(
      t,
      absentIdLike(userId),
      Date.now() + SESSION_LIFETIME_MS,
    );

    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: token }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });
});

describe("sessions expire", () => {
  it("refuses a session whose expiry has passed", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.mutation(api.auth.signup, signupArgs());
    const token = await seedSession(t, userId, Date.now() - 1);

    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: token }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  it("accepts a session one millisecond before its expiry and refuses it one millisecond after", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.mutation(api.auth.signup, signupArgs());

    const deadline = Date.now() + SESSION_LIFETIME_MS;
    const token = await seedSession(t, userId, deadline);

    vi.useFakeTimers();
    vi.setSystemTime(deadline - 1);
    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: token }),
    ).resolves.toEqual([]);

    // The boundary itself counts as expired: a session that is valid "until"
    // an instant is not valid at it.
    vi.setSystemTime(deadline);
    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: token }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  it("does not move the expiry when the session is used", async () => {
    // Absolute, not sliding. A sliding window makes a stolen token immortal
    // for as long as the thief keeps using it.
    const t = convexTest(schema, modules);
    const userId = await t.mutation(api.auth.signup, signupArgs());
    const result = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });

    await t.query(api.orgs.listMyOrgs, { sessionToken: result.sessionToken });
    await t.query(api.orgs.listMyOrgs, { sessionToken: result.sessionToken });

    const rows = await t.run(async (ctx) => listSessionsByUser(ctx, userId));
    expect(rows[0]?.expiresAt).toBe(result.sessionExpiresAt);
  });
});

describe("logout", () => {
  it("refuses the token immediately, not at expiry", async () => {
    const t = convexTest(schema, modules);
    const token = await signIn(t);

    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: token }),
    ).resolves.toEqual([]);

    await t.mutation(api.auth.logout, { sessionToken: token });

    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: token }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  it("removes the row rather than flagging it", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.mutation(api.auth.signup, signupArgs());
    const result = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });

    await t.mutation(api.auth.logout, { sessionToken: result.sessionToken });

    expect(await t.run(async (ctx) => listSessionsByUser(ctx, userId))).toEqual(
      [],
    );
  });

  it("leaves the user's other sessions alone", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());
    const laptop = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });
    const phone = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER,
    });

    await t.mutation(api.auth.logout, { sessionToken: laptop.sessionToken });

    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: laptop.sessionToken }),
    ).rejects.toThrow(NOT_AUTHENTICATED);
    await expect(
      t.query(api.orgs.listMyOrgs, { sessionToken: phone.sessionToken }),
    ).resolves.toEqual([]);
  });

  it("says nothing about a token it does not recognise", async () => {
    // Idempotent and silent. Throwing here would turn logout into an oracle
    // for whether a guessed token is live, and would make a double click on
    // the sign out button an error the user has to read.
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(api.auth.logout, { sessionToken: "ef".repeat(32) }),
    ).resolves.toBeNull();
    await expect(
      t.mutation(api.auth.logout, { sessionToken: "" }),
    ).resolves.toBeNull();
  });

  it("is idempotent for a token it just ended", async () => {
    const t = convexTest(schema, modules);
    const token = await signIn(t);
    await t.mutation(api.auth.logout, { sessionToken: token });
    await expect(
      t.mutation(api.auth.logout, { sessionToken: token }),
    ).resolves.toBeNull();
  });
});

describe("expired sessions are pruned", () => {
  it("deletes what has expired and keeps what has not", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.mutation(api.auth.signup, signupArgs());

    await t.run(async (ctx) => {
      await insertSession(ctx, {
        userId,
        tokenHash: hashSessionToken("11".repeat(32)),
        createdAt: Date.now() - SESSION_LIFETIME_MS,
        expiresAt: Date.now() - 1,
      });
      await insertSession(ctx, {
        userId,
        tokenHash: hashSessionToken("22".repeat(32)),
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_LIFETIME_MS,
      });
    });

    const deleted = await t.mutation(internal.sessions.pruneExpiredSessions, {});

    expect(deleted).toBe(1);
    const rows = await t.run(async (ctx) => listSessionsByUser(ctx, userId));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.tokenHash).toBe(hashSessionToken("22".repeat(32)));
  });

  it("reports zero when there is nothing to prune", async () => {
    const t = convexTest(schema, modules);
    expect(
      await t.mutation(internal.sessions.pruneExpiredSessions, {}),
    ).toBe(0);
  });
});
