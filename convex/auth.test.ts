import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api } from "./_generated/api";
import { newId } from "@sluice/crypto";
import { normaliseEmail } from "./lib/email";
import { getUserByEmail, insertUser } from "./repo/users";

export const modules = import.meta.glob("./**/*.ts");

// A full-entropy 256-bit value in canonical lowercase hex, which is exactly
// what the client uploads. Written out rather than generated so a failure
// names a constant instead of a value that changes every run.
const VERIFIER_A =
  "3f2a91c0d4b7e65a18cc0fd3b2a94e7710f5c86d2b41a9e3c7d508f6b1a2c3d4";
const VERIFIER_B =
  "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

// A throwaway pepper for the suite. Set on `process.env` directly, because
// that is what the deployment reads; a test that proved a mock worked would
// prove nothing about the deployment.
const TEST_PEPPER =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

beforeEach(() => {
  process.env.AUTH_PEPPER = TEST_PEPPER;
});

afterEach(() => {
  delete process.env.AUTH_PEPPER;
});

const PUBLIC_KEY =
  "1111111111111111111111111111111111111111111111111111111111111111";
const VERIFY_KEY =
  "2222222222222222222222222222222222222222222222222222222222222222";

// Fixed rather than minted per call so a test that signs up twice with the
// same arguments collides on BOTH the address and the uid, and the duplicate
// email test keeps pinning the email message: the email check runs first.
const USER_UID = "usr_" + "0123456789abcdef".repeat(2);
// 16 bytes, lowercase hex: the shape `newAccountSalt` produces once encoded.
const ACCOUNT_SALT = "5a".repeat(16);

function signupArgs(overrides: Record<string, unknown> = {}) {
  return {
    uid: USER_UID,
    accountSalt: ACCOUNT_SALT,
    email: "ada@example.test",
    authVerifier: VERIFIER_A,
    publicKey: PUBLIC_KEY,
    verifyKey: VERIFY_KEY,
    wrappedPrivateKey: "wrapped-private-key-blob",
    wrappedSigningKey: "wrapped-signing-key-blob",
    ...overrides,
  };
}

describe("signup", () => {
  it("creates a user for a new email and returns its id", async () => {
    const t = convexTest(schema, modules);

    const userId = await t.mutation(api.auth.signup, signupArgs());

    expect(userId).toBeTruthy();
    const stored = await t.run(async (ctx) =>
      getUserByEmail(ctx, normaliseEmail("ada@example.test")),
    );
    expect(stored?._id).toBe(userId);
  });

  it("rejects a duplicate email", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.auth.signup, signupArgs());

    await expect(
      t.mutation(api.auth.signup, signupArgs({ authVerifier: VERIFIER_B })),
    ).rejects.toThrow("An account already exists for that email.");
  });

  // `by_email` is an exact-match index. Case-insensitive identity that is not
  // normalised on write is not enforced by anything, so this asserts the
  // normalisation itself and not just the symptom.
  it("treats a case variant as the same account", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.auth.signup, signupArgs({ email: "Ada@Example.TEST" }));

    await expect(
      t.mutation(api.auth.signup, signupArgs({ email: "ada@example.test" })),
    ).rejects.toThrow("An account already exists for that email.");
  });

  it("stores the email lowercased and trimmed", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(
      api.auth.signup,
      signupArgs({ email: "  Ada@Example.TEST \t" }),
    );

    const stored = await t.run(async (ctx) =>
      getUserByEmail(ctx, normaliseEmail("ada@example.test")),
    );
    expect(stored?.email).toBe("ada@example.test");
  });

  it("stores no value equal to the submitted verifier", async () => {
    const t = convexTest(schema, modules);

    await t.mutation(api.auth.signup, signupArgs());

    const stored = await t.run(async (ctx) =>
      getUserByEmail(ctx, normaliseEmail("ada@example.test")),
    );
    expect(stored).not.toBeNull();
    expect(Object.values(stored as Record<string, unknown>)).not.toContain(
      VERIFIER_A,
    );
  });

  // The canonical-hex rule `@sluice/crypto` enforces on every other
  // identifier. Uppercase is rejected rather than accepted and lowercased,
  // because two spellings of one value that both hash to different strings is
  // the canonicalisation bug this rule exists to prevent.
  describe("rejects a verifier that is not 64 lowercase hex characters", () => {
    const message = "authVerifier must be 64 lowercase hex characters.";
    const cases: Array<[string, string]> = [
      ["uppercase", VERIFIER_A.toUpperCase()],
      ["mixed case", "3F2a91c0d4b7e65a18cc0fd3b2a94e7710f5c86d2b41a9e3c7d508f6b1a2c3d4"],
      ["too short", VERIFIER_A.slice(0, 63)],
      ["too long", VERIFIER_A + "0"],
      ["non hex", VERIFIER_A.slice(0, 63) + "z"],
      ["empty", ""],
      ["hex with 0x prefix", "0x" + VERIFIER_A.slice(2)],
      ["whitespace padded", ` ${VERIFIER_A} `],
    ];

    for (const [name, value] of cases) {
      it(name, async () => {
        const t = convexTest(schema, modules);
        await expect(
          t.mutation(api.auth.signup, signupArgs({ authVerifier: value })),
        ).rejects.toThrow(message);
      });
    }
  });

  it("rejects a public key that is not 64 lowercase hex characters", async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(api.auth.signup, signupArgs({ publicKey: "not-hex" })),
    ).rejects.toThrow("publicKey must be 64 lowercase hex characters.");
  });

  it("rejects a verify key that is not 64 lowercase hex characters", async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(api.auth.signup, signupArgs({ verifyKey: "" })),
    ).rejects.toThrow("verifyKey must be 64 lowercase hex characters.");
  });

  it("rejects an email that is not shaped like an address", async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(api.auth.signup, signupArgs({ email: "ada at example.test" })),
    ).rejects.toThrow("email must be a single address with no spaces.");
  });

  // A deployment without a pepper must refuse to create accounts rather than
  // create ones whose stored hash is worth less than everybody believes.
  it("refuses to run at all when AUTH_PEPPER is unset", async () => {
    const t = convexTest(schema, modules);
    delete process.env.AUTH_PEPPER;

    await expect(t.mutation(api.auth.signup, signupArgs())).rejects.toThrow(
      "AUTH_PEPPER is not set on this deployment.",
    );

    // And it wrote nothing on the way out.
    process.env.AUTH_PEPPER = TEST_PEPPER;
    const stored = await t.run(async (ctx) =>
      getUserByEmail(ctx, normaliseEmail("ada@example.test")),
    );
    expect(stored).toBeNull();
  });

  it("rejects an email that is blank once trimmed", async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(api.auth.signup, signupArgs({ email: "   " })),
    ).rejects.toThrow("email must be between 1 and 254 characters.");
  });

  it("stores the uid and the account salt it was given", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const stored = await t.run(async (ctx) =>
      getUserByEmail(ctx, normaliseEmail("ada@example.test")),
    );
    expect(stored?.uid).toBe(USER_UID);
    expect(stored?.accountSalt).toBe(ACCOUNT_SALT);
  });

  // The uid goes into associated data on the client, so a malformed one is
  // refused here rather than stored and discovered when a wrap fails to open.
  // A Convex document id is the case that matters most: it is the thing the
  // permanent id exists to keep out of bindings.
  describe("rejects a uid that is not a well-formed usr id", () => {
    const message = "uid must be a well-formed usr id";
    const cases: Array<[string, string]> = [
      ["empty", ""],
      ["an org id", newId("org")],
      ["an env id", newId("env")],
      ["uppercase hex", "usr_" + "0123456789ABCDEF".repeat(2)],
      ["too short", USER_UID.slice(0, -1)],
      ["too long", USER_UID + "0"],
      ["trailing newline", USER_UID + "\n"],
      ["no prefix", "0123456789abcdef".repeat(2)],
    ];

    for (const [name, value] of cases) {
      it(name, async () => {
        const t = convexTest(schema, modules);
        await expect(
          t.mutation(api.auth.signup, signupArgs({ uid: value })),
        ).rejects.toThrow(message);
      });
    }

    it("missing", async () => {
      const t = convexTest(schema, modules);
      const { uid: _omitted, ...rest } = signupArgs();
      await expect(
        t.mutation(api.auth.signup, rest as ReturnType<typeof signupArgs>),
      ).rejects.toThrow();
    });
  });

  // Exactly 16 bytes, because that is what the client's width check accepts
  // before it spends an Argon2 run. A salt stored at any other width would be
  // an account nobody can log in to.
  describe("rejects an account salt that is not 16 bytes of lowercase hex", () => {
    const message = "accountSalt must be 32 lowercase hex characters.";
    const cases: Array<[string, string]> = [
      ["empty", ""],
      ["15 bytes", "5a".repeat(15)],
      ["17 bytes", "5a".repeat(17)],
      ["32 bytes", "5a".repeat(32)],
      ["uppercase", "5A".repeat(16)],
      ["non hex", "5a".repeat(15) + "zz"],
      ["odd length", "5a".repeat(16).slice(1)],
    ];

    for (const [name, value] of cases) {
      it(name, async () => {
        const t = convexTest(schema, modules);
        await expect(
          t.mutation(api.auth.signup, signupArgs({ accountSalt: value })),
        ).rejects.toThrow(message);
      });
    }

    it("missing", async () => {
      const t = convexTest(schema, modules);
      const { accountSalt: _omitted, ...rest } = signupArgs();
      await expect(
        t.mutation(api.auth.signup, rest as ReturnType<typeof signupArgs>),
      ).rejects.toThrow();
    });
  });

  // The uid is client-chosen, so its entropy is no defence against a client
  // that copies another account's uid on purpose. Uniqueness is enforced here.
  it("rejects a second account with the same uid", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    await expect(
      t.mutation(
        api.auth.signup,
        signupArgs({ email: "grace@example.test", authVerifier: VERIFIER_B }),
      ),
    ).rejects.toThrow("An account already exists with that uid.");

    // And the second address was not created.
    const second = await t.run(async (ctx) =>
      getUserByEmail(ctx, normaliseEmail("grace@example.test")),
    );
    expect(second).toBeNull();
  });
});

describe("getLoginSalt", () => {
  it("returns the stored salt for a known address", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const result = await t.query(api.auth.getLoginSalt, {
      email: "  ADA@Example.test ",
    });
    expect(result).toEqual({ accountSalt: ACCOUNT_SALT });
  });

  // An unknown address gets an answer of the same shape and width, stable
  // across calls, so a client cannot tell it from a real salt by looking at
  // it and an automated prober cannot tell it by asking twice.
  it("returns a stable 16 byte decoy for an unknown address", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const first = await t.query(api.auth.getLoginSalt, {
      email: "nobody@example.test",
    });
    const second = await t.query(api.auth.getLoginSalt, {
      email: "Nobody@Example.test",
    });

    expect(first.accountSalt).toMatch(/^[0-9a-f]{32}$/);
    expect(second).toEqual(first);
    expect(first.accountSalt).not.toBe(ACCOUNT_SALT);

    const other = await t.query(api.auth.getLoginSalt, {
      email: "someone-else@example.test",
    });
    expect(other.accountSalt).not.toBe(first.accountSalt);
  });

  it("fails loudly when AUTH_PEPPER is unset, even for a known address", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());
    delete process.env.AUTH_PEPPER;

    await expect(
      t.query(api.auth.getLoginSalt, { email: "ada@example.test" }),
    ).rejects.toThrow("AUTH_PEPPER is not set on this deployment.");
  });
});

describe("email identity", () => {
  // `getUserByEmail` uses `.unique()`, which throws when two rows match. For
  // an auth table that is the right failure mode: silently picking one of two
  // accounts that share an identity is how the wrong person gets logged in.
  // The repo layer carries no uniqueness policy, so two rows are reachable if
  // a future writer skips the check, and this pins what happens next.
  it("refuses to resolve an email that matches two rows", async () => {
    const t = convexTest(schema, modules);
    const email = normaliseEmail("twin@example.test");

    await t.run(async (ctx) => {
      for (const suffix of ["a", "b"]) {
        await insertUser(ctx, {
          uid: newId("usr"),
          accountSalt: ACCOUNT_SALT,
          email,
          authVerifierHash: `hash-${suffix}`,
          publicKey: PUBLIC_KEY,
          verifyKey: VERIFY_KEY,
          wrappedPrivateKey: "blob",
          wrappedSigningKey: "blob",
        });
      }
    });

    await expect(
      t.run(async (ctx) => getUserByEmail(ctx, email)),
    ).rejects.toThrow();
  });
});

/**
 * The failure message is a single constant shared by every way login can go
 * wrong, and these tests exist to keep it that way. An error that says "no
 * such account" is an account enumeration oracle: anyone can ask this server
 * whether an address has signed up, one request at a time.
 */
const AUTH_FAILED = "Invalid email or verifier.";

async function captureFailure(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected the login to fail, and it did not");
}

describe("login", () => {
  it("returns the wrapped blobs for a correct verifier", async () => {
    const t = convexTest(schema, modules);
    const userId = await t.mutation(
      api.auth.signup,
      signupArgs({ recoveryBlob: "recovery-blob" }),
    );

    const result = await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER_A,
    });

    // Still an exact key set rather than a subset match: the point of this
    // assertion is that login returns these fields AND NO OTHERS, so a leak
    // added later shows up here. The two session fields are matched by type
    // because the token is random by construction; `session.test.ts` pins what
    // they have to be.
    expect(result).toEqual({
      sessionToken: expect.stringMatching(/^[0-9a-f]{64}$/),
      sessionExpiresAt: expect.any(Number),
      userId,
      userUid: USER_UID,
      publicKey: PUBLIC_KEY,
      verifyKey: VERIFY_KEY,
      wrappedPrivateKey: "wrapped-private-key-blob",
      wrappedSigningKey: "wrapped-signing-key-blob",
      recoveryBlob: "recovery-blob",
    });
  });

  it("returns nothing derived from the verifier", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const result = (await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER_A,
    })) as Record<string, unknown>;

    expect(Object.keys(result)).not.toContain("authVerifierHash");
    expect(Object.values(result)).not.toContain(VERIFIER_A);
  });

  it("accepts a case variant of the email", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const result = await t.mutation(api.auth.login, {
      email: "  ADA@Example.test ",
      authVerifier: VERIFIER_A,
    });

    expect(result).toBeTruthy();
  });

  it("rejects a wrong verifier", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    await expect(
      t.mutation(api.auth.login, {
        email: "ada@example.test",
        authVerifier: VERIFIER_B,
      }),
    ).rejects.toThrow(AUTH_FAILED);
  });

  // The important one. Not "both fail" but "both fail with the same bytes".
  it("fails identically for a wrong verifier and an unknown email", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    const wrongVerifier = await captureFailure(
      t.mutation(api.auth.login, {
        email: "ada@example.test",
        authVerifier: VERIFIER_B,
      }),
    );
    const unknownEmail = await captureFailure(
      t.mutation(api.auth.login, {
        email: "nobody@example.test",
        authVerifier: VERIFIER_A,
      }),
    );

    const shape = (error: unknown) => ({
      name: (error as Error).name,
      message: (error as Error).message,
      data: (error as { data?: unknown }).data,
    });

    expect(shape(wrongVerifier)).toEqual(shape(unknownEmail));
    expect(shape(wrongVerifier).data).toBe(AUTH_FAILED);
    expect(JSON.stringify(shape(wrongVerifier))).toBe(
      JSON.stringify(shape(unknownEmail)),
    );
  });

  // A malformed address and a malformed verifier are the other two ways a
  // caller could probe the shape of this endpoint, so they answer the same
  // way. Nothing legitimate sends either.
  it("fails identically for a malformed email and a malformed verifier", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());

    for (const args of [
      { email: "not an address", authVerifier: VERIFIER_A },
      { email: "ada@example.test", authVerifier: "nope" },
      { email: "ada@example.test", authVerifier: VERIFIER_A.toUpperCase() },
      { email: "", authVerifier: VERIFIER_A },
    ]) {
      const error = await captureFailure(t.mutation(api.auth.login, args));
      expect((error as { data?: unknown }).data).toBe(AUTH_FAILED);
    }
  });

  // Misconfiguration is the one thing login must NOT hide behind the generic
  // failure, because a deployment with no pepper would otherwise look exactly
  // like every password on earth being wrong.
  it("fails loudly and distinguishably when AUTH_PEPPER is unset", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs());
    delete process.env.AUTH_PEPPER;

    await expect(
      t.mutation(api.auth.login, {
        email: "ada@example.test",
        authVerifier: VERIFIER_A,
      }),
    ).rejects.toThrow("AUTH_PEPPER is not set on this deployment.");
  });
});
