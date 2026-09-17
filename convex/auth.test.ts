import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api } from "./_generated/api";
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

const PUBLIC_KEY =
  "1111111111111111111111111111111111111111111111111111111111111111";
const VERIFY_KEY =
  "2222222222222222222222222222222222222222222222222222222222222222";

function signupArgs(overrides: Record<string, unknown> = {}) {
  return {
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

  it("rejects an email that is blank once trimmed", async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(api.auth.signup, signupArgs({ email: "   " })),
    ).rejects.toThrow("email must be between 1 and 254 characters.");
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
