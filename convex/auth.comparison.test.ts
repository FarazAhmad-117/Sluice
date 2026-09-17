import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api } from "./_generated/api";

/**
 * This file exists only to prove that login compares with `constantTimeEqual`
 * from `@sluice/crypto` and not with `===`. It is separate from `auth.test.ts`
 * because `vi.mock` is hoisted to the top of a file and applies to every test
 * in it, and the rest of the auth suite should exercise the real package.
 *
 * The assertion is behavioural rather than a grep over the source. A grep
 * would pass against an implementation that imported the function, compared
 * with `===` anyway, and called it on a value nobody looked at.
 */
vi.mock("@sluice/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@sluice/crypto")>();
  return { ...actual, constantTimeEqual: vi.fn(actual.constantTimeEqual) };
});

const { constantTimeEqual } = await import("@sluice/crypto");
const spy = vi.mocked(constantTimeEqual);

export const modules = import.meta.glob("./**/*.ts");

const VERIFIER_A =
  "3f2a91c0d4b7e65a18cc0fd3b2a94e7710f5c86d2b41a9e3c7d508f6b1a2c3d4";
const VERIFIER_B =
  "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

const signupArgs = {
  email: "ada@example.test",
  authVerifier: VERIFIER_A,
  publicKey:
    "1111111111111111111111111111111111111111111111111111111111111111",
  verifyKey: "2222222222222222222222222222222222222222222222222222222222222222",
  wrappedPrivateKey: "wrapped-private-key-blob",
  wrappedSigningKey: "wrapped-signing-key-blob",
};

beforeEach(() => {
  process.env.AUTH_PEPPER =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
  spy.mockClear();
});

afterEach(() => {
  delete process.env.AUTH_PEPPER;
});

describe("login comparison", () => {
  it("compares the stored hash with constantTimeEqual", async () => {
    const t = convexTest(schema, modules);
    await t.mutation(api.auth.signup, signupArgs);
    spy.mockClear();

    await t.mutation(api.auth.login, {
      email: "ada@example.test",
      authVerifier: VERIFIER_A,
    });

    expect(spy).toHaveBeenCalledTimes(1);
    const call = spy.mock.calls[0];
    expect(call?.[0]).toBeInstanceOf(Uint8Array);
    expect(call?.[1]).toBeInstanceOf(Uint8Array);
    // 32 bytes each, which is the digest width. Comparing hex strings would
    // work and would also be a comparison over text whose length leaks nothing
    // but whose equality check is easy to write with `===` by accident.
    expect(call?.[0]?.length).toBe(32);
    expect(call?.[1]?.length).toBe(32);
  });

  it("compares even when no account exists, so the work is the same", async () => {
    const t = convexTest(schema, modules);

    await expect(
      t.mutation(api.auth.login, {
        email: "nobody@example.test",
        authVerifier: VERIFIER_B,
      }),
    ).rejects.toThrow();

    expect(spy).toHaveBeenCalledTimes(1);
  });
});
