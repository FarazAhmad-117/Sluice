import { afterEach, describe, expect, it } from "vitest";
import { hashAuthVerifier } from "./verifier";

const VERIFIER_A =
  "3f2a91c0d4b7e65a18cc0fd3b2a94e7710f5c86d2b41a9e3c7d508f6b1a2c3d4";
const VERIFIER_B =
  "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

const PEPPER_ONE =
  "1000000000000000000000000000000000000000000000000000000000000001";
const PEPPER_TWO =
  "2000000000000000000000000000000000000000000000000000000000000002";

/**
 * Written against `process.env` directly rather than through `vi.stubEnv`,
 * because the deployment reads `process.env.AUTH_PEPPER` and a test that
 * proves a stub works proves nothing about the deployment.
 */
function withPepper<T>(pepper: string | undefined, fn: () => T): T {
  const previous = process.env.AUTH_PEPPER;
  if (pepper === undefined) delete process.env.AUTH_PEPPER;
  else process.env.AUTH_PEPPER = pepper;
  try {
    return fn();
  } finally {
    if (previous === undefined) delete process.env.AUTH_PEPPER;
    else process.env.AUTH_PEPPER = previous;
  }
}

afterEach(() => {
  delete process.env.AUTH_PEPPER;
});

describe("hashAuthVerifier", () => {
  it("is deterministic for one verifier under one pepper", () => {
    const first = withPepper(PEPPER_ONE, () => hashAuthVerifier(VERIFIER_A));
    const second = withPepper(PEPPER_ONE, () => hashAuthVerifier(VERIFIER_A));
    expect(first).toBe(second);
  });

  it("differs for a different verifier", () => {
    const a = withPepper(PEPPER_ONE, () => hashAuthVerifier(VERIFIER_A));
    const b = withPepper(PEPPER_ONE, () => hashAuthVerifier(VERIFIER_B));
    expect(a).not.toBe(b);
  });

  // The whole point of the pepper. If this passes with the pepper ignored,
  // a database dump is enough to test guesses offline.
  it("differs for a different pepper", () => {
    const one = withPepper(PEPPER_ONE, () => hashAuthVerifier(VERIFIER_A));
    const two = withPepper(PEPPER_TWO, () => hashAuthVerifier(VERIFIER_A));
    expect(one).not.toBe(two);
  });

  it("is not the verifier", () => {
    const hash = withPepper(PEPPER_ONE, () => hashAuthVerifier(VERIFIER_A));
    expect(hash).not.toBe(VERIFIER_A);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  // A missing pepper must not degrade to hashing without one. Silent
  // degradation here is invisible: signup succeeds, login succeeds, and the
  // stored hashes are simply worth less than everyone believes.
  it("throws when AUTH_PEPPER is unset", () => {
    expect(() => withPepper(undefined, () => hashAuthVerifier(VERIFIER_A))).toThrow(
      "AUTH_PEPPER is not set on this deployment.",
    );
  });

  it("throws when AUTH_PEPPER is empty", () => {
    expect(() => withPepper("", () => hashAuthVerifier(VERIFIER_A))).toThrow(
      "AUTH_PEPPER is not set on this deployment.",
    );
  });

  it("throws when AUTH_PEPPER is not 64 lowercase hex characters", () => {
    expect(() => withPepper("changeme", () => hashAuthVerifier(VERIFIER_A))).toThrow(
      "AUTH_PEPPER must be 64 lowercase hex characters.",
    );
  });

  it("never puts the pepper or the verifier in the error it throws", () => {
    for (const pepper of ["changeme", undefined]) {
      let message = "";
      try {
        withPepper(pepper, () => hashAuthVerifier(VERIFIER_A));
      } catch (error) {
        message = String((error as { data?: string }).data ?? error);
      }
      expect(message).not.toContain(VERIFIER_A);
      expect(message).not.toContain("changeme");
    }
  });
});
