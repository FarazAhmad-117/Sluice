import { describe, expect, it } from "vitest";
import {
  MIN_PASSWORD_BITS,
  MIN_PASSWORD_LENGTH,
  assessPassword,
} from "../src/lib/auth/password";

/**
 * THE STRENGTH GATE IS A SECURITY CONTROL, SO ITS BOUNDARIES ARE PINNED.
 *
 * These tests exist to stop the rule being loosened by accident. The salt is
 * derived from a public email address, so the password is the only entropy in
 * the master unlock key, and an edit that drops the floor from 60 bits to 40
 * weakens every account created afterwards with no other visible symptom.
 *
 * They also pin what the estimator CANNOT do, because a test suite that only
 * shows the happy cases makes the estimator look better than it is.
 */
describe("assessPassword", () => {
  it("rejects anything shorter than the minimum, however varied", () => {
    // 11 characters across all four classes. Varied, and still too short.
    const result = assessPassword("aA1!bB2@cC3");
    expect(result.acceptable).toBe(false);
    expect(result.problems.some((problem) => problem.includes(String(MIN_PASSWORD_LENGTH)))).toBe(
      true,
    );
  });

  it("rejects a long password made of one repeated character", () => {
    // Twenty characters, so length alone would pass. The repeat penalty is
    // what catches it, which is the whole reason effective length exists.
    const result = assessPassword("aaaaaaaaaaaaaaaaaaaa");
    expect(result.acceptable).toBe(false);
    expect(result.bits).toBeLessThan(MIN_PASSWORD_BITS);
  });

  it("rejects a straight alphabet run", () => {
    const result = assessPassword("abcdefghijklmnop");
    expect(result.acceptable).toBe(false);
  });

  it("rejects blocklisted passwords even with digits stuck on the end", () => {
    // Long enough and varied enough to clear the entropy bar on its own, which
    // is exactly why the blocklist has to run independently of the estimate.
    const result = assessPassword("correcthorsebatterystaple99");
    expect(result.acceptable).toBe(false);
    expect(result.problems.join(" ")).toContain("commonly chosen");
  });

  it("rejects a password containing the account's own email local part", () => {
    const result = assessPassword("faraz-quiet-harbour-lamp", "faraz@example.com");
    expect(result.acceptable).toBe(false);
    expect(result.problems.join(" ")).toContain("email address");
  });

  it('rejects a password containing "sluice"', () => {
    const result = assessPassword("sluice-quiet-harbour-lamp");
    expect(result.acceptable).toBe(false);
  });

  it("accepts an ordinary four word passphrase", () => {
    const result = assessPassword("quiet harbour lamp thistle");
    expect(result.acceptable).toBe(true);
    expect(result.bits).toBeGreaterThanOrEqual(MIN_PASSWORD_BITS);
  });

  it("accepts a mixed-class password at the length floor", () => {
    const result = assessPassword("Tr0ub4dor&3x");
    expect(result.acceptable).toBe(true);
  });

  it("scores the NFC form, because that is what Argon2id receives", () => {
    // "e" plus a combining acute accent, versus the single precomposed
    // codepoint. `deriveMUK` normalises to NFC before hashing, so the two must
    // score identically or the meter is measuring a string that never reaches
    // the key.
    const decomposed = "café quiet harbour lamp";
    const composed = "café quiet harbour lamp";
    expect(assessPassword(decomposed).bits).toBeCloseTo(assessPassword(composed).bits, 10);
  });

  it("reports empty rather than unusable for an empty field", () => {
    const result = assessPassword("");
    expect(result.verdict).toBe("empty");
    expect(result.problems).toHaveLength(0);
    expect(result.acceptable).toBe(false);
  });

  /**
   * THE KNOWN HOLE, PINNED SO NOBODY DISCOVERS IT BY TRUSTING THE METER.
   *
   * There is no dictionary behind this estimate, so a repeated English word
   * with punctuation passes. It is documented in `password.ts` and it is the
   * reason the interface says "estimated" and never promises safety.
   */
  it("does not catch a dictionary phrase, and this is a known limit", () => {
    expect(assessPassword("Thermostat-Thermostat-19").acceptable).toBe(true);
  });
});
