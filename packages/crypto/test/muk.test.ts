import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ARGON2_PARAMS, deriveMUK } from "../src/muk.js";

/**
 * Argon2id at the tuned parameters costs roughly six to eight seconds per call
 * on a warm desktop CPU, measured on this repo's target Node. Vitest's default
 * five-second budget is not survivable, so every derivation in this file runs
 * once inside a single `beforeAll` with a generous budget and the individual
 * assertions read the results.
 *
 * The timeout is raised rather than the parameters being lowered. A test suite
 * that runs against weakened parameters proves nothing about the deployed
 * derivation, and the cost of Argon2id IS the security property.
 */
const DERIVE_BUDGET_MS = 600_000;

/**
 * Pinned answer for `deriveMUK("correct horse battery staple", "u1")`.
 *
 * Computed from the SPEC of the construction -- Argon2id over the NFC-normalised
 * password with a salt of `sha256("sluice/muk-salt/v1" || userId)` at
 * m=65536 t=3 p=4 dkLen=32 -- before `src/muk.ts` existed, using a standalone
 * script, so it is an independent check and not an echo of the implementation.
 *
 * This single value pins the parameters, the salt label, the salt construction
 * and the normalisation form all at once. If any of them is ever changed, every
 * existing account's MUK changes with it and every account becomes
 * unrecoverable; this vector is the tripwire that makes that change impossible
 * to land by accident.
 */
const KAT_PASSWORD = "correct horse battery staple";
const KAT_USER_ID = "u1";
const KAT_MUK = "dfee4c58ca2653a1b5ae9a64cd3743c1cb33b26f2a6a537715f26e84cfd5b588";

/** Same glyphs, different code points. A user can type either one. */
const CAFE_NFC = "café latte";
const CAFE_NFD = "café latte";

const LONG_PASSWORD = "correct horse battery staple ".repeat(64);
const SPACED_PASSWORD = "  two  spaces   and trailing  ";
const EMOJI_PASSWORD = "\u{1F510}\u{1F5DD}\u{FE0F} unlock me";
const NON_LATIN_PASSWORD = "пароль-密码-パスワード";

describe("deriveMUK", () => {
  let kat: Uint8Array;
  let katAgain: Uint8Array;
  let otherUser: Uint8Array;
  let otherPassword: Uint8Array;
  let nfc: Uint8Array;
  let nfd: Uint8Array;
  let long: Uint8Array;
  let spaced: Uint8Array;
  let emoji: Uint8Array;
  let nonLatin: Uint8Array;

  beforeAll(async () => {
    kat = await deriveMUK(KAT_PASSWORD, KAT_USER_ID);
    katAgain = await deriveMUK(KAT_PASSWORD, KAT_USER_ID);
    otherUser = await deriveMUK(KAT_PASSWORD, "usr_0123456789abcdef");
    otherPassword = await deriveMUK("correct horse battery stapl", KAT_USER_ID);
    nfc = await deriveMUK(CAFE_NFC, KAT_USER_ID);
    nfd = await deriveMUK(CAFE_NFD, KAT_USER_ID);
    long = await deriveMUK(LONG_PASSWORD, KAT_USER_ID);
    spaced = await deriveMUK(SPACED_PASSWORD, KAT_USER_ID);
    emoji = await deriveMUK(EMOJI_PASSWORD, KAT_USER_ID);
    nonLatin = await deriveMUK(NON_LATIN_PASSWORD, KAT_USER_ID);
  }, DERIVE_BUDGET_MS);

  it("matches the pinned known-answer vector", () => {
    expect(toHex(kat)).toBe(KAT_MUK);
  });

  it("returns exactly 32 bytes", () => {
    expect(kat.length).toBe(32);
    expect(kat).toBeInstanceOf(Uint8Array);
  });

  it("is deterministic for the same password and user id", () => {
    expect(toHex(katAgain)).toBe(toHex(kat));
  });

  it("differs for a different user id with the same password", () => {
    expect(toHex(otherUser)).not.toBe(toHex(kat));
  });

  it("differs for a password one character shorter", () => {
    expect(toHex(otherPassword)).not.toBe(toHex(kat));
  });

  /**
   * The regression test for the salt. Argon2id itself refuses any salt under
   * eight bytes, so passing the user id straight through as the salt would make
   * `deriveMUK` throw for a user id like `"u1"` -- signup would crash for a real
   * account. Hashing the id to a fixed 32-byte salt is what makes short ids
   * work at all, and `kat` above is derived from exactly such an id.
   */
  it("accepts a user id far shorter than Argon2id's 8-byte salt minimum", () => {
    expect(KAT_USER_ID.length).toBeLessThan(8);
    expect(kat.length).toBe(32);
  });

  /**
   * NFC is the chosen normalisation form, per RFC 8265 OpaqueString. Without
   * it, the same password typed on a Mac and on Windows can produce different
   * MUKs and lock a user out of an account that nothing can recover.
   */
  it("normalises the password so NFC and NFD forms agree", () => {
    expect(CAFE_NFC).not.toBe(CAFE_NFD);
    expect(toHex(nfd)).toBe(toHex(nfc));
  });

  it("derives from long, spaced, emoji and non-Latin passwords", () => {
    for (const key of [long, spaced, emoji, nonLatin]) {
      expect(key.length).toBe(32);
    }
    const distinct = new Set([long, spaced, emoji, nonLatin, nfc, kat].map(toHex));
    expect(distinct.size).toBe(6);
  });
});

describe("deriveMUK input validation", () => {
  it("rejects an empty password", async () => {
    await expect(deriveMUK("", "u1")).rejects.toThrow(/password/i);
  });

  it("rejects an empty user id", async () => {
    await expect(deriveMUK("correct horse battery staple", "")).rejects.toThrow(/user ?id/i);
  });

  /**
   * Validation must happen BEFORE the seven-second grind, not after. If an
   * empty password reached Argon2id, every rejected signup attempt would cost a
   * full derivation -- a free denial-of-service against the user's own device.
   */
  it("rejects invalid input without paying for a derivation", async () => {
    const started = Date.now();
    await expect(deriveMUK("", "")).rejects.toThrow();
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe("ARGON2_PARAMS", () => {
  /**
   * A lock, not a tautology. These four numbers are the entire cost of an
   * offline guess against a stolen wrapped key bundle. Lowering any of them
   * silently weakens every account that has ever existed, and the change would
   * otherwise be a one-line diff nobody reviews twice.
   */
  it("are the tuned values and are never lowered", () => {
    expect(ARGON2_PARAMS.m).toBe(65536);
    expect(ARGON2_PARAMS.t).toBe(3);
    expect(ARGON2_PARAMS.p).toBe(4);
    expect(ARGON2_PARAMS.dkLen).toBe(32);
  });
});
