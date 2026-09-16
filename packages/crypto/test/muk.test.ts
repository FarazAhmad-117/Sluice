import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ARGON2_PARAMS, deriveMUK, MasterUnlockKey } from "../src/muk.js";

/**
 * Node's formatter (and therefore `console.log`) looks up exactly this symbol
 * on a value and uses its return in place of the default dump. `util.inspect`
 * itself cannot be imported here: `@types/node` is not a dependency of this
 * package. Calling the hook directly exercises the same contract `console.log`
 * would. Identical to the helper in `token.test.ts`, for the same reason.
 */
const INSPECT_CUSTOM = Symbol.for("nodejs.util.inspect.custom");

function inspectLike(value: object): string {
  const hook = (value as unknown as Record<symbol, unknown>)[INSPECT_CUSTOM];
  // Deliberately fails instead of falling back to String(value). A fallback
  // would make the redaction test pass even when the hook is missing entirely.
  if (typeof hook !== "function") throw new Error("no inspect hook: value is not redacted");
  return String((hook as () => unknown).call(value));
}

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
  let kat: MasterUnlockKey;
  let katAgain: MasterUnlockKey;
  let otherUser: MasterUnlockKey;
  let otherPassword: MasterUnlockKey;
  let nfc: MasterUnlockKey;
  let nfd: MasterUnlockKey;
  let long: MasterUnlockKey;
  let spaced: MasterUnlockKey;
  let emoji: MasterUnlockKey;
  let nonLatin: MasterUnlockKey;

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

  /**
   * The vector is UNCHANGED from before `MasterUnlockKey` existed. It reads
   * through the new accessor, which is the point: wrapping the return value must
   * not perturb a single derived byte. A change here means the derivation
   * itself moved, which orphans every account that has ever signed up.
   */
  it("matches the pinned known-answer vector", () => {
    expect(toHex(kat.bytes)).toBe(KAT_MUK);
  });

  /**
   * The wrapper is the whole point of the type. A bare `Uint8Array` return
   * would be dumped in full by `JSON.stringify`, so a regression that unwraps
   * `deriveMUK` must fail here even if every redaction test below still passes
   * against the class in isolation.
   */
  it("returns a MasterUnlockKey rather than raw bytes", () => {
    expect(kat).toBeInstanceOf(MasterUnlockKey);
    expect(kat).not.toBeInstanceOf(Uint8Array);
  });

  it("returns exactly 32 bytes", () => {
    expect(kat.bytes.length).toBe(32);
    expect(kat.bytes).toBeInstanceOf(Uint8Array);
  });

  it("is deterministic for the same password and user id", () => {
    expect(toHex(katAgain.bytes)).toBe(toHex(kat.bytes));
  });

  it("differs for a different user id with the same password", () => {
    expect(toHex(otherUser.bytes)).not.toBe(toHex(kat.bytes));
  });

  it("differs for a password one character shorter", () => {
    expect(toHex(otherPassword.bytes)).not.toBe(toHex(kat.bytes));
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
    expect(kat.bytes.length).toBe(32);
  });

  /**
   * NFC is the chosen normalisation form, per RFC 8265 OpaqueString. Without
   * it, the same password typed on a Mac and on Windows can produce different
   * MUKs and lock a user out of an account that nothing can recover.
   */
  it("normalises the password so NFC and NFD forms agree", () => {
    expect(CAFE_NFC).not.toBe(CAFE_NFD);
    expect(toHex(nfd.bytes)).toBe(toHex(nfc.bytes));
  });

  it("derives from long, spaced, emoji and non-Latin passwords", () => {
    for (const key of [long, spaced, emoji, nonLatin]) {
      expect(key.bytes.length).toBe(32);
    }
    const distinct = new Set([long, spaced, emoji, nonLatin, nfc, kat].map((k) => toHex(k.bytes)));
    expect(distinct.size).toBe(6);
  });

  /**
   * The leak this whole class exists to stop, checked on a REAL derived key
   * rather than on a hand-built instance. `logger.info({ muk })` on a bare
   * `Uint8Array` prints `{"0":223,"1":238,...}` -- the root of the key
   * hierarchy, in full, in a log aggregator.
   */
  it("does not expose a derived key through JSON.stringify", () => {
    const json = JSON.stringify({ event: "signup", muk: kat });
    expect(json).not.toContain(KAT_MUK);
    expect(json).not.toContain(`"0":${kat.bytes[0] as number}`);
    expect(inspectLike(kat)).not.toContain(KAT_MUK);
  });
});

/**
 * Redaction is a property of the CLASS, so these build an instance directly
 * instead of paying seven seconds for a derivation that would tell us nothing
 * extra. `deriveMUK` is pinned to return one of these by the instanceof test
 * above, which is what joins the two halves.
 */
describe("MasterUnlockKey", () => {
  const RAW = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
  const RAW_HEX = toHex(RAW);
  const REDACTED = "[MasterUnlockKey redacted]";

  it("exposes the raw bytes through an explicitly named accessor", () => {
    const muk = new MasterUnlockKey(RAW);
    expect(toHex(muk.bytes)).toBe(RAW_HEX);
    expect(muk.bytes.length).toBe(32);
    expect(muk.bytes).toBeInstanceOf(Uint8Array);
  });

  it("rejects anything that is not a 32-byte key", () => {
    expect(() => new MasterUnlockKey(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => new MasterUnlockKey(new Uint8Array(33))).toThrow(/32 bytes/);
    expect(() => new MasterUnlockKey(new Uint8Array(0))).toThrow(/32 bytes/);
  });

  it("redacts the key in JSON.stringify", () => {
    const json = JSON.stringify(new MasterUnlockKey(RAW));
    expect(json).not.toContain(RAW_HEX);
    expect(json).toContain(REDACTED);
  });

  it("redacts the key when nested inside a logged object", () => {
    const json = JSON.stringify({ event: "unlock", muk: new MasterUnlockKey(RAW) });
    expect(json).not.toContain(RAW_HEX);
    // The byte-index dump a bare Uint8Array would produce, checked directly
    // rather than trusting that the hex form is the only way to leak.
    expect(json).not.toContain(`"0":${RAW[0] as number}`);
    expect(json).not.toContain("bytes");
    expect(json).toContain(REDACTED);
  });

  it("redacts the key in the console.log inspect hook", () => {
    expect(inspectLike(new MasterUnlockKey(RAW))).toBe(REDACTED);
  });

  /**
   * Pins the documented limit of the protection, so the doc comment on the
   * class cannot drift away from what the code actually does.
   *
   * The bytes live in a `#private` field, so a spread or a `structuredClone`
   * does not carry them: the copy is EMPTY, not leaky. That is the safe
   * direction, but it is still a trap -- the copy silently has no key at all --
   * so the rule for callers is the same as for `MintedToken`: pass the
   * instance, never a spread or a copy.
   */
  it("is emptied rather than leaked by a spread or a structured clone", () => {
    const muk = new MasterUnlockKey(RAW);
    const spread = { ...muk };
    expect(Object.keys(spread)).toEqual([]);
    expect(JSON.stringify(spread)).not.toContain(RAW_HEX);
    expect(JSON.stringify(structuredClone(muk))).not.toContain(RAW_HEX);
  });

  /**
   * The one way the key still reaches a log, stated as a test so it is not a
   * surprise: `.bytes` is a raw `Uint8Array` and carries no redaction. Reaching
   * for the accessor must stay a deliberate, greppable act.
   */
  it("does not protect bytes a caller has already unwrapped", () => {
    const muk = new MasterUnlockKey(RAW);
    expect(JSON.stringify({ muk: muk.bytes })).toContain(`"0":${RAW[0] as number}`);
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
