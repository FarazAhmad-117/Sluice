import { beforeAll, describe, expect, it } from "vitest";
import type { Argon2Backend } from "../src/argon2";
import { fromHex, toHex } from "../src/bytes";
import {
  ACCOUNT_SALT_BYTES,
  ARGON2_PARAMS,
  deriveMUK,
  MasterUnlockKey,
  newAccountSalt,
} from "../src/muk";

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
 * Pinned answer for `deriveMUK(KAT_PASSWORD, ACCOUNT_SALT)`.
 *
 * Computed from the SPEC of the construction, not from `src/muk.ts`: the Argon2
 * salt is `sha256(utf8("sluice/muk-salt/v2") || accountSalt)`, which for these
 * sixteen bytes is `d32869c2...6d5950f3`, fed to hash-wasm's Argon2id -- a
 * different implementation from the `@noble/hashes` default -- at m=65536 t=3
 * p=4 dkLen=32. Agreement is therefore evidence about the construction, not an
 * echo of the code under test.
 *
 * This single value pins the parameters, the salt label, the salt construction
 * and the normalisation form all at once. If any of them is ever changed, every
 * existing account's MUK changes with it and every account becomes
 * unrecoverable; this vector is the tripwire that makes that change impossible
 * to land by accident. If it ever disagrees with the implementation, the
 * implementation is what moved.
 *
 * The salt is a readable run of bytes (0x30..0x3f, ASCII "0".."?") rather than
 * random ones so the vector can be reproduced by hand from this comment.
 */
const KAT_PASSWORD = "correct horse battery staple, v2";
const ACCOUNT_SALT = fromHex("303132333435363738393a3b3c3d3e3f");
// hash-wasm Argon2id over the v2 salt; independent of @noble/hashes.
const KAT_MUK_V2 = "633977bb9b6fec724f6574028da06c834895735198e653c3f8a95cb28d70436c";

/** A second account, differing from `ACCOUNT_SALT` in its last byte only. */
const OTHER_ACCOUNT_SALT = fromHex("303132333435363738393a3b3c3d3e40");

/**
 * A backend that records whether it was ever called. `deriveMUK` runs the
 * conformance check -- which calls the backend -- before the real derivation,
 * so `called` staying false proves a rejection happened before ANY Argon2 work,
 * not merely before the expensive part. That is a structural proof; a
 * wall-clock bound would only be a guess that passes on a fast machine.
 */
function spyBackend(): { backend: Argon2Backend; wasCalled: () => boolean } {
  let called = false;
  const backend: Argon2Backend = (_pw, _s, p) => {
    called = true;
    return new Uint8Array(p.dkLen);
  };
  return { backend, wasCalled: () => called };
}

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
  let otherAccount: MasterUnlockKey;
  let otherPassword: MasterUnlockKey;
  let nfc: MasterUnlockKey;
  let nfd: MasterUnlockKey;
  let long: MasterUnlockKey;
  let spaced: MasterUnlockKey;
  let emoji: MasterUnlockKey;
  let nonLatin: MasterUnlockKey;

  beforeAll(async () => {
    kat = await deriveMUK(KAT_PASSWORD, ACCOUNT_SALT);
    katAgain = await deriveMUK(KAT_PASSWORD, ACCOUNT_SALT);
    otherAccount = await deriveMUK(KAT_PASSWORD, OTHER_ACCOUNT_SALT);
    otherPassword = await deriveMUK(KAT_PASSWORD.slice(0, -1), ACCOUNT_SALT);
    nfc = await deriveMUK(CAFE_NFC, ACCOUNT_SALT);
    nfd = await deriveMUK(CAFE_NFD, ACCOUNT_SALT);
    long = await deriveMUK(LONG_PASSWORD, ACCOUNT_SALT);
    spaced = await deriveMUK(SPACED_PASSWORD, ACCOUNT_SALT);
    emoji = await deriveMUK(EMOJI_PASSWORD, ACCOUNT_SALT);
    nonLatin = await deriveMUK(NON_LATIN_PASSWORD, ACCOUNT_SALT);
  }, DERIVE_BUDGET_MS);

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

  it("is deterministic for the same password and account salt", () => {
    expect(toHex(katAgain.bytes)).toBe(toHex(kat.bytes));
  });

  /**
   * The property the per-account salt is FOR. Two accounts that chose the same
   * password must still derive different keys, or one precomputed table of
   * common passwords would open both.
   */
  it("differs for a different account salt with the same password", () => {
    expect(toHex(otherAccount.bytes)).not.toBe(toHex(kat.bytes));
  });

  it("differs for a password one character shorter", () => {
    expect(toHex(otherPassword.bytes)).not.toBe(toHex(kat.bytes));
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
    expect(json).not.toContain(KAT_MUK_V2);
    expect(json).not.toContain(`"0":${kat.bytes[0] as number}`);
    expect(inspectLike(kat)).not.toContain(KAT_MUK_V2);
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

/**
 * Its own derivation rather than a read of `kat` above, so the vector stands
 * alone: a reader who wants to know what the frozen construction produces finds
 * the input, the output and the assertion in one place.
 */
describe("deriveMUK v2", () => {
  it("matches the independent vector", async () => {
    const muk = await deriveMUK("correct horse battery staple, v2", ACCOUNT_SALT);
    expect(toHex(muk.bytes)).toBe(KAT_MUK_V2);
  }, DERIVE_BUDGET_MS);

  it("rejects a salt of the wrong width before doing any work", async () => {
    const spy = spyBackend();
    await expect(deriveMUK("pw", new Uint8Array(15), { argon2: spy.backend })).rejects.toThrow(
      `accountSalt must be ${ACCOUNT_SALT_BYTES} bytes`,
    );
    expect(spy.wasCalled()).toBe(false);
  });

  /**
   * The old signature took a string, and every caller written against it still
   * passes one. A JavaScript caller, or a TypeScript one behind a cast, must
   * fail loudly rather than have its email flow on into the salt construction,
   * where at best it throws somewhere obscure and at worst derives a key bound
   * to the address -- exactly what this version removes.
   */
  it("rejects a string where bytes belong", async () => {
    const spy = spyBackend();
    await expect(
      deriveMUK("pw", "user@example.com" as unknown as Uint8Array, { argon2: spy.backend }),
    ).rejects.toThrow(`accountSalt must be ${ACCOUNT_SALT_BYTES} bytes`);
    expect(spy.wasCalled()).toBe(false);
  });
});

describe("newAccountSalt", () => {
  it("is 16 random bytes", () => {
    expect(newAccountSalt()).toHaveLength(16);
    expect(toHex(newAccountSalt())).not.toBe(toHex(newAccountSalt()));
  });
});

describe("deriveMUK input validation", () => {
  it("rejects an empty password", async () => {
    await expect(deriveMUK("", ACCOUNT_SALT)).rejects.toThrow(/password/i);
  });

  it("rejects an empty account salt", async () => {
    const spy = spyBackend();
    await expect(
      deriveMUK(KAT_PASSWORD, new Uint8Array(0), { argon2: spy.backend }),
    ).rejects.toThrow(`accountSalt must be ${ACCOUNT_SALT_BYTES} bytes`);
    expect(spy.wasCalled()).toBe(false);
  });

  /**
   * Validation must happen BEFORE the seven-second grind, not after. If an
   * empty password reached Argon2id, every rejected signup attempt would cost a
   * full derivation -- a free denial-of-service against the user's own device.
   * Proved with a spy rather than a stopwatch: the backend is never reached.
   */
  it("rejects invalid input without paying for a derivation", async () => {
    const spy = spyBackend();
    await expect(deriveMUK("", new Uint8Array(0), { argon2: spy.backend })).rejects.toThrow();
    expect(spy.wasCalled()).toBe(false);
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
