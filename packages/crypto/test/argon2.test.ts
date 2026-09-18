import { describe, expect, it } from "vitest";
import { argon2id } from "@noble/hashes/argon2";
import { assertConformantArgon2 } from "../src/argon2";
import type { Argon2Backend } from "../src/argon2";
import { toHex, utf8 } from "../src/bytes";
import { ARGON2_PARAMS, deriveMUK } from "../src/muk";

/**
 * THE GUARDS ON THE INJECTION SEAM.
 *
 * `deriveMUK` now accepts an Argon2 implementation from outside the package.
 * That is a hole cut into the single most security-critical function in the
 * system, and these tests are the argument that the hole is survivable. Each
 * one stands in for a real mistake someone will make:
 *
 * - `argon2i` imported instead of `argon2id` (one character).
 * - `memorySize` in bytes rather than KiB (a units mismatch between libraries).
 * - a library defaulting to hex output, read back as if it were bytes.
 * - an options key misspelled, so the library silently uses ITS defaults.
 * - a stub or mock left wired in.
 *
 * Every one of those produces a DIFFERENT MUK. Without these guards the first
 * symptom is a user who cannot open their own account and cannot be helped,
 * because nothing on the server can recover the key.
 *
 * These run in milliseconds because every backend here is a fake. The only
 * expensive test in this file is the one that proves a *correct* alternative
 * backend reproduces the pinned vector, and that one is worth its seconds.
 */

/** Same vector as `muk.test.ts`. Restated, not imported, so a change to either file is a failing test rather than a silent edit propagated to both. */
const KAT_PASSWORD = "correct horse battery staple";
const KAT_USER_ID = "u1";
const KAT_MUK = "dfee4c58ca2653a1b5ae9a64cd3743c1cb33b26f2a6a537715f26e84cfd5b588";

const DERIVE_BUDGET_MS = 600_000;

describe("assertConformantArgon2", () => {
  it("accepts a correct Argon2id implementation", async () => {
    const backend: Argon2Backend = (pw, salt, p) =>
      argon2id(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    await expect(assertConformantArgon2(backend)).resolves.toBeUndefined();
  });

  /**
   * The units bug, which is the one a real integration hits. `hash-wasm` takes
   * `memorySize` in KiB and so does noble's `m`; a library that took bytes, or
   * a call that multiplied by 1024 "to be safe", lands here.
   */
  it("rejects a backend that ignores the memory parameter", async () => {
    const backend: Argon2Backend = (pw, salt, p) =>
      argon2id(pw, salt, { m: 256, t: p.t, p: p.p, dkLen: p.dkLen });
    await expect(assertConformantArgon2(backend)).rejects.toThrow(/conformance/i);
  });

  it("rejects a backend that ignores the iteration parameter", async () => {
    const backend: Argon2Backend = (pw, salt, p) =>
      argon2id(pw, salt, { m: p.m, t: 4, p: p.p, dkLen: p.dkLen });
    await expect(assertConformantArgon2(backend)).rejects.toThrow(/conformance/i);
  });

  /**
   * THE REASON THERE ARE TWO VECTORS. A backend that hardcodes the settings the
   * first vector happens to use passes any single-vector check. This one
   * answers vector A perfectly and vector B wrongly.
   */
  it("rejects a backend that hardcodes one parameter set instead of reading its argument", async () => {
    const backend: Argon2Backend = (pw, salt, p) =>
      argon2id(pw, salt, { m: 64, t: 1, p: 1, dkLen: p.dkLen });
    await expect(assertConformantArgon2(backend)).rejects.toThrow(/conformance/i);
  });

  it("rejects a backend returning a string instead of bytes", async () => {
    // `hash-wasm` returns hex unless told `outputType: "binary"`, so this is
    // the default-shaped mistake rather than a contrived one.
    const backend = ((pw: Uint8Array, salt: Uint8Array, p: { dkLen: number }) =>
      toHex(argon2id(pw, salt, { m: 64, t: 1, p: 1, dkLen: p.dkLen }))) as unknown as Argon2Backend;
    await expect(assertConformantArgon2(backend)).rejects.toThrow(/Uint8Array/);
  });

  it("rejects a backend returning the wrong number of bytes", async () => {
    const backend: Argon2Backend = (_pw, _salt, p) => new Uint8Array(p.dkLen - 1);
    await expect(assertConformantArgon2(backend)).rejects.toThrow(/bytes/);
  });

  it("rejects a backend that is not Argon2 at all", async () => {
    const backend: Argon2Backend = (_pw, _salt, p) => new Uint8Array(p.dkLen).fill(7);
    await expect(assertConformantArgon2(backend)).rejects.toThrow(/conformance/i);
  });

  /**
   * The check costs real work, so it must not be paid on every derivation, and
   * a failed backend must not get a second chance on the next call: caching the
   * rejection is what stops a flaky wrapper from eventually slipping a wrong
   * key through.
   */
  it("runs the check once per backend and caches both outcomes", async () => {
    let calls = 0;
    const good: Argon2Backend = (pw, salt, p) => {
      calls++;
      return argon2id(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    };
    await assertConformantArgon2(good);
    const afterFirst = calls;
    await assertConformantArgon2(good);
    expect(calls).toBe(afterFirst);

    let badCalls = 0;
    const bad: Argon2Backend = (_pw, _salt, p) => {
      badCalls++;
      return new Uint8Array(p.dkLen);
    };
    await expect(assertConformantArgon2(bad)).rejects.toThrow();
    const badAfterFirst = badCalls;
    await expect(assertConformantArgon2(bad)).rejects.toThrow();
    expect(badCalls).toBe(badAfterFirst);
  });

  it("shares one check between concurrent first calls rather than racing two", async () => {
    let calls = 0;
    const backend: Argon2Backend = (pw, salt, p) => {
      calls++;
      return argon2id(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    };
    await Promise.all([assertConformantArgon2(backend), assertConformantArgon2(backend)]);
    expect(calls).toBe(2); // two vectors, one pass -- not four.
  });
});

describe("deriveMUK backend injection", () => {
  it("refuses to derive with a non-conformant backend", async () => {
    const backend: Argon2Backend = (_pw, _salt, p) => new Uint8Array(p.dkLen).fill(7);
    await expect(deriveMUK(KAT_PASSWORD, KAT_USER_ID, { argon2: backend })).rejects.toThrow(
      /conformance/i,
    );
  });

  /**
   * THE FAILURE MODE THIS WHOLE FILE EXISTS FOR, MADE CONCRETE. `argon2i` is
   * one character away from `argon2id`, is a real function in every Argon2
   * library, runs without error, and returns 32 plausible bytes. It is a
   * different KDF. A user who signed up through it could never log in through
   * the correct one, and nothing on the server could tell which they got.
   */
  it("refuses a backend that is argon2i rather than argon2id", async () => {
    const { argon2i } = await import("@noble/hashes/argon2");
    const backend: Argon2Backend = (pw, salt, p) =>
      argon2i(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    await expect(deriveMUK(KAT_PASSWORD, KAT_USER_ID, { argon2: backend })).rejects.toThrow(
      /conformance/i,
    );
  });

  it("rejects an empty password before it reaches an injected backend", async () => {
    let called = false;
    const backend: Argon2Backend = (_pw, _salt, p) => {
      called = true;
      return new Uint8Array(p.dkLen);
    };
    await expect(deriveMUK("", KAT_USER_ID, { argon2: backend })).rejects.toThrow(/password/i);
    expect(called).toBe(false);
  });

  /**
   * THE PARAMETERS ARE NOT NEGOTIABLE AND THE BACKEND CANNOT SEE A WAY TO
   * CHANGE THEM. It receives the real values, and it receives them frozen, so
   * a backend that "normalises" its options in place cannot weaken the
   * module-level constant that every later derivation in the process reads.
   */
  it("hands the backend the real parameters, frozen", async () => {
    let seen: unknown;
    const backend: Argon2Backend = (pw, salt, p) => {
      seen = p;
      return argon2id(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    };
    // Conformance runs first and calls the backend with the cheap vectors, so
    // `seen` is overwritten by the real call that follows.
    await deriveMUK(KAT_PASSWORD, KAT_USER_ID, { argon2: backend });
    expect(seen).toEqual({ m: 65536, t: 3, p: 4, dkLen: 32 });
    expect(Object.isFrozen(seen)).toBe(true);
    expect(() => {
      (seen as { m: number }).m = 8;
    }).toThrow();
  }, DERIVE_BUDGET_MS);

  it("freezes the exported parameter constant itself", () => {
    expect(Object.isFrozen(ARGON2_PARAMS)).toBe(true);
    expect(() => {
      (ARGON2_PARAMS as unknown as { m: number }).m = 8;
    }).toThrow();
  });

  /**
   * THE GATE. An alternative backend is only safe if it reproduces the pinned
   * vector byte for byte; anything else orphans every account derived through
   * the other one. Here the "alternative" is noble reached through the seam
   * rather than through the default, which proves the seam itself -- the
   * parameter hand-off, the frozen copy, the output check, the re-wrapping --
   * perturbs nothing.
   *
   * The cross-IMPLEMENTATION version of this test, noble against WASM, cannot
   * live here: `@sluice/crypto` deliberately has no WASM dependency. It lives
   * in `apps/admin/test/argon2-agreement.test.ts`, which owns the WASM backend.
   */
  it("derives the pinned known-answer vector through the seam", async () => {
    const viaSeam: Argon2Backend = (pw, salt, p) =>
      argon2id(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    const key = await deriveMUK(KAT_PASSWORD, KAT_USER_ID, { argon2: viaSeam });
    expect(toHex(key.bytes)).toBe(KAT_MUK);
  }, DERIVE_BUDGET_MS);

  /**
   * A backend may be asynchronous -- that is the point, a Worker round trip is
   * -- and an async backend must produce the identical key. This one also
   * proves the seam awaits rather than accidentally treating a Promise as
   * bytes, which would reach `MasterUnlockKey` as a non-Uint8Array.
   */
  it("accepts an asynchronous backend and derives the same key", async () => {
    const asyncBackend: Argon2Backend = async (pw, salt, p) => {
      await Promise.resolve();
      return argon2id(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    };
    const key = await deriveMUK(KAT_PASSWORD, KAT_USER_ID, { argon2: asyncBackend });
    expect(toHex(key.bytes)).toBe(KAT_MUK);
  }, DERIVE_BUDGET_MS);

  /**
   * NFC normalisation happens in `deriveMUK`, BEFORE the seam, and it must stay
   * there. If a backend ever received the raw string it would have to
   * normalise for itself, and the day one of them forgot, every user with a
   * non-ASCII password would get a different key on a different device -- the
   * exact unrecoverable lockout the normalisation exists to prevent.
   *
   * This asserts the backend sees identical BYTES for the NFC and NFD spellings
   * of the same password, which is the only way to prove the normalisation is
   * on the package's side of the boundary.
   *
   * It costs milliseconds, not seconds: the recorder answers the two cheap
   * conformance vectors honestly and then refuses the real call, so the input
   * is captured without anyone paying for a 64 MiB grind that would tell us
   * nothing further.
   */
  it("normalises the password before the backend sees it", async () => {
    const seen: string[] = [];
    let armed = false;
    const recorder: Argon2Backend = (pw, salt, p) => {
      if (armed) {
        seen.push(toHex(pw));
        throw new Error("recorder: input captured");
      }
      return argon2id(pw, salt, { m: p.m, t: p.t, p: p.p, dkLen: p.dkLen });
    };
    await assertConformantArgon2(recorder);
    armed = true;

    // Same glyphs, different code points; a user can type either. Written as
    // escapes rather than literal characters so no editor, formatter or git
    // filter can normalise one into the other and quietly gut the test.
    const NFC = "café latte"; // é as a single precomposed code point
    const NFD = "café latte"; // e + U+0301 COMBINING ACUTE ACCENT
    expect(NFC).not.toBe(NFD);
    await expect(deriveMUK(NFC, KAT_USER_ID, { argon2: recorder })).rejects.toThrow(/captured/);
    await expect(deriveMUK(NFD, KAT_USER_ID, { argon2: recorder })).rejects.toThrow(/captured/);

    expect(seen).toHaveLength(2);
    expect(seen[0]).toBe(seen[1]);
    expect(seen[0]).toBe(toHex(utf8.encode(NFC.normalize("NFC"))));
  });
});
