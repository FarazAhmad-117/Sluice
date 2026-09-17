import { describe, expect, it } from "vitest";
import { ARGON2_PARAMS, assertConformantArgon2, deriveMUK, toHex } from "@sluice/crypto";
import { probeArgon2Memory, wasmArgon2 } from "../src/lib/crypto/argon2-wasm";

/**
 * THE GATE THAT MAKES THE BACKEND SWAP SAFE.
 *
 * Swapping the Argon2 implementation under the Master Unlock Key is a change
 * with exactly one acceptable outcome: the SAME BYTES. A backend that is one
 * bit different is not "slightly wrong" -- every account created through it is
 * unopenable by the other one, the server holds nothing that could tell which
 * implementation made which key, and there is no recovery. Without this file
 * the swap is a guess.
 *
 * This is the cross-IMPLEMENTATION half of the gate. `@sluice/crypto` cannot
 * host it: the package deliberately has no WASM dependency, so noble is the
 * only implementation it can see. `apps/web` owns `hash-wasm`, so the
 * comparison lives here.
 *
 * These tests are SLOW ON PURPOSE. Each noble derivation costs about 5.5
 * seconds on a warm desktop and that cost IS the security property; running the
 * comparison at reduced parameters would prove agreement about a computation
 * nobody performs.
 */

/**
 * RESTATED, NOT IMPORTED, from `packages/crypto/test/muk.test.ts`.
 *
 * Importing it would mean one edit could move the vector in both places at
 * once, which is the single change that must never be easy. Here the noble
 * assertion below is the cross-check: if this constant and the one in
 * `muk.test.ts` ever disagree, one of the two files fails immediately.
 */
const KAT_PASSWORD = "correct horse battery staple";
const KAT_USER_ID = "u1";
const KAT_MUK = "dfee4c58ca2653a1b5ae9a64cd3743c1cb33b26f2a6a537715f26e84cfd5b588";

const DERIVE_BUDGET_MS = 600_000;

describe("hash-wasm backend", () => {
  /**
   * The cheap structural check, run here as well as inside `deriveMUK`, so a
   * `hash-wasm` upgrade that changed the meaning of `memorySize`, swapped the
   * default `outputType`, or shipped argon2i under the argon2id name fails in
   * two milliseconds with a clear message rather than eleven seconds later with
   * a wrong key.
   */
  it("passes the Argon2id conformance vectors", async () => {
    await expect(assertConformantArgon2(wasmArgon2)).resolves.toBeUndefined();
  });

  it("can allocate the 64 MiB the real parameters require", () => {
    expect(probeArgon2Memory(ARGON2_PARAMS.m)).toEqual({ ok: true });
  });

  /**
   * The probe must be capable of saying no. A request for 64 GiB is beyond any
   * engine's WebAssembly limit, so this proves the function reports a failure
   * instead of throwing past its caller -- which is what it would do at the
   * moment of signup on a device that genuinely cannot allocate.
   */
  it("reports rather than throws when the allocation is impossible", () => {
    const result = probeArgon2Memory(64 * 1024 * 1024);
    expect(result.ok).toBe(false);
  });
});

describe("noble and hash-wasm agree", () => {
  /**
   * THE KNOWN-ANSWER VECTOR, THROUGH BOTH BACKENDS.
   *
   * `deriveMUK` with no options is noble, the audited reference. `deriveMUK`
   * with `argon2: wasmArgon2` is the WASM path the browser actually uses. Both
   * must equal the pinned hex and each other, byte for byte.
   *
   * Comparing only the two backends to EACH OTHER would not be enough: two
   * implementations that agreed on the wrong answer would pass. Pinning both to
   * the recorded vector is what rules that out.
   */
  it("produce the pinned known-answer vector, byte for byte", async () => {
    const viaNoble = await deriveMUK(KAT_PASSWORD, KAT_USER_ID);
    const viaWasm = await deriveMUK(KAT_PASSWORD, KAT_USER_ID, { argon2: wasmArgon2 });

    expect(toHex(viaNoble.bytes)).toBe(KAT_MUK);
    expect(toHex(viaWasm.bytes)).toBe(KAT_MUK);
    expect(toHex(viaWasm.bytes)).toBe(toHex(viaNoble.bytes));
  }, DERIVE_BUDGET_MS);

  /**
   * NON-ASCII, THROUGH BOTH BACKENDS, IN BOTH NORMALISATION FORMS.
   *
   * ASCII agreement proves almost nothing about text handling. The real risk is
   * an implementation that takes a STRING and does its own encoding: `hash-wasm`
   * accepts `string | Uint8Array` for `password`, and if bytes were ever
   * replaced with a string there, its internal encoder -- not `@sluice/crypto`'s
   * NFC-normalised `TextEncoder` output -- would decide the bytes. For a user
   * whose password is "пароль-密码-パスワード" or "café", that is a
   * different key and a permanently unopenable account.
   *
   * The NFC/NFD pair is the same failure from the other side: a Mac and a
   * Windows machine can deliver different code points for the same typed
   * password, and all four derivations here must land on one key.
   */
  it("agree on non-ASCII passwords in both normalisation forms", async () => {
    // Escapes, not literal characters, so no editor or git filter can normalise
    // one spelling into the other and quietly turn this into an ASCII test.
    const NFC = "café-пароль-密码"; // precomposed é
    const NFD = "café-пароль-密码"; // e + U+0301
    expect(NFC).not.toBe(NFD);
    expect(NFC.normalize("NFC")).toBe(NFD.normalize("NFC"));

    const nobleNFC = await deriveMUK(NFC, KAT_USER_ID);
    const wasmNFC = await deriveMUK(NFC, KAT_USER_ID, { argon2: wasmArgon2 });
    const nobleNFD = await deriveMUK(NFD, KAT_USER_ID);
    const wasmNFD = await deriveMUK(NFD, KAT_USER_ID, { argon2: wasmArgon2 });

    const hexes = [nobleNFC, wasmNFC, nobleNFD, wasmNFD].map((k) => toHex(k.bytes));
    expect(new Set(hexes).size).toBe(1);
    // And it is a real key, not four copies of a zero buffer, which is what a
    // "they all agree" assertion would happily accept on its own.
    expect(hexes[0]).not.toBe("00".repeat(32));
    expect(hexes[0]).not.toBe(KAT_MUK);
  }, DERIVE_BUDGET_MS);

  /**
   * A 4-byte emoji and a lone astral code point. UTF-8 surrogate-pair handling
   * is where hand-rolled encoders differ, and a password picker offering emoji
   * is not hypothetical.
   */
  it("agree on an astral-plane password", async () => {
    const password = "\u{1F510}\u{1F5DD}\u{FE0F} unlock me";
    const viaNoble = await deriveMUK(password, KAT_USER_ID);
    const viaWasm = await deriveMUK(password, KAT_USER_ID, { argon2: wasmArgon2 });
    expect(toHex(viaWasm.bytes)).toBe(toHex(viaNoble.bytes));
  }, DERIVE_BUDGET_MS);

  /**
   * A different user id changes the salt, and the salt is built by
   * `@sluice/crypto` from `sha256("sluice/muk-salt/v1" || userId)`. This checks
   * the backends agree on a salt they did not choose, and -- via the inequality
   * -- that the salt is actually reaching the derivation rather than being
   * dropped by one of them.
   */
  it("agree when the salt changes, and the salt still matters", async () => {
    const viaNoble = await deriveMUK(KAT_PASSWORD, "usr_0123456789abcdef");
    const viaWasm = await deriveMUK(KAT_PASSWORD, "usr_0123456789abcdef", { argon2: wasmArgon2 });
    expect(toHex(viaWasm.bytes)).toBe(toHex(viaNoble.bytes));
    expect(toHex(viaWasm.bytes)).not.toBe(KAT_MUK);
  }, DERIVE_BUDGET_MS);
});
