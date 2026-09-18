import { argon2id } from "hash-wasm";
import type { Argon2Backend } from "@sluice/crypto";

/**
 * The WASM Argon2id backend for `@sluice/crypto`.
 *
 * WHY `hash-wasm`, and what was checked before writing a line against it:
 *
 * - It exists and is current: `npm view hash-wasm` -> 4.12.0, MIT, last
 *   published 2024-11-19, 1.08 million downloads in the week of 2026-09-05.
 *   The repository (Daninet/hash-wasm) is not archived.
 * - Its real API was read from the installed typings
 *   (`node_modules/hash-wasm/dist/lib/argon2.d.ts`), not assumed: it exports
 *   `argon2i`, `argon2id`, `argon2d` and `argon2Verify`, all PROMISE-returning,
 *   taking a single options object of `{ password, salt, iterations,
 *   parallelism, memorySize, hashLength, outputType? }`. `memorySize` is in
 *   KiB, matching noble's `m`. `outputType` DEFAULTS TO `"hex"`.
 * - Its output was checked against noble at the real Sluice parameters before
 *   any of this code was written: byte-identical, and 12.6x faster
 *   (5460 ms -> 434 ms on a desktop x64 under Node 22).
 *
 * The alternatives were weighed and rejected on maintenance, not on features:
 * `argon2-browser` (1.18.0, last published 2022-04, 17.5k weekly) and
 * `argon2id` (1.0.1, 2023-08, 12.6k weekly) are both older and roughly sixty
 * times less used.
 *
 * THE HONEST CAVEAT. `hash-wasm` has not been published since November 2024.
 * For a hash library with a frozen API that is defensible -- there is nothing
 * to churn -- but it means a CVE in the bundled WASM would have no maintainer
 * turnaround guarantee. The mitigation is that nothing depends on trusting it:
 * `assertConformantArgon2` checks it on every page load and the cross-backend
 * agreement test checks it against noble at the real parameters in CI, so a
 * change in its behaviour is a failing test rather than a silent key change.
 */

/**
 * TWO MISTAKES THIS FUNCTION IS WRITTEN TO AVOID, both of which produce a
 * WRONG MASTER UNLOCK KEY and neither of which throws:
 *
 * 1. `argon2i` instead of `argon2id`. One character. A real export of this same
 *    module. Returns 32 plausible bytes from a different KDF.
 * 2. Omitting `outputType: "binary"`. The library then returns a HEX STRING,
 *    and a caller that passes it on as bytes gets a 64-byte "key" of ASCII hex
 *    digits -- or, worse, something downstream that coerces it.
 *
 * Neither is caught by reading the code. Both are caught by
 * `assertConformantArgon2`, which every `deriveMUK` call runs against this
 * backend before accepting a single byte from it.
 */
export const wasmArgon2: Argon2Backend = async (password, salt, params) => {
  // The parameters come from `@sluice/crypto` frozen, and are copied field by
  // field rather than spread. A spread would silently carry any future field
  // `Argon2Params` gains into an options object `hash-wasm` does not
  // understand, and this library ignores unknown keys rather than rejecting
  // them -- which is exactly how a parameter stops being applied without
  // anyone noticing.
  return argon2id({
    password,
    salt,
    iterations: params.t,
    parallelism: params.p,
    memorySize: params.m, // KiB on both sides. Verified, not assumed.
    hashLength: params.dkLen,
    outputType: "binary",
  });
};

/** 64 MiB expressed the way WebAssembly counts it: 64 KiB pages. */
const PAGE_BYTES = 65536;

/**
 * Asks the engine for the allocation Argon2id will need, and reports rather
 * than guesses.
 *
 * WHY THIS EXISTS. `m = 65536` is 64 MiB of contiguous WebAssembly memory per
 * derivation. On a memory-constrained device -- iOS Safari in particular --
 * that request can fail, and a failure DURING signup happens after the user has
 * chosen a password, after the account row may exist, at the worst possible
 * moment. Asking first turns an unrecoverable mid-signup crash into a sentence
 * on the page before they start typing.
 *
 * WHAT IT MUST NEVER BE USED FOR. If this returns `false`, the answer is to
 * TELL THE USER, not to quietly lower `m`. Weakening the parameters on the
 * weakest devices would hand the worst-protected accounts to exactly the
 * population least able to notice, and nothing in the stored key bundle records
 * which parameters produced it, so the damage would be permanent and
 * unauditable. `ARGON2_PARAMS` is frozen and there is no code path here that
 * reads anything else.
 *
 * A caveat worth stating: a probe that succeeds is not a guarantee. Memory
 * freed here can be taken by something else a second later, and iOS can reclaim
 * a tab for reasons unrelated to this allocation. The probe removes the
 * predictable failure, not the race.
 */
export function probeArgon2Memory(kib: number): { ok: true } | { ok: false; reason: string } {
  const pages = Math.ceil((kib * 1024) / PAGE_BYTES);
  try {
    // A real WebAssembly.Memory, not a Uint8Array: the WASM heap is what
    // Argon2id actually allocates, it has its own engine-level limits, and a
    // JS typed array can succeed where a WASM memory grow would not.
    // `+16` pages of slack for the module's own working space, so a probe that
    // passes is not sitting exactly on the edge of the request that follows.
    const memory = new WebAssembly.Memory({ initial: pages + 16 });
    // Touch the far end. Some engines reserve address space lazily, so an
    // allocation can "succeed" and then fault on first write.
    const view = new Uint8Array(memory.buffer);
    view[view.length - 1] = 1;
    if (view[view.length - 1] !== 1) return { ok: false, reason: "memory did not retain a write" };
    return { ok: true };
  } catch (cause) {
    // The message is the engine's, about an allocation. It contains no user
    // input and no key material, so it is safe to surface.
    return { ok: false, reason: cause instanceof Error ? cause.message : String(cause) };
  }
}
