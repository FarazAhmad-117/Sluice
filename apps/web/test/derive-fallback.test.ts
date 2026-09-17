import { describe, expect, it } from "vitest";
import { toHex } from "@sluice/crypto";
import {
  DerivationBusyError,
  deriveMasterUnlockKey,
  isDeriving,
  probeDerivationCapability,
} from "../src/lib/crypto/derive";

/**
 * WHAT HAPPENS WHEN THE WORKER IS NOT THERE.
 *
 * This file runs under Node, where there is no global `Worker`. That is not a
 * limitation being worked around -- it is the exact condition being tested. A
 * browser reaches the same state through a Content-Security-Policy without
 * `worker-src`, a sandboxed iframe, or an extension that blocks worker
 * creation, and in every one of those cases `new Worker(...)` throws
 * synchronously just as it does here.
 *
 * The three things that must hold when it does:
 *
 * 1. THE USER STILL GETS THE RIGHT KEY. A fallback that derived a different key
 *    would lock people out of accounts created on a working browser.
 * 2. THE PARAMETERS DO NOT MOVE. The fallback changes WHERE the work runs, not
 *    how much work it is. A "degraded mode" that quietly halved `m` would hand
 *    the weakest keys to the most constrained devices, with nothing in the
 *    stored bundle to record which accounts got which.
 * 3. IT IS NOT SILENT. The route taken is returned and the degradation is
 *    reported, so "every user on this browser is freezing their tab for eleven
 *    seconds" is something the UI can know rather than something nobody finds
 *    out.
 */

const KAT_PASSWORD = "correct horse battery staple";
const KAT_USER_ID = "u1";
const KAT_MUK = "dfee4c58ca2653a1b5ae9a64cd3743c1cb33b26f2a6a537715f26e84cfd5b588";
const BUDGET_MS = 600_000;

it("has no Worker global, which is the condition under test", () => {
  expect(typeof (globalThis as { Worker?: unknown }).Worker).toBe("undefined");
});

describe("probeDerivationCapability", () => {
  /**
   * The probe has to be usable BEFORE the user types a password, and it must
   * not throw when something is missing -- a probe that throws is a probe that
   * takes the signup page down instead of warning about it.
   */
  it("reports the missing worker without throwing, and says why", async () => {
    const result = await probeDerivationCapability();
    expect(result.workerAvailable).toBe(false);
    expect(result.reasons.join(" ")).toMatch(/worker unavailable/i);
    // WASM and the 64 MiB allocation are independent of the worker, and both
    // are available here, so a UI can tell "no worker, still usable" apart from
    // "this device cannot do it at all".
    expect(result.wasmUsable).toBe(true);
    expect(result.memoryAvailable).toBe(true);
  }, BUDGET_MS);
});

describe("deriveMasterUnlockKey without a worker", () => {
  it("falls back to main-thread WASM, reports it, and derives the identical key", async () => {
    const reported: string[] = [];
    const result = await deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID, {
      onDegraded: (d) => reported.push(`${d.from}->${d.to}`),
    });

    // 1. The right key, byte for byte.
    expect(toHex(result.key.bytes)).toBe(KAT_MUK);
    // 2. The route is named, not inferred.
    expect(result.path).toBe("main-wasm");
    // 3. It was announced, both through the callback and in the result.
    expect(reported).toEqual(["worker-wasm->main-wasm"]);
    expect(result.degradations).toHaveLength(1);
    expect(result.degradations[0]?.reason).toMatch(/worker/i);
  }, BUDGET_MS);

  /**
   * The opt-out has to actually stop the fallback, or a caller that decided a
   * frozen tab is unacceptable would get one anyway.
   */
  it("refuses rather than blocking the main thread when the fallback is declined", async () => {
    await expect(
      deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID, { allowMainThreadFallback: false }),
    ).rejects.toThrow(/worker/i);
  }, BUDGET_MS);
});

describe("single-flight", () => {
  /**
   * THE DOUBLE-CLICKED SIGNUP BUTTON. Two concurrent derivations mean two
   * concurrent 64 MiB allocations, which is how a phone kills the tab. The
   * second identical call must join the first, not start a second.
   */
  it("gives a duplicate request the same promise rather than a second derivation", async () => {
    const first = deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID);
    const second = deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID);
    expect(second).toBe(first);
    expect(isDeriving()).toBe(true);

    const [a, b] = await Promise.all([first, second]);
    expect(toHex(a.key.bytes)).toBe(KAT_MUK);
    expect(toHex(b.key.bytes)).toBe(KAT_MUK);
    expect(isDeriving()).toBe(false);
  }, BUDGET_MS);

  /**
   * A concurrent request for a DIFFERENT key is not a double-click, it is two
   * allocations. It is refused, synchronously, so the caller cannot mistake it
   * for queued work.
   */
  it("refuses a concurrent request with different inputs", async () => {
    const running = deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID);
    expect(() => deriveMasterUnlockKey("a different password", KAT_USER_ID)).toThrow(
      DerivationBusyError,
    );
    expect(() => deriveMasterUnlockKey(KAT_PASSWORD, "a-different-user")).toThrow(
      DerivationBusyError,
    );
    await running;
  }, BUDGET_MS);

  /**
   * The slot must be released on FAILURE too. If a rejected derivation left it
   * held, the password would stay referenced in module scope and every later
   * attempt on the page would get `DerivationBusyError` forever -- a login form
   * that is permanently broken after one bad attempt.
   */
  it("releases the slot after a rejected derivation", async () => {
    await expect(
      deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID, { allowMainThreadFallback: false }),
    ).rejects.toThrow();
    expect(isDeriving()).toBe(false);
    const result = await deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID);
    expect(toHex(result.key.bytes)).toBe(KAT_MUK);
  }, BUDGET_MS);
});
