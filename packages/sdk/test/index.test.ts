import { describe, expect, it } from "vitest";
import * as sdk from "../src/index";

/**
 * The surface pin. See `src/index.ts` for why this file exists: an export added
 * to a kill switch without argument is how a back door gets in, so the list is
 * asserted rather than inferred.
 */
describe("the public surface", () => {
  it("is exactly this list", () => {
    expect(Object.keys(sdk).sort()).toEqual([
      "EXIT_CODE",
      "MAX_CLOCK_STEP_MS",
      "MAX_DRAIN_MS",
      "MIN_MAX_OFFLINE_DURATION_MS",
      "SluiceCore",
      "VERSION",
      "applyDecisions",
      "sanitiseForLog",
    ]);
  });

  it("exposes no way to order a shutdown without a signature", () => {
    // Anything that could produce an exit without going through
    // `verifyRevocation` would defeat the entire design.
    for (const name of Object.keys(sdk)) {
      expect(name.toLowerCase()).not.toMatch(/shutdown|revoke|kill|exit(?!_code)/);
    }
  });

  it("pins the constants section 4.3 fixes", () => {
    expect(sdk.EXIT_CODE).toBe(1);
    expect(sdk.MAX_DRAIN_MS).toBe(60_000);
    expect(sdk.VERSION).toBe("sluice-sdk/v1");
  });
});
