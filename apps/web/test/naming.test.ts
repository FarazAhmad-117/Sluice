import { describe, expect, it } from "vitest";
import { MAX_SLUG_LENGTH, isSlug } from "../src/lib/naming";

/**
 * THE CLIENT COPY OF A SERVER RULE, PINNED TO THE SERVER'S CASES.
 *
 * `convex/lib/naming.ts` is the authority and rejects a bad slug whatever this
 * says. What this buys is that the rejection happens before the form is
 * submitted, on the field that is wrong, rather than as a sentence about an
 * argument after a round trip.
 *
 * The cases below are the ones the server's own rule turns on, so a drift shows
 * up here rather than as a form that lets somebody through to a refusal.
 */
describe("isSlug", () => {
  it("accepts what the server accepts", () => {
    for (const good of ["api", "a", "0", "acme-rockets", "web-2-api", "a1-b2-c3"]) {
      expect({ good, ok: isSlug(good) }).toEqual({ good, ok: true });
    }
  });

  it("rejects the shapes the server rejects", () => {
    const bad = [
      "", // empty
      "Acme", // uppercase
      "acme rockets", // space
      "acme_rockets", // underscore
      "-acme", // leading hyphen
      "acme-", // trailing hyphen
      "acme--rockets", // doubled hyphen
      "acme.rockets", // dot
      "acme/rockets", // slash
      "café", // not in the accepted alphabet
      "a".repeat(MAX_SLUG_LENGTH + 1), // over length
    ];
    for (const value of bad) {
      expect({ value, ok: isSlug(value) }).toEqual({ value, ok: false });
    }
  });

  it("accepts a slug of exactly the maximum length", () => {
    // The boundary in the direction that matters: one character shorter than
    // the refusal. A client stricter than the server refuses names the product
    // allows, which is a bug nobody reports, they just pick another name.
    expect(MAX_SLUG_LENGTH).toBe(48);
    expect(isSlug("a".repeat(MAX_SLUG_LENGTH))).toBe(true);
  });

  it("is not a global regular expression", () => {
    // A `g` flag carries `lastIndex` across `.test` calls, so the same input
    // would alternate between pass and fail. On a form that is a field that
    // rejects itself every second keystroke.
    for (let i = 0; i < 5; i += 1) expect(isSlug("api")).toBe(true);
  });
});
