// @vitest-environment node

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { secretAssociatedData, toHex } from "@sluice/crypto";

/**
 * ONE DEFINITION OF EACH CROSS-SIDE PROTOCOL RULE, AND IT IS NOT IN HERE.
 *
 * `convex/lib/aad.ts` used to define the secret associated data prefix and so
 * does `packages/crypto/src/protocol.ts`. Two definitions of a protocol constant,
 * both carrying a long comment that makes each look authoritative, is strictly
 * worse than the single-sided definition the move was meant to replace: a
 * reader has no way to tell which one the other side computes from, and the
 * failure when they drift is an opaque AEAD rejection at read time, months
 * later, with no error anybody can act on.
 *
 * This file is the enforcement. It reads the source tree the way
 * `repo/repo.test.ts` does, because a rule nothing checks is a comment.
 *
 * It needs Node built-ins, hence the docblock above: the rest of the suite runs
 * in an edge runtime to match Convex's default runtime.
 */

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry !== "_generated") walk(full, out);
    } else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

/**
 * Written split so that this file, which necessarily names the literal to test
 * for it, does not itself contain the literal and fail its own scan. The same
 * reason `repo/repo.test.ts` words its own prose carefully: the check is a grep
 * over source text and cannot tell a definition from a mention.
 */
const SECRET_AAD_LITERAL = "sluice/secret" + "/v1|";

describe("the secret associated data rule", () => {
  it("is defined nowhere under convex/", () => {
    const offenders = walk("convex").filter((file) =>
      readFileSync(file, "utf8").includes(SECRET_AAD_LITERAL),
    );
    expect(offenders).toEqual([]);
  });

  /**
   * The two holes the Convex copy had, asserted rather than asserted about.
   * They are the reason the deletion is not merely tidying.
   */
  it("refuses lone surrogates instead of collapsing three ids into one AAD", () => {
    // `TextEncoder` substitutes U+FFFD for an unpaired surrogate rather than
    // throwing, so under the Convex definition these three distinct index keys
    // encoded to identical bytes and each could open the others' ciphertext.
    for (const environmentId of ["\uD800", "\uDC00"]) {
      expect(() => secretAssociatedData({ environmentId })).toThrow();
    }
    // U+FFFD itself is a real character and stays legal. The collision is
    // closed by removing the two ids that were never representable, not by
    // banning the one that was, which is what keeps this a tightening.
    expect(toHex(secretAssociatedData({ environmentId: "�" }))).toBe(
      toHex(new TextEncoder().encode(SECRET_AAD_LITERAL + "�")),
    );
  });

  it("refuses a non-string environment id instead of encoding it", () => {
    // A numeric id produced the perfectly well formed, completely wrong AAD
    // AAD for the environment id 42. An id off a database row or a URL segment is
    // exactly where a number arrives from.
    expect(() =>
      secretAssociatedData({ environmentId: 42 as unknown as string }),
    ).toThrow();
    expect(() =>
      secretAssociatedData({ environmentId: undefined as unknown as string }),
    ).toThrow();
  });

  it("still produces the same bytes for a real environment id", () => {
    // The move is a tightening, not a change of encoding. Anything already
    // sealed under the old definition must still open under this one.
    expect(toHex(secretAssociatedData({ environmentId: "jd7abc123" }))).toBe(
      toHex(new TextEncoder().encode(SECRET_AAD_LITERAL + "jd7abc123")),
    );
  });
});
