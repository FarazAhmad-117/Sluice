// @vitest-environment node

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { secretAssociatedData, toHex } from "@sluice/crypto";

/**
 * ONE DEFINITION OF EACH CROSS-SIDE PROTOCOL RULE, AND IT IS NOT IN HERE.
 *
 * `convex/lib/aad.ts` used to define the secret associated data prefix and so
 * did `packages/crypto/src/protocol.ts`. Two definitions of a protocol constant,
 * both carrying a long comment that makes each look authoritative, is strictly
 * worse than the single-sided definition the move was meant to replace: a
 * reader has no way to tell which one the other side computes from, and the
 * failure when they drift is an opaque AEAD rejection at read time, months
 * later, with no error anybody can act on.
 *
 * The Convex copy is gone. The rule is now `/v2`, which binds the environment's
 * permanent `env_` id from `ids.ts` rather than its Convex document id, and the
 * only definition of it is in `@sluice/crypto`. This file is the enforcement
 * that it stays that way. It reads the source tree the way `repo/repo.test.ts`
 * does, because a rule nothing checks is a comment.
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
 * Written split so that this file, which necessarily names the literals to test
 * for them, does not itself contain either literal and fail its own scan. The
 * same reason `repo/repo.test.ts` words its own prose carefully: the check is a
 * grep over source text and cannot tell a definition from a mention.
 *
 * Both versions are scanned for. The v2 literal is the one a hand-copy would
 * spell today; the v1 literal is the one a stale copy would still carry, and a
 * stale copy is worse than a fresh one because it now disagrees with the
 * client.
 */
const SECRET_AAD_LITERALS = ["sluice/secret" + "/v1|", "sluice/secret" + "/v2|"];

/** The permanent id `packages/crypto/test/protocol.test.ts` pins its vector on. */
const ENV = "env_000102030405060708090a0b0c0d0e0f";

/**
 * The v2 secret associated data for `ENV`, as hex, computed with node:crypto
 * and never with `@sluice/crypto`. (The prefix is deliberately not spelled out
 * here: the scan below would find it in this comment.) Identical to `SECRET_AAD` in the crypto package's own
 * test: the two suites pin the same point of the map from opposite sides of
 * the wire.
 */
const SECRET_AAD =
  "736c756963652f7365637265742f76327c656e765f3030303130323033303430353036303730383039306130623063306430653066";

describe("the secret associated data rule", () => {
  it("is defined nowhere under convex/", () => {
    const offenders = walk("convex").filter((file) => {
      const text = readFileSync(file, "utf8");
      return SECRET_AAD_LITERALS.some((literal) => text.includes(literal));
    });
    expect(offenders).toEqual([]);
  });

  it("refuses a non-string environment uid instead of encoding it", () => {
    // A numeric id would produce a perfectly well formed, completely wrong AAD
    // for the environment 42. An id off a database row or a URL segment is
    // exactly where a number arrives from.
    expect(() =>
      secretAssociatedData({ environmentUid: 42 as unknown as string }),
    ).toThrow(/^environmentUid must be a well-formed env id$/);
    expect(() =>
      secretAssociatedData({ environmentUid: undefined as unknown as string }),
    ).toThrow(/^environmentUid must be a well-formed env id$/);
  });

  /**
   * The server side of the change, asserted where the server lives. Every
   * Convex document id is now refused outright, which is what stops a call
   * site in this directory from passing `environment._id` where it means
   * `environment.uid` and binding ciphertext to a value that is re-minted on a
   * cell move.
   */
  it("refuses a Convex document id", () => {
    expect(() => secretAssociatedData({ environmentUid: "jd7abc123" })).toThrow(
      /^environmentUid must be a well-formed env id$/,
    );
  });

  it("produces the pinned bytes for a real environment uid", () => {
    expect(toHex(secretAssociatedData({ environmentUid: ENV }))).toBe(SECRET_AAD);
  });
});
