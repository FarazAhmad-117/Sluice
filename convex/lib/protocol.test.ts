// @vitest-environment node

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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
 * that it stays that way -- for that rule and for every other label the crypto
 * package owns. It reads the source tree the way `repo/repo.test.ts` does,
 * because a rule nothing checks is a comment.
 *
 * It needs Node built-ins, hence the `@vitest-environment node` pragma on the
 * first line: the rest of the suite runs in an edge runtime to match Convex's
 * default runtime.
 */

/**
 * The `convex/` directory, resolved from this file rather than from the working
 * directory, so the scan covers the same tree whether vitest is started from
 * the repo root, from `convex/`, or by an editor integration with some other
 * cwd. A cwd-relative `walk("convex")` scans nothing, or throws, from anywhere
 * but the root.
 */
const CONVEX_DIR = fileURLToPath(new URL("..", import.meta.url));

/** Every source extension Convex will bundle, not just TypeScript. */
const SOURCE_EXTENSIONS = [".ts", ".js", ".mjs"];

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry !== "_generated" && entry !== "node_modules") walk(full, out);
    } else if (SOURCE_EXTENSIONS.some((ext) => entry.endsWith(ext))) out.push(full);
  }
  return out;
}

/**
 * ANY HAND-WRITTEN LABEL OWNED BY `@sluice/crypto`, AT ANY VERSION.
 *
 * The secret, project data key, revocation key, user key and token id labels
 * are defined once, in the crypto package, and reached only through its
 * functions. Version-agnostic on purpose: a hand-copy written today would spell
 * the current version, a stale copy still carries an old one, and a stale copy
 * is worse than a fresh one because it now disagrees with the client. A future
 * version is banned before it exists.
 *
 * Built from split strings so that this file, which necessarily describes the
 * pattern, does not itself match it and fail its own scan -- the same reason
 * `repo/repo.test.ts` words its own prose carefully: the check is a grep over
 * source text and cannot tell a definition from a mention. Labels the crypto
 * package does not own (`handshake-nonce`, `bundle`, `session`) are Convex's
 * own and are deliberately not in the list.
 */
const OWNED_LABEL = new RegExp(
  "sluice" + "/(secret|pdk|revocation-key|user-key|token-id)/v" + "\\d",
);

/** The permanent id `packages/crypto/test/protocol.test.ts` pins its vector on. */
const ENV = "env_000102030405060708090a0b0c0d0e0f";

/**
 * The v2 secret associated data for `ENV`, as hex, computed with node:crypto
 * and never with `@sluice/crypto`. The prefix is deliberately not spelled out
 * here, because the scan below would find it in this comment. Identical to
 * `SECRET_AAD` in the crypto package's own test: the two suites pin the same
 * point of the map from opposite sides of the wire.
 */
const SECRET_AAD =
  "736c756963652f7365637265742f76327c656e765f3030303130323033303430353036303730383039306130623063306430653066";

describe("the secret associated data rule", () => {
  it("is defined nowhere under convex/, and neither is any other crypto-owned label", () => {
    const files = walk(CONVEX_DIR);
    // A scan that read nothing proves nothing. This file is itself under the
    // root, so not finding it means the root resolved to the wrong place.
    expect(files.some((file) => file.endsWith("protocol.test.ts"))).toBe(true);
    const offenders = files.filter((file) => OWNED_LABEL.test(readFileSync(file, "utf8")));
    expect(offenders).toEqual([]);
  });

  /**
   * The scan is only as good as its pattern, so the pattern is checked against
   * the spellings it exists to catch, assembled here from parts for the same
   * reason the pattern is.
   */
  it("matches every owned label at any version and nothing Convex owns", () => {
    for (const domain of ["secret", "pdk", "revocation-key", "user-key", "token-id"]) {
      for (const version of ["1", "2", "9"]) {
        expect(OWNED_LABEL.test(`"${"sluice"}/${domain}/v${version}|"`)).toBe(true);
      }
    }
    for (const notOurs of ["handshake-nonce", "bundle", "session"]) {
      expect(OWNED_LABEL.test(`${"sluice"}/${notOurs}/v1`)).toBe(false);
    }
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
