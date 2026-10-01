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
 * Every domain label in `packages/crypto/src` -- the four associated data
 * rules (secret, project data key, revocation key, user key), the token id
 * hash, the signed revocation notice, the token's auth and unwrap derivations,
 * the auth verifier, the MUK salt and the Argon2 conformance vector -- is
 * defined once, in the crypto package, and reached only through its functions.
 * The revocation notice matters most: a drifted hand copy here would verify
 * notices the SDK never signed, or reject ones it did, and either way a
 * revoked token keeps working. A test below reads the crypto source and fails
 * if it grows a label this pattern does not cover.
 *
 * Version-agnostic on purpose: a hand-copy written today would spell
 * the current version, a stale copy still carries an old one, and a stale copy
 * is worse than a fresh one because it now disagrees with the client. A future
 * version is banned before it exists.
 *
 * Built from split strings so that this file, which necessarily describes the
 * pattern, does not itself match it and fail its own scan -- the same reason
 * `repo/repo.test.ts` words its own prose carefully: the check is a grep over
 * source text and cannot tell a definition from a mention. Labels the crypto
 * package does not own (`handshake-nonce`, `bundle`, `session`, and the
 * verifier's `auth/decoy`) are Convex's own and are deliberately not matched:
 * the pattern requires `/v<digit>` straight after the domain, so `auth/decoy`
 * is not read as `auth`.
 */
const OWNED_LABEL = new RegExp(
  "sluice" +
    "/(secret|pdk|revocation-key|revocation|user-key|token-id|auth|unwrap|auth-verifier|muk-salt|argon2-conformance)/v" +
    "\\d",
);

/**
 * The same domains, written out separately so the self-test below is not
 * merely the pattern checked against itself: dropping a name from either list
 * fails a test.
 */
const OWNED_DOMAINS = [
  "secret",
  "pdk",
  "revocation-key",
  "revocation",
  "user-key",
  "token-id",
  "auth",
  "unwrap",
  "auth-verifier",
  "muk-salt",
  "argon2-conformance",
];

/** The crypto package's source, where every owned label is defined. */
const CRYPTO_SRC = fileURLToPath(new URL("../../packages/crypto/src", import.meta.url));

/** The permanent ids `packages/crypto/test/protocol.test.ts` pins its vectors on. */
const ENV = "env_000102030405060708090a0b0c0d0e0f";
const SEC = "sec_303132333435363738393a3b3c3d3e3f";

/** A valid secret binding, so each test below varies exactly one field. */
const BINDING = { environmentUid: ENV, secretUid: SEC, version: 1, field: "value" } as const;

/**
 * The v2 secret associated data for the value of version 1 of `SEC` in `ENV`,
 * as hex, computed with node:crypto and never with `@sluice/crypto`. The prefix
 * is deliberately not spelled out here, because the scan below would find it
 * in this comment. Identical to `SECRET_AAD_AT_1_VALUE` in the crypto package's
 * own test: the two suites pin the same point of the map from opposite sides
 * of the wire.
 */
const SECRET_AAD_AT_1_VALUE =
  "736c756963652f7365637265742f76327c656e765f30303031303230333034303530363037303830393061306230633064306530667c7365635f33303331333233333334333533363337333833393361336233633364336533667c317c76616c7565";

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
    for (const domain of OWNED_DOMAINS) {
      for (const version of ["1", "2", "9"]) {
        const spelled = `"${"sluice"}/${domain}/v${version}|"`;
        expect(`${spelled} ${String(OWNED_LABEL.test(spelled))}`).toBe(`${spelled} true`);
      }
    }
    // `auth/decoy` is `convex/lib/verifier.ts`'s own label and must stay
    // allowed even though it starts with an owned domain.
    for (const notOurs of ["handshake-nonce", "bundle", "session", "auth/decoy"]) {
      expect(`${notOurs} ${String(OWNED_LABEL.test(`${"sluice"}/${notOurs}/v1`))}`).toBe(
        `${notOurs} false`,
      );
    }
  });

  /**
   * The ban has to keep up with the crypto package. Every label defined there
   * is read back from its source and the set must EQUAL the owned list: a new
   * label added to `@sluice/crypto` without extending this file fails here
   * rather than going unguarded, and a label removed from the crypto package
   * fails here too rather than lingering in the ban as a name nothing defines.
   *
   * Its limits, since it is a regex over source text: it sees only labels of
   * the form `sluice/<one path segment>/v<digit>`, so a nested-path label (`a/b`
   * between the prefix and the version), a label assembled by concatenation, or
   * one with no `/v<digit>` at all would not be read back and would go unchecked.
   */
  it("covers every label the crypto package actually defines", () => {
    const label = new RegExp("sluice" + "/([a-z0-9-]+)/v" + "\\d", "g");
    const defined = new Set<string>();
    for (const file of walk(CRYPTO_SRC)) {
      for (const match of readFileSync(file, "utf8").matchAll(label)) {
        defined.add(match[1] as string);
      }
    }
    expect([...defined].sort()).toEqual([...OWNED_DOMAINS].sort());
  });

  it("refuses a non-string environment uid instead of encoding it", () => {
    // A numeric id would produce a perfectly well formed, completely wrong AAD
    // for the environment 42. An id off a database row or a URL segment is
    // exactly where a number arrives from.
    expect(() =>
      secretAssociatedData({ ...BINDING, environmentUid: 42 as unknown as string }),
    ).toThrow(/^environmentUid must be a well-formed env id$/);
    expect(() =>
      secretAssociatedData({ ...BINDING, environmentUid: undefined as unknown as string }),
    ).toThrow(/^environmentUid must be a well-formed env id$/);
  });

  /**
   * The same for the secret's own version, which is exactly the kind of value
   * a database column or a JSON body returns as a string.
   */
  it("refuses a version that is not a positive whole number", () => {
    for (const bad of ["1", 0, 1.5]) {
      expect(() => secretAssociatedData({ ...BINDING, version: bad as number })).toThrow(
        /^version must be a whole number from 1 to 9007199254740991$/,
      );
    }
  });

  /**
   * The server side of the change, asserted where the server lives. Every
   * Convex document id is now refused outright, which is what stops a call
   * site in this directory from passing `environment._id` where it means
   * `environment.uid` and binding ciphertext to a value that is re-minted on a
   * cell move.
   */
  it("refuses a Convex document id", () => {
    expect(() => secretAssociatedData({ ...BINDING, environmentUid: "jd7abc123" })).toThrow(
      /^environmentUid must be a well-formed env id$/,
    );
    expect(() => secretAssociatedData({ ...BINDING, secretUid: "jd7abc123" })).toThrow(
      /^secretUid must be a well-formed sec id$/,
    );
  });

  it("produces the pinned bytes for a real environment and secret", () => {
    expect(toHex(secretAssociatedData(BINDING))).toBe(SECRET_AAD_AT_1_VALUE);
  });
});
