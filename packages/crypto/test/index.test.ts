import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";

/**
 * THE PUBLIC SURFACE OF THE PACKAGE, PINNED EXACTLY.
 *
 * This assertion is not a restatement of `index.ts`; it is the thing that makes
 * changing `index.ts` a decision. On a security package an accidental export is
 * how key material escapes: an internal added here without argument becomes an
 * API that consumers depend on, and the day it is removed again is the day the
 * SDK breaks. Adding or removing a name must fail this test and show up in the
 * diff as two edits rather than one.
 *
 * WHAT THIS CANNOT SEE. `SealedBox`, `TokenKeys` and `RevocationNotice` are
 * interfaces, and interfaces are erased at compile time -- they exist in no
 * runtime object, so `Object.keys` cannot report them and no runtime assertion
 * can pin them. They are exported from `index.ts` with `export type` for
 * consumers, and the only thing guarding them is `tsc`, which fails if a
 * re-export names a type that no longer exists. `MintedToken` and
 * `MasterUnlockKey` are CLASSES, so they are values and do appear below.
 *
 * WHAT IS DELIBERATELY ABSENT, and why:
 *
 * `concat` is not here. It is a plain buffer join with no security semantics,
 * and every caller inside this package uses it to build bytes that are then
 * SIGNED. Handing it to consumers invites exactly the failure `revocation.ts`
 * documents at length: an ad-hoc `concat(a, b)` message encoding whose field
 * boundaries are ambiguous, so one signature covers two different structures.
 * Signed encodings belong inside this package, so the helper for building them
 * stays inside too.
 *
 * `constantTimeEqual` IS here, which is the opposite call on a similar-looking
 * helper. The difference is that a consumer genuinely has to compare secrets --
 * a stored token id against a presented one, a recovery code, a MAC -- and the
 * alternative to exporting this is not "they do not compare", it is `a === b`
 * in an SDK we do not own, which is the timing leak this function exists to
 * remove. Withholding it does not prevent the comparison, it only guarantees
 * the naive one.
 *
 * `deriveTokenKeys` IS here. It is not a convenience: it is the function the
 * SDK calls on every start-up. The SDK holds a token string, calls
 * `parseToken`, and must derive `unwrapKey` locally to open the project data
 * key -- that derivation happening on the client instead of the server is the
 * zero-knowledge property itself. Without this export the package can mint
 * tokens and never use one.
 *
 * `mukSalt`, `handshakeMessage`, `encode`, `assertValidNotice`, `importKey` and
 * the `*_INFO` / `*_PATTERN` / `*_BYTES` constants stay private. They are
 * encoding and validation internals; anything that needs them is a function
 * that is itself exported.
 */
const PUBLIC_SURFACE = [
  "ARGON2_PARAMS",
  "MasterUnlockKey",
  "MintedToken",
  "VERSION",
  "constantTimeEqual",
  "deriveMUK",
  "deriveTokenKeys",
  "fromHex",
  "mintToken",
  "parseToken",
  "randomBytes",
  "seal",
  "signHandshake",
  "signRevocation",
  "toHex",
  "unseal",
  "utf8",
  "verifyHandshake",
  "verifyRevocation",
];

describe("public API surface", () => {
  it("exports exactly the pinned set of names", () => {
    expect(Object.keys(api).sort()).toEqual([...PUBLIC_SURFACE].sort());
  });

  it("does not export internal byte plumbing", () => {
    // Named explicitly rather than left implicit in the list above, because
    // this one is a judgement that a future reader will want to re-litigate.
    expect(Object.keys(api)).not.toContain("concat");
  });

  it("binds every exported name to something defined", () => {
    // A `export { x } from` of a name that exists but is undefined at runtime
    // would still satisfy the key check above.
    for (const name of PUBLIC_SURFACE) {
      expect(api[name as keyof typeof api]).toBeDefined();
    }
  });

  it("exports the two secret-bearing classes as constructors, not plain objects", () => {
    // Their redaction lives on the prototype, so a consumer receiving anything
    // other than a class here would be receiving something that can be dumped.
    expect(typeof api.MasterUnlockKey).toBe("function");
    expect(typeof api.MintedToken).toBe("function");
    expect(typeof api.MasterUnlockKey.prototype.toJSON).toBe("function");
    expect(typeof api.MintedToken.prototype.toJSON).toBe("function");
  });

  it("re-exports the same function objects the modules define", () => {
    // Guards against a barrel that wraps or shadows rather than re-exports.
    expect(api.VERSION).toBe("sluice-crypto/v1");
    expect(api.ARGON2_PARAMS).toEqual({ m: 65536, t: 3, p: 4, dkLen: 32 });
    expect(api.toHex(api.fromHex("00ff"))).toBe("00ff");
  });
});
