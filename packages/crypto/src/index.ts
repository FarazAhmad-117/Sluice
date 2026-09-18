/**
 * THE PUBLIC SURFACE OF @sluice/crypto.
 *
 * Everything reachable by a consumer is named here and nowhere else, and
 * `test/index.test.ts` pins the exact list. That test is the point of this
 * file: on a security package an export added without argument is how key
 * material escapes, so adding one must be a deliberate act that shows up in a
 * diff as an edit to both files.
 *
 * What is NOT exported is as considered as what is. `concat` stays internal --
 * it builds bytes that get SIGNED, and an ad-hoc concatenation is precisely the
 * ambiguous encoding `revocation.ts` documents at length. `constantTimeEqual`
 * IS exported, because the alternative to giving consumers a safe comparison is
 * not that they stop comparing secrets, it is `a === b` in an SDK we do not
 * own. The encoding and validation internals (`mukSalt`, `handshakeMessage`,
 * `encode`, `assertValidNotice`, `importKey`) stay private; every caller that
 * needs them reaches them through a function that is exported.
 *
 * Types are re-exported with `export type` so consumers can annotate. They are
 * erased at runtime, so the surface test cannot see them and only `tsc` guards
 * them.
 *
 * ON THE EXTENSIONLESS IMPORT SPECIFIERS BELOW. They used to be written
 * `./bytes.js`, the NodeNext convention, and that convention is wrong for this
 * package: `tsconfig.base.json` sets `moduleResolution: "bundler"`, under which
 * extensionless is the canonical form. Keeping `.js` was not merely untidy, it
 * was load-bearing in the wrong direction. This package declares
 * `"type": "module"` and ships TypeScript SOURCE, so a bundler applying strict
 * ESM resolution looks for a literal `bytes.js`, finds nothing, and FAILS THE
 * BUILD of anything that imports this package. Verified: Turbopack in Next 16
 * cannot resolve `./aead.js` here and resolves `./aead` without complaint, and
 * `experimental.extensionAlias` does not help because it is webpack-only. Do
 * not put the extensions back without also giving this package a build step.
 */
export const VERSION = "sluice-crypto/v1";

export { constantTimeEqual, fromHex, randomBytes, toHex, utf8 } from "./bytes";

export { seal, unseal } from "./aead";
export type { SealedBox } from "./aead";

export { ARGON2_PARAMS, deriveMUK, MasterUnlockKey } from "./muk";
export type { DeriveMUKOptions } from "./muk";

/**
 * The Argon2 injection seam. `assertConformantArgon2` is the ONE runtime name
 * added for it, and `nobleArgon2` -- the default backend -- is deliberately NOT
 * exported alongside it.
 *
 * Exporting the default would invite `deriveMUK(pw, id, { argon2: nobleArgon2 })`
 * as a way of "being explicit", and that call site is indistinguishable in a
 * diff from one that pins the SLOW path on purpose. The default is reached by
 * omitting the option, which is the only spelling that cannot drift.
 *
 * `assertConformantArgon2` is exported because an application needs to prove a
 * WASM backend works BEFORE the user has typed a password -- at page load, in a
 * health check -- not at the moment of signup, where the only recovery left is
 * an error on a form the user has already filled in. `deriveMUK` runs the same
 * check itself, so this export is an early-warning hook and never a
 * prerequisite a caller can forget.
 */
export { assertConformantArgon2 } from "./argon2";
export type { Argon2Backend, Argon2Params } from "./argon2";

export {
  deriveTokenKeys,
  mintToken,
  MintedToken,
  parseToken,
  signHandshake,
  verifyHandshake,
} from "./token";
export type { TokenKeys } from "./token";

export { signRevocation, verifyRevocation } from "./revocation";
export type { RevocationNotice } from "./revocation";

/**
 * The three rules both ends of the wire must agree on, byte for byte.
 *
 * These are the only exports here that exist for a reason of LOCATION rather
 * than of function. None is novel cryptography: two are UTF-8 strings, the
 * third a domain-separated SHA-256. They are in this package because it is the
 * one module `convex/`, `apps/web` and `packages/sdk` all already depend on,
 * and because each of them, computed differently on two sides, fails without an
 * error anybody can act on -- an opaque AEAD rejection at read time, a
 * revocation query that joins on nothing, or a project data key that no client
 * can unwrap and no server can help with.
 *
 * `pdkAssociatedData` is the one the dashboard is blocked on: the reason org
 * creation stalled was that no document stated the associated data for a key
 * wrap, so nobody could write the client half without inventing a literal.
 *
 * `SECRET_AAD_PREFIX`, `PDK_AAD_PREFIX` and `TOKEN_ID_HASH_LABEL` are
 * deliberately NOT exported alongside them. A caller who can reach a prefix can
 * join the string themselves, at their own call site, without the validation --
 * which is exactly the hand-copied literal this move exists to delete. The only
 * way to obtain any of those values is to call the function that binds it.
 */
export { pdkAssociatedData, secretAssociatedData, tokenIdHash } from "./protocol";
export type { PDKGranteeType } from "./protocol";
