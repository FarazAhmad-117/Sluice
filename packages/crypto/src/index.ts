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
 */
export const VERSION = "sluice-crypto/v1";

export { constantTimeEqual, fromHex, randomBytes, toHex, utf8 } from "./bytes.js";

export { seal, unseal } from "./aead.js";
export type { SealedBox } from "./aead.js";

export { ARGON2_PARAMS, deriveMUK, MasterUnlockKey } from "./muk.js";

export {
  deriveTokenKeys,
  mintToken,
  MintedToken,
  parseToken,
  signHandshake,
  verifyHandshake,
} from "./token.js";
export type { TokenKeys } from "./token.js";

export { signRevocation, verifyRevocation } from "./revocation.js";
export type { RevocationNotice } from "./revocation.js";
