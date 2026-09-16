/**
 * Internals shared by more than one module.
 *
 * NOTHING HERE IS EXPORTED FROM `index.ts`, and `test/index.test.ts` pins that
 * by asserting the public surface exactly. This module exists so that a value
 * two modules must agree on is DECLARED once rather than copied, since two
 * copies are two things that can drift apart. Anything a consumer needs belongs
 * in the module that owns it, not here.
 */

/**
 * The symbol Node's formatter, and therefore `console.log`, looks up on a value
 * to find a custom representation.
 *
 * `MintedToken` and `MasterUnlockKey` both key their redaction hook off this.
 * `Symbol.for` returns the GLOBAL interned symbol, so separate declarations
 * would in fact have produced the same symbol -- but "would have" is not a
 * guarantee anyone should have to re-derive. A third redacting class that keyed
 * its hook off a locally created `Symbol()` instead would silently print raw
 * key bytes, and the only thing preventing that is that there is one name to
 * import.
 *
 * `unique symbol` is a TypeScript-level assertion, needed so the symbol can be
 * used as a computed property name in a class declaration.
 */
export const INSPECT_CUSTOM: unique symbol = Symbol.for("nodejs.util.inspect.custom");

/**
 * The one legal spelling of an Ed25519 public key on this package's boundary:
 * exactly 64 LOWERCASE hex characters, fully anchored.
 *
 * WHY REJECTION AND NOT NORMALISATION. `fromHex` accepts `[0-9a-fA-F]`, so an
 * uppercased public key decodes to identical bytes and used to verify exactly
 * as well as the lowercase form `toHex` emits. Two strings, one identity, both
 * returning true. Lowercasing the input before decoding would therefore change
 * nothing observable -- the second spelling has to STOP VERIFYING for the
 * ambiguity to be gone. Callers key real state on these strings: a replay
 * cache, a rate-limit bucket, a per-token epoch table. Two spellings means two
 * entries, and each one misses what the other recorded.
 *
 * This matches the strictness `parseToken` and revocation's `TOKEN_ID_PATTERN`
 * already apply to the values THEY accept, so the whole surface now agrees.
 * Nothing this package produces is affected: `toHex` only ever emits lowercase.
 *
 * The length is pinned here too, which makes the guard the single place that
 * states what a public key looks like rather than leaving it to Noble to throw
 * about point decoding.
 *
 * No `g` flag, deliberately: a global regex carries `lastIndex` across `.test`
 * calls and would alternate between pass and fail on the same input.
 */
export const PUBLIC_KEY_HEX_PATTERN = /^[0-9a-f]{64}$/;
