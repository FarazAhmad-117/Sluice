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
