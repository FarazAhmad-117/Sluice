import { ConvexError } from "convex/values";

/**
 * THE CANONICAL HEX RULE, IN ONE PLACE.
 *
 * Lowercase only, no `0x` prefix, no whitespace, an even number of characters.
 * It is the rule `@sluice/crypto` enforces on every identifier it signs over,
 * and `toHex` is the only encoder that package exports, so it is also exactly
 * what a conforming client produces.
 *
 * Uppercase is REJECTED rather than folded. A value with two accepted
 * spellings is two different strings in an exact-match index and two different
 * inputs to a hash, so folding on the way in leaves the canonicalisation
 * decision inside one function that every future caller has to remember to
 * route through. Rejecting makes the client's encoding the only encoding.
 *
 * No message here echoes the value. These functions are handed ciphertext,
 * nonces and key material, and an error message travels into logs, error
 * reporters and support tickets.
 */
const LOWERCASE_HEX = /^[0-9a-f]+$/;

/**
 * `value` must be exactly `bytes` bytes in canonical hex.
 *
 * The length is checked in bytes rather than characters because every caller
 * thinks in bytes: a GCM nonce is 12, an Ed25519 key is 32. Writing the
 * character count at each call site is one doubling away from a bug.
 */
export function assertHexBytes(
  field: string,
  value: string,
  bytes: number,
): string {
  if (value.length !== bytes * 2 || !LOWERCASE_HEX.test(value)) {
    throw new ConvexError(
      `${field} must be ${bytes * 2} lowercase hex characters.`,
    );
  }
  return value;
}

/**
 * `value` must be canonical hex of at least `minBytes` bytes.
 *
 * Used for ciphertext, whose length is not fixed. There is a minimum because
 * AES-GCM appends a 16 byte authentication tag to every ciphertext, so
 * anything shorter than 16 bytes cannot be output this product produced. An
 * empty string passing as ciphertext is the failure this catches: it stores
 * cleanly, lists cleanly, and fails only when someone tries to decrypt it,
 * which may be months later and on the one row that mattered.
 */
export function assertHexAtLeast(
  field: string,
  value: string,
  minBytes: number,
): string {
  if (
    value.length < minBytes * 2 ||
    value.length % 2 !== 0 ||
    !LOWERCASE_HEX.test(value)
  ) {
    throw new ConvexError(
      `${field} must be at least ${minBytes * 2} lowercase hex characters, and an even number of them.`,
    );
  }
  return value;
}
