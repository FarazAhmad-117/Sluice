import { ConvexError } from "convex/values";
import { sha256 } from "@noble/hashes/sha256";
import { fromHex, toHex } from "@sluice/crypto";

/**
 * The canonical-hex rule. Lowercase only, exactly 64 characters, no prefix and
 * no surrounding whitespace, which is the same rule `@sluice/crypto` enforces
 * on every identifier it signs over.
 *
 * Uppercase is rejected rather than accepted and folded. A value that has two
 * accepted spellings hashes to two different strings, so folding on the way in
 * would leave the canonicalisation decision in one function that every future
 * caller has to remember to route through. Rejecting makes the client's
 * encoding the only encoding.
 */
const CANONICAL_HEX_32 = /^[0-9a-f]{64}$/;

export function assertCanonicalHex32(field: string, value: string): string {
  if (!CANONICAL_HEX_32.test(value)) {
    // The message names the field and never echoes the value. `authVerifier`
    // is password-adjacent and an error message travels into logs.
    throw new ConvexError(`${field} must be 64 lowercase hex characters.`);
  }
  return value;
}

/**
 * Hashes the client-computed auth verifier for storage.
 *
 * Task 5 stores a bare SHA-256 so that the row never holds the submitted
 * verifier. The server pepper lands in Task 6 and replaces this body; the
 * function exists now so there is one call site to change.
 */
export function hashAuthVerifier(authVerifier: string): string {
  assertCanonicalHex32("authVerifier", authVerifier);
  return toHex(sha256(fromHex(authVerifier)));
}
