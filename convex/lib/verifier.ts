import { ConvexError } from "convex/values";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { constantTimeEqual, fromHex, toHex, utf8 } from "@sluice/crypto";

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
 * WHY A PASSWORD-ADJACENT VALUE GETS A FAST HASH
 *
 * A reviewer should ask this, so here is the answer before they do.
 *
 * `authVerifier` is not a password. The client already paid the Argon2id cost:
 * it derived the master unlock key from the password with Argon2id at the
 * parameters `@sluice/crypto` pins, and derived this verifier by a separate
 * path from the same expensive work. What arrives here is a 256-bit value with
 * full entropy, so there is nothing to brute-force. An attacker holding a
 * database dump cannot guess a 256-bit input at any hash speed, which means
 * slowing the hash down buys nothing.
 *
 * What a dump-only attacker CAN do without a pepper is precompute, and confirm
 * a verifier obtained elsewhere against the table. The pepper closes that,
 * because it lives in deployment configuration rather than in the row, so a
 * dump on its own is not enough to test a candidate.
 *
 * Running Argon2id again on the server would add no security and would cost a
 * great deal. Argon2id at these parameters allocates a single 64 MiB buffer,
 * which is the entire budget of Convex's default runtime. Every login would
 * have to become a `"use node"` action for the 512MB runtime, which means an
 * action rather than a mutation, which means no transaction and a separate
 * retry story, all to defend against an attack that cannot happen.
 *
 * The pepper and the JWT signing key are the only secrets this server holds,
 * and neither can decrypt customer data. Losing the pepper invalidates every
 * stored verifier and locks everyone out of login; it does not expose a
 * secret, because a verifier is not a key to anything the server stores.
 */
function pepper(): Uint8Array {
  const value = process.env.AUTH_PEPPER;

  // Loud, not lenient. A missing pepper that fell back to an unpeppered hash
  // would leave signup and login working perfectly while every stored hash
  // quietly lost the only property it was added for, and nothing would ever
  // surface it.
  if (value === undefined || value.length === 0) {
    throw new ConvexError("AUTH_PEPPER is not set on this deployment.");
  }

  // The same canonical rule as everything else here, and exactly what
  // `randomBytes(32).toString("hex")` produces. A pepper that is a memorable
  // string rather than 32 random bytes is the quiet failure this catches: it
  // would work, and it would be guessable. The message deliberately does not
  // echo the configured value.
  if (!CANONICAL_HEX_32.test(value)) {
    throw new ConvexError("AUTH_PEPPER must be 64 lowercase hex characters.");
  }

  return fromHex(value);
}

/**
 * A value of exactly the shape of a stored hash, for the login path to compare
 * against when no account matches.
 *
 * Without it, "no such account" skips the comparison entirely and the endpoint
 * answers faster for an address nobody has registered, which is an enumeration
 * oracle measured in microseconds rather than in error strings. It is derived
 * under the pepper so it is unguessable, and its message is a UTF-8 domain
 * string rather than 32 raw bytes, so no real verifier can ever hash to it.
 */
export function decoyVerifierHash(): string {
  return toHex(
    hmac(sha256, pepper(), utf8.encode("sluice/auth/decoy/v1")),
  );
}

/**
 * True when `candidate` and `stored` are the same digest, compared in time
 * that does not depend on where they differ.
 *
 * A stored hash that is not canonical hex cannot be decoded, so it compares
 * against the decoy instead and fails. The alternative is `fromHex` throwing a
 * different error for a corrupted row, which would be one more way for the
 * caller to tell two accounts apart.
 */
export function verifierHashEquals(candidate: string, stored: string): boolean {
  const comparable = CANONICAL_HEX_32.test(stored) ? stored : decoyVerifierHash();
  return constantTimeEqual(fromHex(candidate), fromHex(comparable));
}

/**
 * `HMAC-SHA256(key = pepper, message = authVerifier)`.
 *
 * The pepper is the key, not a prefix on the message. `sha256(pepper || value)`
 * is length-extendable and has an ambiguous encoding at the join; HMAC is the
 * construction designed for a secret key, so it is the one used.
 */
export function hashAuthVerifier(authVerifier: string): string {
  assertCanonicalHex32("authVerifier", authVerifier);
  return toHex(hmac(sha256, pepper(), fromHex(authVerifier)));
}
