import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import type { SealedBox } from "./aead";
import { fromHex, toHex, utf8 } from "./bytes";
import type { MasterUnlockKey } from "./muk";

/**
 * THE THREE ACCOUNT-IDENTITY CONSTANTS THAT BECOME PERMANENT AT FIRST SIGNUP.
 *
 * The dashboard invented these, and they were correct, but they lived in an
 * application. That stops being tolerable the moment a second client exists:
 * the Rust CLI has to derive the same verifier, parse the same blob and bind
 * the same associated data, BYTE FOR BYTE, or a user who signed up in the
 * browser cannot log in from a terminal. Every one of the three fails silently
 * when two sides disagree -- a login rejected as a wrong password, a blob
 * reported as an unknown format, an AEAD rejection with no reason attached --
 * so they are defined once, here, and pinned by known-answer vectors in
 * `test/identity.test.ts` that were computed independently of this code.
 *
 * NOTHING HERE MAY BE EDITED IN PLACE once a real account exists. A change to
 * any label or to the blob layout is a new version and a migration, never an
 * edit to the current one.
 */

/**
 * The wrapped-blob format. Version first, so a later format is distinguishable
 * rather than merely unparseable.
 *
 * `sluice.k1.<nonceHex>.<ciphertextHex>`
 *
 * Both fields are lowercase hex and the separator is not in the hex alphabet,
 * so the string has exactly one reading. The server treats it as an opaque
 * string and validates only that it is non-empty; every constraint on it is
 * enforced here, at both ends of the round trip.
 *
 * The nonce is exactly 12 bytes (24 hex), the AES-GCM nonce `seal` produces.
 * The ciphertext is at least 16 bytes (32 hex), because the GCM tag alone is
 * 16 bytes and anything shorter cannot be a real ciphertext.
 */
const BLOB_VERSION = "sluice.k1";
const BLOB_PATTERN = /^sluice\.k1\.([0-9a-f]{24})\.([0-9a-f]{32,})$/;

/**
 * Associated data for the two wrapped keys.
 *
 * This is NOT `secretAssociatedData`. That construction binds a secret to its
 * environment and is shared with the SDK and the backend; these blobs are
 * opened only by the account's own clients, so they get their own domain and
 * their own version. Mixing the two would let a secret ciphertext be presented
 * as a wrapped private key and vice versa.
 *
 * The purpose label is what stops the two blobs being swapped: a database
 * operator who writes the X25519 blob into `wrappedSigningKey` produces a row
 * that FAILS to decrypt rather than one that yields a signing key which is
 * really an agreement key. The account's own email is deliberately NOT bound in
 * here, because the MUK is already unique per account (the salt is derived per
 * account) so a cross-account swap already fails, and binding it would add a
 * second thing an email change would have to migrate.
 */
const KEY_AAD_PREFIX = "sluice/user-key/v1|";

/** Which of the account's two private keys a wrapped blob holds. */
export type KeyPurpose = "x25519" | "ed25519";

export function userKeyAssociatedData(purpose: KeyPurpose): Uint8Array {
  return utf8.encode(KEY_AAD_PREFIX + purpose);
}

/**
 * Domain label for the auth verifier. Versioned, and bumping it would
 * invalidate every stored verifier on the deployment, so it is a new label and
 * a migration, never an edit to this one.
 */
const AUTH_VERIFIER_LABEL = "sluice/auth-verifier/v1";

/**
 * THE AUTH VERIFIER, AND WHY IT IS NOT THE MASTER UNLOCK KEY.
 *
 * `HMAC-SHA256(key = MUK, message = "sluice/auth-verifier/v1")`, hex encoded.
 *
 * The one rule this construction has to satisfy is that the server must be able
 * to authenticate the account WITHOUT being able to unlock it. HMAC is
 * preimage resistant under a secret key, so a server holding the verifier (and
 * an attacker holding a dump of `users.authVerifierHash`) cannot work back to
 * the MUK. Sending the MUK itself, or a truncation of it, would hand the root
 * of the key hierarchy to the one party the design says must never hold it.
 *
 * It reuses the SINGLE Argon2id derivation rather than running a second one.
 * That is the whole point of deriving it from the MUK: a second Argon2id pass
 * at the same parameters would cost the user another 64 MiB and another 1.6
 * seconds on every login for no security whatsoever, since the two outputs
 * would be equally unguessable either way.
 *
 * `@noble/hashes` rather than WebCrypto, and synchronous as a result. This
 * package runs in Node, in browsers, and later in the known-answer vector
 * generator the Rust CLI is checked against, and WebCrypto is not uniform
 * across those: `crypto.subtle` is absent on insecure origins, differs in its
 * global between Node versions, and is async only. HMAC-SHA-256 is the same
 * function either way -- the KAT in `test/identity.test.ts` was computed with
 * `node:crypto` and pins that this implementation reproduces the one the
 * dashboard shipped with.
 *
 * SHA-256 is 32 bytes, so the result is 64 lowercase hex characters by
 * construction, which is exactly what `assertCanonicalHex32` on the server
 * demands.
 */
export function deriveAuthVerifier(muk: MasterUnlockKey): string {
  // `.bytes` is a deliberate unwrap, as its doc comment requires. The array is
  // used as the HMAC key and is not retained here.
  return toHex(hmac(sha256, muk.bytes, utf8.encode(AUTH_VERIFIER_LABEL)));
}

export class WrappedKeyFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrappedKeyFormatError";
  }
}

/** Serialises a sealed private key into the ratified `sluice.k1` blob. */
export function encodeWrappedKey(box: SealedBox): string {
  return `${BLOB_VERSION}.${toHex(box.nonce)}.${toHex(box.ciphertext)}`;
}

/**
 * Parses a `sluice.k1` blob. Throws `WrappedKeyFormatError` for anything that
 * is not exactly that format, including a well-formed blob of a LATER version,
 * which this code must refuse rather than guess at.
 */
export function decodeWrappedKey(blob: string): SealedBox {
  const match = BLOB_PATTERN.exec(blob);
  if (match === null) {
    // The message does not echo the blob. It is ciphertext rather than a
    // secret, but an error string travels into places a key bundle should not.
    throw new WrappedKeyFormatError(
      "This account's wrapped key is not in a format this client understands.",
    );
  }
  return {
    nonce: fromHex(match[1] as string),
    ciphertext: fromHex(match[2] as string),
  };
}
