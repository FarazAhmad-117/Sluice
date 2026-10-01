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
 * BOTH WIDTHS ARE EXACT, NOT MINIMUMS. The nonce is 12 bytes (24 hex), the
 * AES-GCM nonce `seal` produces. The ciphertext is 48 bytes (96 hex): both
 * wrapped keys are 32-byte secrets (the X25519 private scalar and the Ed25519
 * seed), and AES-GCM adds a 16-byte tag and nothing else, so a `k1` blob can
 * have no other length. Pinning it exactly means a truncated, padded or
 * odd-length field is reported as `WrappedKeyFormatError` here rather than
 * surfacing as a bare hex-parsing error or an opaque AEAD rejection later. A
 * key type with a different plaintext width is a new `k2` version, never a
 * loosening of this one. The Rust CLI reproduces this grammar character for
 * character, so it is a protocol constant, not a validation detail.
 */
const BLOB_VERSION = "sluice.k1";
const NONCE_BYTES = 12;
const CIPHERTEXT_BYTES = 48;
const BLOB_PATTERN = /^sluice\.k1\.([0-9a-f]{24})\.([0-9a-f]{96})$/;

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
 * really an agreement key.
 *
 * Nothing identifying the account is bound in here, and that is deliberate.
 * The MUK is already unique per account, because its Argon2id salt is a random
 * per-account value (see `mukSalt` in `muk.ts`), so a blob moved to another
 * account's row already fails to open. The email in particular is NOT bound,
 * because it is mutable: binding it would make every address change a re-wrap
 * of both keys, for no protection the per-account MUK does not already give.
 */
const KEY_AAD_PREFIX = "sluice/user-key/v1|";

/** Which of the account's two private keys a wrapped blob holds. */
export type KeyPurpose = "x25519" | "ed25519";

export function userKeyAssociatedData(purpose: KeyPurpose): Uint8Array {
  // The type already says this, but a caller in plain JS (or behind a cast)
  // could pass "X25519" and get associated data that silently matches nothing
  // the other clients produce. Refusing is cheaper than that failure.
  if (purpose !== "x25519" && purpose !== "ed25519") {
    throw new Error("purpose must be x25519 or ed25519");
  }
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

/**
 * Serialises a sealed private key into the ratified `sluice.k1` blob.
 *
 * It enforces exactly what `decodeWrappedKey` enforces, so this function can
 * never emit a blob its own counterpart (or the CLI) would refuse. A wrong
 * width here means the caller sealed something other than a 32-byte key, and
 * finding that out at signup beats finding it out at the next login.
 */
export function encodeWrappedKey(box: SealedBox): string {
  if (box.nonce.length !== NONCE_BYTES || box.ciphertext.length !== CIPHERTEXT_BYTES) {
    // Lengths only; the bytes themselves never go into the message.
    throw new WrappedKeyFormatError(
      `A k1 wrapped key needs a ${NONCE_BYTES}-byte nonce and a ${CIPHERTEXT_BYTES}-byte ciphertext.`,
    );
  }
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
