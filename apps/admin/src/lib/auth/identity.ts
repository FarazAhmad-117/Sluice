import { ed25519, x25519 } from "@noble/curves/ed25519";
import { MasterUnlockKey, fromHex, seal, toHex, unseal, utf8 } from "@sluice/crypto";
import type { SealedBox } from "@sluice/crypto";

/**
 * THE ACCOUNT IDENTITY: TWO KEYPAIRS, WRAPPED UNDER THE MASTER UNLOCK KEY.
 *
 * Everything the server ever receives about a user's keys is produced here:
 *
 *   publicKey          X25519 public half, 64 lowercase hex. PUBLIC.
 *   verifyKey          Ed25519 public half, 64 lowercase hex. PUBLIC.
 *   wrappedPrivateKey  X25519 private half, AES-256-GCM under the MUK. OPAQUE.
 *   wrappedSigningKey  Ed25519 seed, AES-256-GCM under the MUK. OPAQUE.
 *   authVerifier       HMAC of a fixed label under the MUK, 64 hex. NOT A KEY.
 *
 * THE MASTER UNLOCK KEY IS NOT IN THAT LIST AND NEVER WILL BE. Nothing in this
 * module serialises it, posts it, or stores it. It arrives as a
 * `MasterUnlockKey` instance, is used, and is dropped.
 *
 * ON THE HEX RULE, because it is the constraint that fails silently. Both
 * `publicKey` and `verifyKey` are checked server side by
 * `assertCanonicalHex32`: EXACTLY 64 LOWERCASE HEX CHARACTERS, no prefix, no
 * whitespace, no uppercase. Base64 is rejected, and so is an uppercase hex
 * string that every other tool would accept. `toHex` from `@sluice/crypto`
 * produces the canonical form (`b.toString(16).padStart(2, "0")` is lowercase),
 * so it is the only encoder used here and `btoa` appears nowhere.
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
 */
const BLOB_VERSION = "sluice.k1";
const BLOB_PATTERN = /^sluice\.k1\.([0-9a-f]{24})\.([0-9a-f]{32,})$/;

/**
 * Associated data for the two wrapped keys.
 *
 * This is NOT `secretAssociatedData`. That construction binds a secret to its
 * environment and is shared with the SDK and the backend; these blobs are
 * opened only by this client, so they get their own domain and their own
 * version. Mixing the two would let a secret ciphertext be presented as a
 * wrapped private key and vice versa.
 *
 * The purpose label is what stops the two blobs being swapped: a database
 * operator who writes the X25519 blob into `wrappedSigningKey` produces a row
 * that FAILS to decrypt rather than one that yields a signing key which is
 * really an agreement key. The account's own email is deliberately NOT bound in
 * here, because the MUK is already unique per account (the salt is the address)
 * so a cross-account swap already fails, and binding it would add a second
 * thing an email change would have to migrate.
 */
const KEY_AAD_PREFIX = "sluice/user-key/v1|";

type KeyPurpose = "x25519" | "ed25519";

function keyAssociatedData(purpose: KeyPurpose): Uint8Array {
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
 * WebCrypto rather than `@noble/hashes`: the browser has HMAC-SHA-256 built in,
 * `@sluice/crypto` does not export an HMAC, and reaching into `@noble/hashes`
 * from this application would be a phantom dependency that happens to resolve
 * through the root workspace today.
 */
export async function deriveAuthVerifier(muk: MasterUnlockKey): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    // `.bytes` is a deliberate unwrap, as its doc comment requires. The array
    // is handed straight to WebCrypto and is not retained here.
    new Uint8Array(muk.bytes).buffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new Uint8Array(utf8.encode(AUTH_VERIFIER_LABEL)).buffer,
  );
  // SHA-256 is 32 bytes, so this is 64 hex characters by construction, which
  // is exactly what `assertCanonicalHex32` demands.
  return toHex(new Uint8Array(signature));
}

function encodeBlob(box: SealedBox): string {
  return `${BLOB_VERSION}.${toHex(box.nonce)}.${toHex(box.ciphertext)}`;
}

export class WrappedKeyFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrappedKeyFormatError";
  }
}

function decodeBlob(blob: string): SealedBox {
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

/** The public half of an account identity, in the exact shape `signup` takes. */
export interface PublicIdentity {
  /** X25519, 64 lowercase hex. */
  readonly publicKey: string;
  /** Ed25519, 64 lowercase hex. */
  readonly verifyKey: string;
}

/** The private half. NEVER serialise, log, or persist an instance of this. */
export interface PrivateIdentity {
  /** X25519 private scalar, 32 bytes. */
  readonly privateKey: Uint8Array;
  /** Ed25519 seed, 32 bytes. Not the expanded secret. */
  readonly signingKey: Uint8Array;
}

export interface WrappedIdentity {
  readonly publicKey: string;
  readonly verifyKey: string;
  readonly wrappedPrivateKey: string;
  readonly wrappedSigningKey: string;
}

/**
 * Generates a fresh account identity and wraps its private halves under `muk`.
 *
 * Both keypairs come from `@noble/curves`, which draws from the platform CSPRNG
 * (`crypto.getRandomValues`). They are generated in the browser and the private
 * halves exist in plaintext only inside this function's frame and in the
 * returned `PrivateIdentity`; what goes on the wire is the public halves and
 * two AES-256-GCM ciphertexts.
 *
 * Returns the private identity as well as the wrapped form, because signup has
 * to go straight on to using it and re-deriving it would mean unwrapping what
 * was just wrapped.
 */
export async function createIdentity(
  muk: MasterUnlockKey,
): Promise<{ wrapped: WrappedIdentity; priv: PrivateIdentity; pub: PublicIdentity }> {
  const privateKey = x25519.utils.randomPrivateKey();
  const signingKey = ed25519.utils.randomPrivateKey();

  const pub: PublicIdentity = {
    publicKey: toHex(x25519.getPublicKey(privateKey)),
    verifyKey: toHex(ed25519.getPublicKey(signingKey)),
  };

  const [wrappedPrivateKey, wrappedSigningKey] = await Promise.all([
    seal(muk.bytes, privateKey, keyAssociatedData("x25519")).then(encodeBlob),
    seal(muk.bytes, signingKey, keyAssociatedData("ed25519")).then(encodeBlob),
  ]);

  return {
    wrapped: { ...pub, wrappedPrivateKey, wrappedSigningKey },
    priv: { privateKey, signingKey },
    pub,
  };
}

export class UnwrapFailedError extends Error {
  constructor() {
    // Deliberately says nothing about WHICH input was wrong. AES-GCM reports a
    // bare `OperationError` and there is no honest way to be more specific:
    // a wrong password, a tampered blob and a mismatched associated data all
    // look identical, which is what stops this being a decryption oracle.
    super("The wrapped keys for this account could not be opened.");
    this.name = "UnwrapFailedError";
  }
}

/**
 * Opens the two wrapped blobs `auth.login` returned.
 *
 * A rejection here means the derived MUK does not match the one that sealed
 * these blobs. In practice that is a wrong password, except that a wrong
 * password normally fails earlier, at `auth.login`, because the verifier is
 * derived from the same MUK. Reaching this failure with a successful login
 * therefore means something worse: a tampered row, a changed email, or a
 * changed derivation. It must never be swallowed and the undecrypted bytes must
 * never be used.
 */
export async function unwrapIdentity(
  muk: MasterUnlockKey,
  blobs: { wrappedPrivateKey: string; wrappedSigningKey: string },
): Promise<PrivateIdentity> {
  const privateBox = decodeBlob(blobs.wrappedPrivateKey);
  const signingBox = decodeBlob(blobs.wrappedSigningKey);
  try {
    const [privateKey, signingKey] = await Promise.all([
      unseal(muk.bytes, privateBox, keyAssociatedData("x25519")),
      unseal(muk.bytes, signingBox, keyAssociatedData("ed25519")),
    ]);
    return { privateKey, signingKey };
  } catch {
    throw new UnwrapFailedError();
  }
}

/**
 * Checks that an unwrapped private identity really is the one the server's
 * public material describes.
 *
 * This is cheap and it closes a real gap. AES-GCM authenticates the blob
 * against tampering, but it says nothing about whether the blob and the
 * `publicKey` column belong together: an operator who swaps one user's wrapped
 * blob for another's produces a bundle that unwraps fine under the wrong MUK
 * only if the MUKs match, but an operator who swaps only the PUBLIC column
 * produces an account that encrypts to a key it cannot read. That failure would
 * otherwise surface months later as a secret nobody can open.
 */
export function identityMatches(priv: PrivateIdentity, pub: PublicIdentity): boolean {
  return (
    toHex(x25519.getPublicKey(priv.privateKey)) === pub.publicKey &&
    toHex(ed25519.getPublicKey(priv.signingKey)) === pub.verifyKey
  );
}
