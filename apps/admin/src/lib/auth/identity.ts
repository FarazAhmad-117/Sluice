import { ed25519, x25519 } from "@noble/curves/ed25519";
import {
  MasterUnlockKey,
  decodeWrappedKey,
  encodeWrappedKey,
  seal,
  toHex,
  unseal,
  userKeyAssociatedData,
} from "@sluice/crypto";

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
 *
 * WHAT IS NOT DEFINED HERE ANY MORE. The auth verifier construction, the
 * `sluice.k1` blob format and the per-purpose associated data used to live in
 * this file. They are now in `@sluice/crypto` (`src/identity.ts`), pinned by
 * known-answer vectors, because the CLI has to reproduce all three byte for
 * byte to open an account the browser created. This file keeps only what is
 * specific to the dashboard: generating the keypairs and composing the
 * package's pieces into a signup and a login.
 *
 * `deriveAuthVerifier` is re-exported because two modules import it from here
 * (`auth-context.tsx` and the end-to-end test in `convex/secrets.test.ts`), and
 * signup and login read better with the whole identity behind one import.
 * `WrappedKeyFormatError` is deliberately not re-exported: nothing imports it,
 * and `messageForUser` recognises it by `name`, not by class.
 */
export { deriveAuthVerifier } from "@sluice/crypto";

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
    seal(muk.bytes, privateKey, userKeyAssociatedData("x25519")).then(encodeWrappedKey),
    seal(muk.bytes, signingKey, userKeyAssociatedData("ed25519")).then(encodeWrappedKey),
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
  const privateBox = decodeWrappedKey(blobs.wrappedPrivateKey);
  const signingBox = decodeWrappedKey(blobs.wrappedSigningKey);
  try {
    const [privateKey, signingKey] = await Promise.all([
      unseal(muk.bytes, privateBox, userKeyAssociatedData("x25519")),
      unseal(muk.bytes, signingBox, userKeyAssociatedData("ed25519")),
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
