import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import { concat, fromHex, randomBytes, toHex, utf8 } from "./bytes.js";

const TOKEN_ID_BYTES = 16;
const TOKEN_SECRET_BYTES = 32;

/**
 * HKDF `info` strings. These are the ONLY thing separating the two derived
 * keys: both come from the same input key material and the same salt, so if
 * these two constants were ever equal, or one were changed to match the other,
 * the server-verifiable auth key and the never-transmitted unwrap key would
 * become the same value and the zero-knowledge property would collapse.
 *
 * They are versioned because changing either one silently invalidates every
 * token already in the field. A new derivation gets a new `/v2` suffix rather
 * than an edit here.
 */
const AUTH_INFO = "sluice/auth/v1";
const UNWRAP_INFO = "sluice/unwrap/v1";

export interface TokenKeys {
  /** Ed25519 seed. Its PUBLIC half is uploaded; the seed itself never is. */
  authSeed: Uint8Array;
  /** Opens the project data key. NEVER transmitted, never stored server-side. */
  unwrapKey: Uint8Array;
}

/**
 * Splits a token secret into two independent keys.
 *
 * Argument order is `hkdf(hash, ikm, salt, info, length)`, so `tokenSecret` is
 * the input key material and `tokenId` is the salt. That is deliberate and not
 * interchangeable: the secret is the entropy being expanded, and the id is the
 * public, per-token value that binds the expansion. Because the id is the salt,
 * two tokens that somehow shared a secret -- a broken RNG, a copied fixture, a
 * restored backup -- still derive completely different keys.
 *
 * The two outputs are independent because HKDF-Expand runs HMAC-SHA256 over
 * distinct `info` strings from the same PRK. Recovering `unwrapKey` from
 * `authSeed` (or from the Ed25519 public key the server stores) would require
 * inverting HMAC-SHA256. This is the single function the product's central
 * claim rests on.
 */
export function deriveTokenKeys(tokenId: Uint8Array, tokenSecret: Uint8Array): TokenKeys {
  return {
    authSeed: hkdf(sha256, tokenSecret, tokenId, utf8.encode(AUTH_INFO), 32),
    unwrapKey: hkdf(sha256, tokenSecret, tokenId, utf8.encode(UNWRAP_INFO), 32),
  };
}

/**
 * The result of minting, containing secret material.
 *
 * DANGER: every field except `upload` is secret. `tokenSecret` reconstructs
 * both derived keys, and `unwrapKey` opens customer plaintext. This object must
 * be shown to the user exactly once, at creation, and never persisted
 * server-side in any form.
 *
 * Only `.upload` may cross the wire. Do not pass this whole object to a logger,
 * an error reporter, an analytics call or a response body. There is no runtime
 * guard against that: `JSON.stringify` turns a `Uint8Array` into
 * `{"0":12,"1":244,...}`, which is a complete and trivially reversible dump of
 * the secret, and `console.log` prints every byte. Destructure what you need.
 */
export interface MintedToken {
  /** The full `slc_<env>_<id>.<secret>` string. Secret. Show once, then drop. */
  token: string;
  tokenId: Uint8Array;
  /** Secret. Reconstructs authSeed and unwrapKey via {@link deriveTokenKeys}. */
  tokenSecret: Uint8Array;
  /** Secret. The Ed25519 private seed. */
  authSeed: Uint8Array;
  /** Secret. Never send this anywhere, ever. */
  unwrapKey: Uint8Array;
  /** The ONLY part of this object the server is allowed to receive. */
  upload: { tokenId: string; publicKey: string };
}

/**
 * Mints a new service token.
 *
 * The server receives `upload` and nothing else: a public token id and an
 * Ed25519 public key. From those it can verify a handshake signature, which
 * proves the caller holds the token secret, but it cannot derive `unwrapKey`
 * and therefore cannot read any secret it stores.
 *
 * `environment` is interpolated into the token string unvalidated. It must
 * match `[a-z0-9-]+` or {@link parseToken} will reject the token this function
 * just produced. See the note on that function.
 */
export function mintToken(opts: { environment: string }): MintedToken {
  const tokenId = randomBytes(TOKEN_ID_BYTES);
  const tokenSecret = randomBytes(TOKEN_SECRET_BYTES);
  const { authSeed, unwrapKey } = deriveTokenKeys(tokenId, tokenSecret);
  // Every 32-byte value is a valid Ed25519 seed: the seed is hashed with
  // SHA-512 and the scalar is clamped, so there is no weak or rejected seed and
  // no retry loop is needed. A 32-byte HKDF output always works.
  const publicKey = ed25519.getPublicKey(authSeed);

  return {
    token: `slc_${opts.environment}_${toHex(tokenId)}.${toHex(tokenSecret)}`,
    tokenId,
    tokenSecret,
    authSeed,
    unwrapKey,
    upload: { tokenId: toHex(tokenId), publicKey: toHex(publicKey) },
  };
}

/**
 * Parses a token string back into its id and secret.
 *
 * The pattern is deliberately strict and fully anchored. Lowercase hex only, so
 * a token that differs from another only by case cannot be accepted as the
 * same one. The environment segment excludes `_`, which keeps the separator
 * before the id unambiguous. Note that JavaScript's `$` without the `m` flag
 * matches only the true end of input, so a trailing newline is rejected rather
 * than tolerated.
 *
 * ASYMMETRY WITH `mintToken`: this rejects environments containing `_`, `.`,
 * uppercase letters, or nothing at all, but `mintToken` will happily build such
 * a token. Callers must constrain `environment` upstream.
 */
export function parseToken(token: string): { tokenId: Uint8Array; tokenSecret: Uint8Array } {
  const match = /^slc_[a-z0-9-]+_([0-9a-f]{32})\.([0-9a-f]{64})$/.exec(token);
  if (!match) throw new Error("malformed token");
  return { tokenId: fromHex(match[1] as string), tokenSecret: fromHex(match[2] as string) };
}

/**
 * Builds the bytes signed during a handshake.
 *
 * The encoding is unambiguous only because `tokenId` is fixed at
 * {@link TOKEN_ID_BYTES} bytes, which puts the boundary at a known offset. A
 * variable-length id WOULD create a concatenation ambiguity here: an id ending
 * in the byte `0x31` followed by timestamp `2` produces exactly the same bytes
 * as a one-byte-shorter id followed by timestamp `12`. Nothing in this file
 * enforces the length, so a caller that invents its own id length reintroduces
 * that ambiguity. Any change to the id width must add a length prefix.
 *
 * The timestamp is a decimal string, which is injective over the integer
 * seconds this is used with, but it is not a robust wire encoding: `-0` renders
 * identically to `0`, fractions render as `1.5`, magnitudes at or above 1e21
 * render as `1e+21`, and `NaN` and `Infinity` render as words. Callers must
 * pass a non-negative integer. The server's timestamp-window check is the
 * backstop; a `NaN` comparison there is always false, so it fails closed.
 */
function handshakeMessage(tokenId: Uint8Array, timestamp: number): Uint8Array {
  return concat(tokenId, utf8.encode(String(timestamp)));
}

/**
 * Signs a handshake, proving possession of the token secret.
 *
 * ED25519 SIGNATURES ARE DETERMINISTIC. The same token id and the same
 * timestamp always produce byte-identical output. This function therefore
 * provides AUTHENTICATION ONLY -- it is NOT replay protection. Anyone who
 * observes one handshake can resend it verbatim and it will verify.
 *
 * Whoever writes the `httpAction` MUST do both of these server-side:
 *   1. Reject any timestamp outside a narrow window around server time, and
 *   2. Remember signatures already seen inside that window and reject repeats.
 *
 * Without step 2 a captured handshake is replayable for the whole window.
 * Without step 1 it is replayable forever.
 */
export function signHandshake(
  tokenId: Uint8Array,
  tokenSecret: Uint8Array,
  timestamp: number,
): Uint8Array {
  const { authSeed } = deriveTokenKeys(tokenId, tokenSecret);
  return ed25519.sign(handshakeMessage(tokenId, timestamp), authSeed);
}

/**
 * Verifies a handshake signature against the stored public key.
 *
 * Returns `false` for every failure rather than throwing. Noble throws on a
 * wrong-length signature or public key and returns `false` on a well-formed but
 * incorrect one, and `fromHex` throws on non-hex input; the caller should not
 * have to distinguish those, and turning a malformed key into an exception
 * would give an attacker a way to tell "bad encoding" apart from "bad
 * signature". The `catch` is load-bearing, not defensive decoration.
 */
export function verifyHandshake(
  publicKeyHex: string,
  tokenId: Uint8Array,
  timestamp: number,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, handshakeMessage(tokenId, timestamp), fromHex(publicKeyHex));
  } catch {
    return false;
  }
}
