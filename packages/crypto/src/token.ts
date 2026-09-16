import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import { concat, fromHex, randomBytes, toHex, utf8 } from "./bytes.js";
import { INSPECT_CUSTOM, PUBLIC_KEY_HEX_PATTERN } from "./internal.js";

const TOKEN_ID_BYTES = 16;
const TOKEN_SECRET_BYTES = 32;

/**
 * What {@link mintToken} will accept as an environment name.
 *
 * Deliberately TIGHTER than the environment class inside {@link parseToken}.
 * The parser allows a bare `-` and leading or trailing hyphens so it can still
 * read anything already issued; the minter refuses to create such a name in the
 * first place. Tightening the minter is safe, tightening the parser would
 * strand existing tokens.
 *
 * No `g` flag, deliberately: a global regex carries `lastIndex` across `.test`
 * calls and would alternate between pass and fail on the same input.
 */
const ENVIRONMENT_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

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

/**
 * The token id width is a load-bearing invariant, not a detail.
 *
 * {@link handshakeMessage} concatenates the id with a decimal timestamp and
 * relies on the id being a known fixed width to keep that encoding
 * unambiguous. Enforcing the width here is what makes the boundary real rather
 * than accidental. ANY future change to the id width must add an explicit
 * length prefix to the handshake message.
 */
function assertTokenId(tokenId: Uint8Array): void {
  if (tokenId.length !== TOKEN_ID_BYTES) {
    throw new Error(`tokenId must be ${TOKEN_ID_BYTES} bytes, got ${tokenId.length}`);
  }
}

/**
 * The token secret width, enforced rather than assumed.
 *
 * WHAT THIS STOPS, which is not a formality. Without it `deriveTokenKeys`
 * accepted a secret of ANY length, including zero bytes, and returned a
 * complete, self-consistent key pair: a `signHandshake` over an empty secret
 * produced a signature that `verifyHandshake` accepted. Because the token id is
 * public -- it is uploaded as `upload.tokenId` -- anyone who saw one could
 * recompute that token's `unwrapKey` and read customer plaintext. HKDF is
 * perfectly happy to expand nothing into 32 impressive-looking bytes; the
 * entropy has to be checked, because the maths will not check it.
 *
 * {@link mintToken} always supplies 32 random bytes and {@link parseToken}
 * enforces 64 hex characters, so the hole was unreachable until
 * `deriveTokenKeys` became part of the public surface. Every other
 * secret-bearing entry point in this package -- `importKey` in `aead.ts`,
 * `signRevocation` in `revocation.ts`, `MasterUnlockKey` in `muk.ts` -- already
 * checks its key length. This one checked only the PUBLIC id.
 */
function assertTokenSecret(tokenSecret: Uint8Array): void {
  if (tokenSecret.length !== TOKEN_SECRET_BYTES) {
    throw new Error(`tokenSecret must be ${TOKEN_SECRET_BYTES} bytes, got ${tokenSecret.length}`);
  }
}

/**
 * Constrains a handshake timestamp to values the decimal encoding renders
 * injectively.
 *
 * `String()` is injective over distinct doubles with exactly one exception:
 * `-0` renders as `"0"` and therefore collides with `0`. `Object.is` is the
 * only way to catch that, since `-0 < 0` is false and `Number.isSafeInteger(-0)`
 * is true. The safe-integer bound also excludes fractions, `NaN`, both
 * infinities, and magnitudes at or above 1e21 where `String` switches to
 * exponential notation.
 */
function assertTimestamp(timestamp: number): void {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || Object.is(timestamp, -0)) {
    throw new Error("timestamp must be a non-negative safe integer");
  }
}

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
  assertTokenId(tokenId);
  assertTokenSecret(tokenSecret);
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
 * server-side in any form. Only `.upload` may cross the wire.
 *
 * This is a CLASS rather than a plain object purely so that `toJSON` and the
 * inspect hook can live on the prototype. Without them, the most likely way to
 * lose a customer's secrets is not a flaw in the cryptography but a single
 * careless `logger.info({ minted })`: `JSON.stringify` renders a `Uint8Array`
 * as `{"0":12,"1":244,...}`, a complete and trivially reversible dump, and
 * `console.log` prints every byte. Both hooks below reduce that to the public
 * upload payload.
 *
 * LIMIT OF THE PROTECTION, stated plainly: redaction lives on the prototype, so
 * it is lost the moment the instance is reshaped. `{ ...minted }` and
 * `structuredClone(minted)` both produce a bare object that dumps everything.
 * Pass `minted.upload` explicitly rather than spreading or copying this value.
 */
export class MintedToken {
  /** The full `slc_<env>_<id>.<secret>` string. Secret. Show once, then drop. */
  readonly token: string;
  readonly tokenId: Uint8Array;
  /** Secret. Reconstructs authSeed and unwrapKey via {@link deriveTokenKeys}. */
  readonly tokenSecret: Uint8Array;
  /** Secret. The Ed25519 private seed. */
  readonly authSeed: Uint8Array;
  /** Secret. Never send this anywhere, ever. */
  readonly unwrapKey: Uint8Array;
  /** The ONLY part of this object the server is allowed to receive. */
  readonly upload: { tokenId: string; publicKey: string };

  constructor(fields: {
    token: string;
    tokenId: Uint8Array;
    tokenSecret: Uint8Array;
    authSeed: Uint8Array;
    unwrapKey: Uint8Array;
    upload: { tokenId: string; publicKey: string };
  }) {
    this.token = fields.token;
    this.tokenId = fields.tokenId;
    this.tokenSecret = fields.tokenSecret;
    this.authSeed = fields.authSeed;
    this.unwrapKey = fields.unwrapKey;
    this.upload = fields.upload;
  }

  /**
   * Serialises to the public upload payload only.
   *
   * Every JSON path -- a log line, an error report, a response body, a queue
   * message -- routes through here, so a secret cannot reach one by accident.
   */
  toJSON(): { upload: { tokenId: string; publicKey: string } } {
    return { upload: this.upload };
  }

  /** Keeps `console.log(minted)` from printing the secret bytes. */
  [INSPECT_CUSTOM](): string {
    return "[MintedToken redacted]";
  }
}

/**
 * Mints a new service token.
 *
 * The server receives `upload` and nothing else: a public token id and an
 * Ed25519 public key. From those it can verify a handshake signature, which
 * proves the caller holds the token secret, but it cannot derive `unwrapKey`
 * and therefore cannot read any secret it stores.
 *
 * Validates `environment` up front. Without this check the minter could emit a
 * token its own {@link parseToken} rejects -- an environment containing `_`,
 * `.`, an uppercase letter, or nothing at all -- and the failure would surface
 * at the customer's first CLI call rather than here.
 */
export function mintToken(opts: { environment: string }): MintedToken {
  if (!ENVIRONMENT_PATTERN.test(opts.environment)) {
    throw new Error(
      `environment must match ${ENVIRONMENT_PATTERN.source}, got ${JSON.stringify(opts.environment)}`,
    );
  }

  const tokenId = randomBytes(TOKEN_ID_BYTES);
  const tokenSecret = randomBytes(TOKEN_SECRET_BYTES);
  const { authSeed, unwrapKey } = deriveTokenKeys(tokenId, tokenSecret);
  // Every 32-byte value is a valid Ed25519 seed: the seed is hashed with
  // SHA-512 and the scalar is clamped, so there is no weak or rejected seed and
  // no retry loop is needed. A 32-byte HKDF output always works.
  const publicKey = ed25519.getPublicKey(authSeed);

  return new MintedToken({
    token: `slc_${opts.environment}_${toHex(tokenId)}.${toHex(tokenSecret)}`,
    tokenId,
    tokenSecret,
    authSeed,
    unwrapKey,
    upload: { tokenId: toHex(tokenId), publicKey: toHex(publicKey) },
  });
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
 * The environment class here is looser than {@link ENVIRONMENT_PATTERN} on
 * purpose, so this can still read tokens issued before the minter tightened.
 *
 * `environment` is RETURNED rather than discarded. It is in the token, the
 * minter validates it, and leaving it out meant any consumer who needed it
 * would write `token.split("_")[1]` -- re-implementing this module's parsing,
 * without the anchored pattern, on a string whose second half is a secret.
 */
export function parseToken(token: string): {
  environment: string;
  tokenId: Uint8Array;
  tokenSecret: Uint8Array;
} {
  const match = /^slc_([a-z0-9-]+)_([0-9a-f]{32})\.([0-9a-f]{64})$/.exec(token);
  if (!match) throw new Error("malformed token");
  return {
    environment: match[1] as string,
    tokenId: fromHex(match[2] as string),
    tokenSecret: fromHex(match[3] as string),
  };
}

/**
 * Builds the bytes signed during a handshake.
 *
 * The encoding is unambiguous because {@link assertTokenId} pins the id to a
 * fixed width, putting the boundary at a known offset. Were the id ever
 * variable-length, this concatenation would be ambiguous: an id ending in the
 * byte `0x31` followed by timestamp `2` produces exactly the same bytes as a
 * one-byte-shorter id followed by timestamp `12`. Any change to the id width
 * must add an explicit length prefix here.
 *
 * Both guards run on the verify path too, so malformed input is rejected before
 * it can be attributed to a signature mismatch.
 */
function handshakeMessage(tokenId: Uint8Array, timestamp: number): Uint8Array {
  assertTokenId(tokenId);
  assertTimestamp(timestamp);
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
 * Without step 1 it is replayable forever. The {@link assertTimestamp} guard
 * here only rejects nonsense values; it knows nothing about server clocks and
 * is not a substitute for either check.
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
 * Returns `false` for every failure rather than throwing, including a
 * wrong-width token id and an out-of-range timestamp. Noble throws on a
 * wrong-length signature or public key and returns `false` on a well-formed but
 * incorrect one, and `fromHex` throws on non-hex input; the caller should not
 * have to distinguish those, and turning a malformed input into an exception
 * would give an attacker a way to tell "bad encoding" apart from "bad
 * signature". The `catch` is load-bearing, not defensive decoration.
 *
 * The public key must be CANONICAL lowercase hex. An uppercased key decodes to
 * the same bytes and would otherwise verify, giving one token two spellings
 * that a caller's replay cache or rate-limit bucket would treat as two
 * identities. See {@link PUBLIC_KEY_HEX_PATTERN}.
 */
export function verifyHandshake(
  publicKeyHex: string,
  tokenId: Uint8Array,
  timestamp: number,
  signature: Uint8Array,
): boolean {
  if (!PUBLIC_KEY_HEX_PATTERN.test(publicKeyHex)) return false;
  try {
    return ed25519.verify(signature, handshakeMessage(tokenId, timestamp), fromHex(publicKeyHex));
  } catch {
    return false;
  }
}
