import { ConvexError } from "convex/values";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { constantTimeEqual, fromHex, utf8 } from "@sluice/crypto";

/**
 * THE BUNDLE TOKEN: WHAT THE HANDSHAKE ISSUES AND WHAT THE BUNDLE READS.
 *
 * A service token proves possession once, over the handshake endpoint, with an
 * Ed25519 signature. It cannot keep proving it on every frame of a live
 * subscription, so the handshake trades that one proof for a short-lived
 * bearer credential, and this file is both ends of that credential.
 *
 * WHY A JWT HERE WHEN `sessions` IS A DATABASE TABLE. The long note at the top
 * of `session.ts` explains why dashboard sessions are stored rows: a verified
 * JWT cannot be logged out, and a security product whose wedge is instant
 * revocation cannot ship a credential that outlives the decision to revoke.
 * Every word of that is still true. It does not apply here, and the reason is
 * worth writing down rather than leaving as an apparent inconsistency:
 *
 *   REVOCATION DOES NOT TRAVEL THROUGH THIS TOKEN. It travels through the
 *   BUNDLE, which is a reactive query that re-runs the instant a `revocations`
 *   row lands and pushes the signed notice to every live subscriber. Killing
 *   the bearer token would not revoke anything; it would merely disconnect the
 *   process that most needs to be told. The bundle deliberately keeps serving
 *   a revoked token so that the notice reaches it.
 *
 * So this credential carries no authority beyond "read one environment's
 * ciphertext", it lives five minutes, and it is stateless because the state
 * that matters lives in `serviceTokens.status` and `revocations`, both of which
 * the bundle reads on every run.
 *
 * WHAT IS IN IT: the Convex document id of the `serviceTokens` row, and
 * nothing else identifying. NOT the plaintext token id. That was the obvious
 * shortcut, because `revocations` carries the plaintext id and a bundle query
 * holding it could join directly. It would also push the exact identifier
 * `serviceTokens.tokenIdHash` exists to protect into a bearer token, into SDK
 * memory, and into every log line that prints a JWT. The bundle reads the hash
 * off the row instead, which costs one document read it was making anyway.
 *
 * HS256 RATHER THAN AN ASYMMETRIC ALGORITHM, deliberately. Nobody outside this
 * deployment verifies this token: it is minted by the handshake and read by
 * the bundle, both here. A public key would buy third party verification that
 * nothing wants and would add key distribution to a thing that lives five
 * minutes. The signing key never leaves the deployment configuration, and it
 * cannot decrypt anything: like `AUTH_PEPPER`, losing it invalidates live
 * bundle tokens and exposes no customer data.
 *
 * NOTHING HERE PARSES `alg` TO DECIDE WHAT TO DO. The algorithm is pinned as a
 * constant and the header is compared against it. That is the whole of the
 * classic JWT algorithm confusion family, including `alg: "none"`, closed by
 * construction rather than by a check somebody has to remember.
 */

/**
 * Five minutes. Long enough that a handshake is not on the hot path of every
 * reconnect, short enough that a leaked token is worthless before anyone could
 * notice it leaked. It is an absolute deadline with no renewal, for the reason
 * `SESSION_LIFETIME_MS` gives: a sliding window makes a stolen credential
 * immortal.
 */
export const BUNDLE_TOKEN_LIFETIME_MS = 5 * 60 * 1000;

/**
 * Pinned, not read. See the header.
 *
 * `typ` is pinned too so that a token minted for some other purpose under the
 * same key can never be presented here, which is the same domain separation
 * every digest in this codebase gets.
 */
const HEADER = { alg: "HS256", typ: "JWT" } as const;

const ISSUER = "sluice";

/**
 * The audience label is the domain separator between this credential and any
 * future one signed under the same key. A token minted for a different purpose
 * must not open a bundle, and the only thing that can enforce that is a claim
 * the verifier requires rather than merely tolerates.
 */
const AUDIENCE = "sluice/bundle/v1";

const SIGNING_KEY_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Base64url, no padding, as RFC 7515 requires.
 *
 * Hand-rolled rather than reached for through `btoa`, which is defined over
 * binary strings and would need a second encoding step from bytes, and whose
 * availability across Convex's default runtime and the test runtime is one more
 * thing to be wrong about. This is thirty lines and has no ambient dependency.
 */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function base64UrlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const hasB1 = i + 1 < bytes.length;
    const hasB2 = i + 2 < bytes.length;
    const b1 = hasB1 ? (bytes[i + 1] as number) : 0;
    const b2 = hasB2 ? (bytes[i + 2] as number) : 0;

    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 0b11) << 4) | (b1 >> 4)];
    if (!hasB1) break;
    out += ALPHABET[((b1 & 0b1111) << 2) | (b2 >> 6)];
    if (!hasB2) break;
    out += ALPHABET[b2 & 0b111111];
  }
  return out;
}

/**
 * STRICT. Padding is rejected, characters outside the alphabet are rejected,
 * and a final partial group whose unused bits are not zero is rejected.
 *
 * That last rule is the one that is easy to leave out and the one that matters.
 * Without it a single token has several spellings that all decode to the same
 * bytes, so one credential presents as several distinct strings, and any cache,
 * rate limit bucket or replay record keyed on the string counts them as
 * different callers. It is the same split-identity problem
 * `PUBLIC_KEY_HEX_PATTERN` closes for hex.
 */
function base64UrlDecode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new Error("not base64url");

  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let accumulator = 0;
  let bits = 0;
  let written = 0;

  for (let i = 0; i < text.length; i++) {
    const value = ALPHABET.indexOf(text[i] as string);
    if (value < 0) throw new Error("not base64url");
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written++] = (accumulator >> bits) & 0xff;
    }
  }
  if ((accumulator & ((1 << bits) - 1)) !== 0) throw new Error("not canonical");

  return out.subarray(0, written);
}

function encodeJson(value: unknown): string {
  return base64UrlEncode(utf8.encode(JSON.stringify(value)));
}

/**
 * Loud, not lenient, exactly like `pepper()` in `verifier.ts`.
 *
 * A missing key that fell back to an empty one would leave the handshake and
 * the bundle working perfectly while every token in the fleet became forgeable
 * by anyone who read this file, and nothing would ever surface it.
 */
function signingKey(): Uint8Array {
  const value = process.env.JWT_SIGNING_KEY;
  if (value === undefined || value.length === 0) {
    throw new ConvexError("JWT_SIGNING_KEY is not set on this deployment.");
  }
  // The same canonical rule as everything else here, and exactly what
  // `randomBytes(32).toString("hex")` produces. A memorable string would work
  // and would be guessable. The message never echoes the configured value.
  if (!SIGNING_KEY_PATTERN.test(value)) {
    throw new ConvexError("JWT_SIGNING_KEY must be 64 lowercase hex characters.");
  }
  return fromHex(value);
}

/**
 * Fails now, rather than after the caller has already changed the database.
 *
 * The handshake consumes a replay nonce and writes an audit row before it has
 * any use for a signed token. If the key turned out to be missing at THAT
 * point, the transaction would roll back and the deployment would look merely
 * broken, but the shape of the failure would depend on how far the mutation got
 * rather than on the configuration. Calling this first makes a misconfigured
 * deployment refuse everything identically and touch nothing.
 */
export function assertBundleSigningKey(): void {
  signingKey();
}

function sign(signingInput: string): string {
  return base64UrlEncode(hmac(sha256, signingKey(), utf8.encode(signingInput)));
}

export interface BundleTokenClaims {
  /** The `serviceTokens` document id this credential speaks for. */
  subject: string;
}

/**
 * Mints a bundle token for one service token document.
 *
 * `now` is passed in rather than read here so that the whole of this module is
 * a pure function of its inputs and its key. The caller is a Convex mutation,
 * where `Date.now()` is fixed for the transaction, and a clock read hidden
 * inside a signing function is a thing no test can pin.
 */
export function signBundleToken(params: {
  subject: string;
  now: number;
}): string {
  const { subject, now } = params;
  if (typeof subject !== "string" || subject.length === 0) {
    throw new ConvexError("subject must be a non-empty string.");
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new ConvexError("now must be a non-negative safe integer.");
  }

  const signingInput = `${encodeJson(HEADER)}.${encodeJson({
    iss: ISSUER,
    aud: AUDIENCE,
    sub: subject,
    iat: now,
    exp: now + BUNDLE_TOKEN_LIFETIME_MS,
  })}`;
  return `${signingInput}.${sign(signingInput)}`;
}

/**
 * The claims, or `null` for every kind of invalid token.
 *
 * `null` rather than a thrown error for anything the caller supplied, matching
 * `verifyHandshake` and `verifyRevocation`: a caller deciding whether to serve
 * a bundle must not be able to tell "bad encoding" from "bad signature" from
 * "expired", because that difference is a free oracle and there is nothing
 * useful it could do with the answer.
 *
 * A missing or malformed SIGNING KEY still throws. That is not a property of
 * the presented token, it is a broken deployment, and answering `null` would
 * turn a configuration error into "every token in the fleet is forged".
 */
export function verifyBundleToken(params: {
  token: string;
  now: number;
}): BundleTokenClaims | null {
  const { token, now } = params;

  // Computed before anything else can return, so a broken deployment throws
  // whatever the token looks like.
  const key = signingKey();
  void key;

  if (typeof token !== "string") return null;

  const segments = token.split(".");
  if (segments.length !== 3) return null;
  const [header, payload, signature] = segments as [string, string, string];

  // The signature is compared as the ENCODED string, so nothing attacker
  // supplied is ever decoded before it is authenticated.
  const expected = sign(`${header}.${payload}`);
  // The length check is separate and comes first because `constantTimeEqual`
  // THROWS on an empty input rather than returning false, and an empty third
  // segment is exactly what an `alg: "none"` token has. Leaking a length
  // comparison costs nothing: the length of a correct signature is a constant
  // this file publishes.
  if (signature.length !== expected.length) return null;
  if (!constantTimeEqual(utf8.encode(expected), utf8.encode(signature))) {
    return null;
  }

  try {
    // Authenticated before parsed. Everything below is bytes this deployment
    // signed, so a parse failure here means a bug rather than an attack, and
    // it is still caught rather than thrown at the caller.
    const decodedHeader = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(header)),
    ) as Record<string, unknown>;
    if (
      decodedHeader.alg !== HEADER.alg ||
      decodedHeader.typ !== HEADER.typ ||
      Object.keys(decodedHeader).length !== 2
    ) {
      return null;
    }

    const claims = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(payload)),
    ) as Record<string, unknown>;

    if (claims.iss !== ISSUER || claims.aud !== AUDIENCE) return null;
    if (typeof claims.sub !== "string" || claims.sub.length === 0) return null;
    for (const value of [claims.iat, claims.exp]) {
      if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        return null;
      }
    }
    // `>=` rather than `>`. A token valid "until" an instant is not valid at
    // it, and the alternative leaves a one millisecond window nobody would
    // ever think about again. Same rule as `requireSession`.
    if (now >= (claims.exp as number)) return null;

    return { subject: claims.sub };
  } catch {
    return null;
  }
}
