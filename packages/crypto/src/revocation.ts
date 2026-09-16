import { ed25519 } from "@noble/curves/ed25519";
import { fromHex, utf8 } from "./bytes.js";
import { PUBLIC_KEY_HEX_PATTERN } from "./internal.js";

/**
 * A signed instruction to stop using a service token.
 *
 * This is the kill switch. An SDK enters shutdown ONLY on a notice carrying a
 * valid signature from the organisation's revocation key, which is held in the
 * admin's browser and never by the server. That is what stops a compromised
 * Sluice server, a compromised Convex deployment, or a network attacker from
 * mass-killing customer production fleets: they can deliver any bytes they
 * like down a live subscription, but they cannot produce this signature.
 */
export interface RevocationNotice {
  /** Lowercase hex of the 16-byte token id `mintToken` produced. */
  tokenId: string;
  /** Monotonic per-token counter. Freshness is the SDK's job -- see below. */
  epoch: number;
  /** Unix milliseconds, for display and audit only. Never trusted as a clock. */
  revokedAt: number;
  /** Human-readable justification, shown in the SDK's shutdown log. */
  reason: string;
}

const TOKEN_ID_PATTERN = /^[0-9a-f]{32}$/;

/**
 * Upper bound on `reason`, in UTF-16 code units.
 *
 * A revocation notice is fanned out to EVERY live subscription for the token,
 * so an unbounded `reason` turns the kill switch into an amplified push
 * channel. The cap is on `String.length`, so the true worst case is 1536 UTF-8
 * bytes (512 three-byte BMP characters); that is still bounded, which is the
 * property being bought here.
 */
const MAX_REASON_LENGTH = 512;

/**
 * WHY THIS ENCODING IS HAND-ROLLED, AND WHY `JSON.stringify` IS BANNED HERE.
 *
 * JSON object key order is an artefact of how an engine happens to store
 * properties. It is not part of the data and not guaranteed to survive a round
 * trip through a database row, a structured clone, a proxy, or a different
 * runtime. A verifier that disagrees with the signer about key order hashes
 * different bytes and therefore rejects EVERY valid notice -- a silent, total
 * failure of the kill switch that would only surface when a customer needed it.
 * The same applies to a re-serialised number (`1e21`, `-0`), to added or
 * dropped optional keys, and to any whitespace choice. Signing a fixed field
 * order that this module alone decides removes all of it.
 *
 * WHAT THE VALIDATION IS HOLDING UP. Do not relax the `tokenId` check without
 * reading this.
 *
 * Newline-joining is injective ONLY while no field before `reason` can contain
 * a newline. Nothing about the TypeScript type enforces that: a notice arrives
 * from an untrusted database row or a JSON payload, and a type is not a runtime
 * guarantee. Concretely, these two notices produced identical bytes, so ONE
 * signature verified BOTH:
 *
 *   A: { tokenId: "aa\nbb", epoch: 1,    revokedAt: 2, reason: "x"    }
 *   B: { tokenId: "aa",     epoch: "bb", revokedAt: 1, reason: "2\nx" }
 *
 * Both join to `sluice/revocation/v1\naa\nbb\n1\n2\nx`. `epoch: "bb"` is not
 * reachable through the type system and is entirely reachable from a database
 * row. Pinning `tokenId` to 32 lowercase hex characters and `epoch` and
 * `revokedAt` to non-negative safe integers removes every character that could
 * shift a field boundary, which makes the split unambiguous and the encoding
 * injective. `reason` is last, so a newline inside it cannot move anything.
 *
 * The version prefix is the domain separator. It keeps these bytes from ever
 * being confused with a handshake message or any future signed structure under
 * the same key, and any change to the field order or set gets `/v2` rather than
 * an edit here.
 */
function encode(notice: RevocationNotice): Uint8Array {
  return utf8.encode(
    [
      "sluice/revocation/v1",
      notice.tokenId,
      String(notice.epoch),
      String(notice.revokedAt),
      notice.reason,
    ].join("\n"),
  );
}

/**
 * The single validator, called from BOTH the sign and the verify path.
 *
 * One function rather than two copies, deliberately. If the signer accepted
 * something the verifier rejected, real revocations would silently fail to take
 * effect and a stolen token would keep working. If the verifier accepted
 * something the signer would never emit, the ambiguity above reopens. Sharing
 * the code is what makes those two sets provably equal, so the only thing
 * `verifyRevocation`'s guard can ever reject is a notice `signRevocation` would
 * have refused to create.
 *
 * The number predicate is intentionally identical in shape to `assertTimestamp`
 * in `token.ts`, including the `Object.is(x, -0)` clause: `String(-0)` is `"0"`,
 * so `-0` and `0` encode to the same bytes while comparing as distinct values.
 * `Number.isSafeInteger(-0)` is true and `-0 < 0` is false, so `Object.is` is
 * the only way to catch it. The safe-integer bound also excludes fractions,
 * `NaN`, both infinities, and magnitudes at or above 1e21 where `String`
 * switches to exponential notation.
 *
 * Runtime `typeof` checks on fields the type already declares are not
 * redundant. This value comes off the wire.
 */
function assertValidNotice(notice: RevocationNotice): void {
  if (typeof notice !== "object" || notice === null) {
    throw new Error("notice must be an object");
  }
  if (typeof notice.tokenId !== "string" || !TOKEN_ID_PATTERN.test(notice.tokenId)) {
    throw new Error(`tokenId must match ${TOKEN_ID_PATTERN.source}`);
  }
  for (const [name, value] of [
    ["epoch", notice.epoch],
    ["revokedAt", notice.revokedAt],
  ] as const) {
    if (
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < 0 ||
      Object.is(value, -0)
    ) {
      throw new Error(`${name} must be a non-negative safe integer`);
    }
  }
  if (typeof notice.reason !== "string") {
    throw new Error("reason must be a string");
  }
  if (notice.reason.length > MAX_REASON_LENGTH) {
    throw new Error(`reason must be at most ${MAX_REASON_LENGTH} characters`);
  }
}

const ORG_PRIVATE_KEY_BYTES = 32;

/**
 * Signs a revocation notice with the organisation's revocation private key.
 *
 * Throws on invalid input rather than returning a signature over malformed
 * bytes. An admin clicking "revoke" needs a loud failure, not a notice that no
 * SDK will ever honour. The key length is checked here so the error names the
 * problem; Noble would throw anyway, but with a message about point decoding.
 *
 * ED25519 SIGNATURES ARE DETERMINISTIC. The same notice always produces
 * byte-identical output, so a notice and its signature are a stable, freely
 * copyable pair. This function therefore proves AUTHENTICITY, NOT FRESHNESS.
 * Anyone who observes a notice can resend it verbatim at any later time and
 * `verifyRevocation` will return true, because it IS genuine -- it is simply
 * old. A rolled-back `epoch` fails only because the signature covers the epoch;
 * an attacker replaying a genuine OLD notice at an old epoch passes every check
 * in this module.
 *
 * THE SDK MUST therefore keep the highest epoch it has already acted on per
 * token and REFUSE any notice at or below it. That is the SDK's job, not this
 * module's: this module has no state, no clock and no view of what the SDK has
 * already seen, and pretending otherwise here would be a lie in the API.
 */
export function signRevocation(orgPrivateKey: Uint8Array, notice: RevocationNotice): Uint8Array {
  if (orgPrivateKey.length !== ORG_PRIVATE_KEY_BYTES) {
    throw new Error(
      `orgPrivateKey must be ${ORG_PRIVATE_KEY_BYTES} bytes, got ${orgPrivateKey.length}`,
    );
  }
  assertValidNotice(notice);
  return ed25519.sign(encode(notice), orgPrivateKey);
}

/**
 * Verifies a revocation notice against the organisation's public key.
 *
 * Returns `false` for every failure rather than throwing, matching
 * `verifyHandshake`. Noble throws on a wrong-length signature or public key and
 * returns `false` on a well-formed but incorrect one, and `fromHex` throws on
 * non-hex input; a caller deciding whether to shut down should not have to
 * distinguish those, and an exception would hand an attacker a channel for
 * telling "bad encoding" apart from "bad signature". The `catch` also swallows
 * the validation throws above, which is what keeps the two paths on one
 * validator without forcing this one to throw.
 *
 * A `false` here means DO NOT SHUT DOWN. It never means "maybe".
 *
 * The org public key must be CANONICAL lowercase hex, matching the strictness
 * {@link TOKEN_ID_PATTERN} already applies to the token id in the notice. An
 * uppercased key decodes to the same bytes and would otherwise verify, giving
 * one organisation two spellings that a caller's cache would treat as two.
 * See {@link PUBLIC_KEY_HEX_PATTERN}.
 */
export function verifyRevocation(
  orgPublicKeyHex: string,
  notice: RevocationNotice,
  signature: Uint8Array,
): boolean {
  if (!PUBLIC_KEY_HEX_PATTERN.test(orgPublicKeyHex)) return false;
  try {
    assertValidNotice(notice);
    return ed25519.verify(signature, encode(notice), fromHex(orgPublicKeyHex));
  } catch {
    return false;
  }
}
