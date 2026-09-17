import { sha256 } from "@noble/hashes/sha256";
import { toHex, utf8 } from "@sluice/crypto";

/**
 * HOW `handshakeNonces.signatureHash` IS COMPUTED. THIS IS THE ONLY DEFINITION.
 *
 * The column, its index and `insertHandshakeNonce` all shipped before anything
 * produced a value for them: the repository function took the hash already
 * computed, so every future caller was free to invent its own construction.
 * That is the identical shape of the token id hash problem, and it is written
 * down here for the same reason.
 *
 * THE CONSTRUCTION:
 *
 *     sha256(utf8("sluice/handshake-nonce/v1") || signature)   lowercase hex
 *
 * where `signature` is the 64 raw bytes of the Ed25519 handshake signature.
 *
 * WHY THE SIGNATURE ALONE, AND NOT THE TOKEN ID OR THE TIMESTAMP TOO. This was
 * the decision, so here is the argument rather than the result.
 *
 * The replay cache has to reject a second presentation of one request and must
 * never reject a first presentation of a different one. A handshake request is
 * the triple (token id, timestamp, signature), and the signature is a FUNCTION
 * of the other two under the token's key, because Ed25519 is deterministic.
 * That determinism is the whole reason this table exists, and it is also what
 * makes the signature a complete name for the request: two requests that differ
 * in the token id or in the timestamp sign different messages and therefore
 * carry different signatures, and two requests that agree on both carry
 * byte-identical ones. Adding either field to the digest would add no
 * information and would give a future caller two fields it could get wrong.
 *
 * The one case worth checking is a signature that is valid for two different
 * tokens, which would make one nonce row block both. That needs two
 * `serviceTokens` rows with the same stored public key AND the same token id,
 * and the token id hash is a unique index, so the second registration cannot
 * exist. The hash is only ever consulted after `verifyHandshake` has already
 * bound the signature to one stored public key.
 *
 * WHY IT IS DOMAIN SEPARATED. `tokenIdHash` labels its input for a stated
 * reason: without a label, two subsystems that both "just hash the bytes" can
 * produce the same string and silently share an index. That argument does not
 * weaken because both subsystems happen to live on this server. If some later
 * digest is ever taken over a raw 64-byte value, this label is what keeps the
 * two apart.
 *
 * WHY PLAIN SHA-256 IS SAFE DESPITE LENGTH EXTENSION. The output is an index
 * key, not a MAC. Nothing authenticates anything on the strength of it, and an
 * attacker who could extend it would produce a digest that matches no row. The
 * label is a fixed-width string and the signature is a fixed 64 bytes, so the
 * boundary in `label || signature` sits at a known offset and the concatenation
 * has exactly one reading. The width is enforced below rather than assumed,
 * which is what makes that true rather than merely likely.
 *
 * WHY THIS LIVES IN `convex/` AND NOT IN `@sluice/crypto`. `secretAssociatedData`
 * and `tokenIdHash` are there because BOTH ENDS OF THE WIRE compute them and
 * drift between the two ends is silent. Nothing outside this server ever
 * computes a handshake nonce key: the SDK sends a signature and never learns
 * what is done with it. Putting a server-only digest in the shared package
 * would widen a security package's public surface for no one's benefit, and
 * `packages/crypto/test/index.test.ts` pins that surface precisely so an export
 * has to be argued for.
 */

const HANDSHAKE_NONCE_LABEL = "sluice/handshake-nonce/v1";

/** An Ed25519 signature. Fixed width, and that is load bearing above. */
const SIGNATURE_BYTES = 64;

/**
 * How long a nonce row is kept.
 *
 * The acceptance window is 60 seconds either side of server time, so a
 * signature that is already outside the window is rejected on the timestamp
 * before this table is consulted and does not need a row. 120 seconds is that
 * window plus the same again, so the record outlives every request it could
 * possibly have to refuse. Keeping them longer would only grow a table whose
 * reaper is already a written-down concern.
 */
export const HANDSHAKE_NONCE_LIFETIME_MS = 120 * 1000;

export function handshakeSignatureHash(params: {
  signature: Uint8Array;
}): string {
  const { signature } = params;

  // Reached from a JSON body by way of `fromHex`, so the runtime check is
  // real. A plain array of 64 numbers would satisfy `.length` and be silently
  // mis-hashed, which is why this tests the constructor and not the length
  // alone. Same rule, same reason, as `tokenIdHash`.
  if (!(signature instanceof Uint8Array)) {
    throw new Error("signature must be a Uint8Array");
  }
  if (signature.length !== SIGNATURE_BYTES) {
    throw new Error(
      `signature must be ${SIGNATURE_BYTES} bytes, got ${signature.length}`,
    );
  }

  const label = utf8.encode(HANDSHAKE_NONCE_LABEL);
  const message = new Uint8Array(label.length + signature.length);
  message.set(label, 0);
  message.set(signature, label.length);
  return toHex(sha256(message));
}
