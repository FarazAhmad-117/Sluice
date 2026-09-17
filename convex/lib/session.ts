import { sha256 } from "@noble/hashes/sha256";
import { randomBytes, toHex, utf8 } from "@sluice/crypto";

/**
 * WHY SLUICE OWNS ITS SESSIONS INSTEAD OF USING `ctx.auth`.
 *
 * This was investigated rather than assumed, and the answer is in the type
 * declarations shipped with `convex@1.45.0`, at
 * `node_modules/convex/dist/esm-types/server/authentication.d.ts`.
 *
 * `AuthConfig.providers` accepts exactly two shapes. One is an OIDC provider,
 * `{ domain, applicationID }`, where the backend fetches the issuer's
 * discovery document. The other is `{ type: "customJwt", issuer, jwks,
 * algorithm: "RS256" | "ES256" }`, where the backend fetches a JWKS over HTTPS
 * and verifies an asymmetric signature. There is no third shape, and in
 * particular there is no hook that hands a presented credential to code in
 * this repository. `ctx.auth.getUserIdentity()` reads claims out of a token
 * Convex has already verified; it cannot be driven by a verifier of ours.
 * "Custom auth" in Convex means a custom JWT ISSUER, not custom verification.
 *
 * So using `ctx.auth` would mean becoming an issuer: an RS256 or ES256 key
 * pair held on this deployment, a JWKS published from an HTTP action, JWT
 * minting inside `login`, and key rotation. That is a great deal of new
 * machinery, and it still does not satisfy the requirement below it:
 *
 *   A VERIFIED JWT CANNOT BE LOGGED OUT. It is valid until it expires,
 *   because verification consults a public key and nothing else. Immediate
 *   revocation needs server side state the request is checked against, which
 *   is a session table. Building the JWT layer as well would mean owning both,
 *   and the table would be the half that actually decided every request.
 *
 * Sluice is a product whose entire wedge is signed instant revocation. A
 * session layer that cannot revoke instantly is not arguable here.
 *
 * The cost, stated plainly rather than buried: the token travels as a function
 * ARGUMENT, because a Convex query or mutation called through the client
 * carries no headers of its own. It is an argument the server verifies against
 * stored state, not a claim the server believes, which is the distinction that
 * matters. But it does mean the token is in the request body of every call,
 * so nothing in this codebase may ever put it in a log line, an error message,
 * an audit row or a URL. See `authz.ts`.
 */

/**
 * 32 bytes. The token is the entire credential, so it is sized like a key
 * rather than like an identifier: guessing one is guessing a 256 bit value,
 * which is why the stored hash below can be a fast unkeyed one.
 */
const SESSION_TOKEN_BYTES = 32;

/**
 * Twelve hours, absolute, with no sliding renewal.
 *
 * TWELVE, because a Sluice session cannot usefully outlive the master unlock
 * key it accompanies. The MUK is derived from the password in the browser and
 * lives in memory only; it is never persisted, because persisting it is the
 * one thing that would make the zero knowledge claim false. A page reload
 * therefore costs a password re-entry no matter how long this server side
 * session lasts. A longer lifetime would buy the user nothing and would buy an
 * attacker holding a stolen token a longer window, so it is set to rather more
 * than a working day and no more.
 *
 * ABSOLUTE, because a sliding window makes a stolen token immortal: the thief
 * keeps using it, the expiry keeps moving, and the session outlives the
 * account it was taken from. An absolute deadline bounds the damage of a leak
 * to a fixed interval regardless of how busy the attacker is.
 */
export const SESSION_LIFETIME_MS = 12 * 60 * 60 * 1000;

/**
 * Domain separation. The token is fixed width lowercase hex and the separator
 * is not in that alphabet, so the concatenation has exactly one reading.
 */
const SESSION_HASH_DOMAIN = "sluice/session/v1|";

/**
 * A fresh bearer credential. Opaque: it carries no user id, no expiry and no
 * structure a client could parse or an attacker could forge a variant of. The
 * only thing that makes it mean anything is a row in `sessions`.
 */
export function issueSessionToken(): string {
  return toHex(randomBytes(SESSION_TOKEN_BYTES));
}

/**
 * What `sessions.tokenHash` stores, for the same reason `serviceTokens` stores
 * `tokenIdHash`: someone who reads the database must not be able to use what
 * they read. A dump of this table is a list of digests, and a digest cannot be
 * presented to `requireSession`.
 *
 * Unkeyed SHA-256 rather than HMAC under `AUTH_PEPPER`, deliberately, and this
 * is the one place it differs from `verifier.ts`. The pepper is there because
 * an auth verifier is derived from a password and an attacker who obtains one
 * out of band wants to confirm it against a dump. A session token has no
 * such life: it is 256 uniform bits, so there is nothing to precompute and
 * nothing to confirm, and anyone holding the token would present it rather
 * than look for it. Keying this would also drag `AUTH_PEPPER` into every
 * QUERY in the product, where a missing pepper would surface as an
 * authentication failure instead of as the configuration error it is.
 *
 * The input is the token STRING, not decoded bytes. There is no parse step, so
 * there is no malformed-token branch with its own error message and its own
 * timing; anything that is not byte identical to an issued token simply misses
 * the index.
 */
export function hashSessionToken(token: string): string {
  return toHex(sha256(utf8.encode(SESSION_HASH_DOMAIN + token)));
}
