import { randomBytes, toHex } from "./bytes";

/**
 * PERMANENT IDENTIFIERS, MINTED BY THE CLIENT.
 *
 * Every org, user and environment carries one of these alongside its Convex
 * document id, and every encryption binding and external reference uses THIS,
 * never the document id. Two reasons, both load bearing:
 *
 * 1. PORTABILITY. A Convex document id is local to one deployment. Moving an
 *    org to another cell re-mints every id it owns. Ciphertext bound to the old
 *    ids would stop opening, and no server could fix it, because no server holds
 *    a key. These ids travel with the rows unchanged.
 *
 * 2. ORDERING. Convex mints document ids on insert, after the client has
 *    already wrapped the keys a creation mutation takes. These ids exist BEFORE
 *    the mutation, so a wrap can bind the environment or org it belongs to,
 *    which the v1 constructions documented as impossible.
 *
 * THE KIND IS IN THE ID. `usr_…` passed where `env_…` is expected fails here,
 * at the call, instead of producing well-formed associated data for the wrong
 * thing. A Convex document id fails too, which is what stops one sneaking back
 * into a binding.
 *
 * 128 random bits, lowercase hex. Uniqueness is enforced again by the server's
 * `by_uid` index; the entropy makes a collision a bug rather than an event.
 */
export type IdKind = "org" | "usr" | "env";

const ID_BYTES = 16;

/**
 * One pattern per kind, anchored at both ends. Lowercase only, because these
 * strings go into associated data byte for byte: `env_…A…` and `env_…a…` name
 * the same random value and would seal to different AAD, so exactly one
 * spelling is accepted. `$` without the `m` flag matches only at end of input
 * in JavaScript, so a trailing newline is rejected too (the test pins that).
 */
const PATTERNS: Readonly<Record<IdKind, RegExp>> = Object.freeze({
  org: /^org_[0-9a-f]{32}$/,
  usr: /^usr_[0-9a-f]{32}$/,
  env: /^env_[0-9a-f]{32}$/,
});

export function newId(kind: IdKind): string {
  return `${kind}_${toHex(randomBytes(ID_BYTES))}`;
}

/**
 * Checks shape and kind. The value is never echoed: an id is not a secret, but
 * this guard runs on the path into associated data, and the rest of this
 * package refuses to print its inputs on principle.
 */
export function assertId(kind: IdKind, field: string, value: string): string {
  if (typeof value !== "string" || !PATTERNS[kind].test(value)) {
    throw new Error(`${field} must be an ${kind} id`);
  }
  return value;
}
