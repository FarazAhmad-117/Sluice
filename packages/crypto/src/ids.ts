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
 * WHAT THE SERVER MAY ASSUME: NOTHING BEYOND THE SHAPE. 128 random bits,
 * lowercase hex -- but a uid arrives from a client, and the server must treat
 * it as attacker-chosen. The entropy only makes ACCIDENTAL collisions
 * negligible; it does nothing against a client that copies somebody else's
 * uid on purpose. Uniqueness is the server's job, enforced per deployment by
 * the `by_uid` index. Any future path that moves or imports an org between
 * cells must reject a uid already present in the target and must never upsert
 * by uid, or a forged uid would let one org's rows land on another's.
 * Ciphertext stays safe regardless: a copied uid is a label, not a key, and
 * confers no ability to open anything bound to it.
 */
export type IdKind = "org" | "usr" | "env";

const ID_BYTES = 16;

/**
 * One pattern per kind, anchored at both ends, with the length derived from
 * ID_BYTES so minting and validation cannot disagree about it. Lowercase only,
 * because these strings go into associated data byte for byte: `env_…A…` and
 * `env_…a…` name the same random value and would seal to different AAD, so
 * exactly one spelling is accepted. No flags: `$` without `m` matches only at
 * end of input in JavaScript, so a trailing newline is rejected (the test pins
 * that).
 */
function pattern(kind: IdKind): RegExp {
  return new RegExp(`^${kind}_[0-9a-f]{${ID_BYTES * 2}}$`);
}

const PATTERNS: Readonly<Record<IdKind, RegExp>> = Object.freeze({
  org: pattern("org"),
  usr: pattern("usr"),
  env: pattern("env"),
});

/**
 * Routed through `assertId` so this function can never hand out an id the
 * validator would refuse -- including for a kind that slipped past the type
 * system at runtime.
 */
export function newId(kind: IdKind): string {
  return assertId(kind, "id", `${kind}_${toHex(randomBytes(ID_BYTES))}`);
}

/**
 * Checks kind, then shape. The value is never echoed: an id is not a secret,
 * but this guard runs on the path into associated data, and the rest of this
 * package refuses to print its inputs on principle.
 *
 * The kind check is a runtime check because the type is erased: a caller in
 * plain JavaScript, or one casting through `unknown`, can pass anything, and
 * an own-property test also keeps `"toString"` or `"__proto__"` from
 * resolving to something on Object.prototype.
 */
export function assertId(kind: IdKind, field: string, value: string): string {
  if (!Object.prototype.hasOwnProperty.call(PATTERNS, kind)) {
    throw new Error("kind must be org, usr or env");
  }
  if (typeof value !== "string" || !PATTERNS[kind].test(value)) {
    throw new Error(`${field} must be a well-formed ${kind} id`);
  }
  return value;
}
