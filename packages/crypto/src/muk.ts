import { argon2id } from "@noble/hashes/argon2";
import { sha256 } from "@noble/hashes/sha256";
import { concat, utf8 } from "./bytes.js";

/**
 * Argon2id parameters, tuned per section 3.1 of Implementation_Plan.md.
 *
 * DO NOT LOWER THESE. They are not a performance knob; they are the entire cost
 * of an offline guessing attack. An attacker who steals the wrapped key bundle
 * -- from a database dump, a backup, a compromised host -- can guess passwords
 * at exactly the rate this function runs, and nothing else stands between them
 * and every secret the account can reach. Halving `m` or `t` halves the cost of
 * every guess against every account that has ever existed, retroactively.
 *
 * `m` is in KiB, so 65536 means 64 MiB allocated per derivation. That is the
 * memory-hardness: it is what stops a GPU or ASIC farm from running millions of
 * guesses in parallel, because each parallel guess needs its own 64 MiB.
 *
 * Raising them later is also not free: the MUK is a pure function of
 * (password, userId, parameters), so any change here produces a DIFFERENT key
 * and every existing wrapped private key becomes unopenable. A future change
 * must be a versioned second derivation with a migration, never an edit to
 * these numbers.
 */
export const ARGON2_PARAMS = { m: 65536, t: 3, p: 4, dkLen: 32 } as const;

/**
 * Domain separation label for the MUK salt, following the `sluice/...`
 * convention used by the HKDF `info` strings in `token.ts`, and versioned for
 * the same reason: bumping it to `/v2` would change every user's salt and
 * therefore every user's MUK, so a new derivation gets a new label rather than
 * an edit to this one.
 */
const SALT_LABEL = "sluice/muk-salt/v1";

/**
 * Turns a user id into a fixed-width Argon2id salt.
 *
 * This exists because of a real, verified failure mode, not for tidiness.
 * `@noble/hashes` rejects any salt under 8 bytes outright:
 *
 *     argon2id(pw, utf8.encode("u1"), params)
 *     // Error: salt should be at least 8 bytes and less than 4 GB
 *
 * Using the raw user id as the salt would therefore CRASH SIGNUP for any user
 * whose id happens to be short -- a sequential id, a test fixture, a seed row.
 * The failure would appear at account creation, on the one code path that has
 * no fallback.
 *
 * Padding the id to 8 bytes was rejected: a pad is not injective. `"u1"` padded
 * with zeros is indistinguishable from a literal user id `"u1\0\0\0\0\0\0"`,
 * so two distinct users could share a salt, and a shared salt means two users
 * with the same password derive the same MUK.
 *
 * Requiring a minimum user id length was also rejected. The id is handed to us
 * by whatever issues account identifiers; making the ROOT OF THE KEY HIERARCHY
 * depend on an external system's id format means the day that format changes,
 * or a dev seeds a short id, signup breaks for real people.
 *
 * Hashing gives a constant 32-byte salt for every user, keeps distinct ids
 * distinct (SHA-256 preimage/collision resistance), and as a side effect stops
 * the salt width from leaking how long the user id is. The label prefix is
 * fixed-length ASCII, so `label || userId` is an unambiguous encoding: no user
 * id can shift the boundary or impersonate the label.
 *
 * The user id is deliberately NOT Unicode-normalised, unlike the password.
 * Normalisation is lossy, and two distinct account identifiers must never
 * collapse to the same salt. The id is an opaque machine-issued value that must
 * be used byte-exactly as the server stores it.
 */
function mukSalt(userId: string): Uint8Array {
  return sha256(concat(utf8.encode(SALT_LABEL), utf8.encode(userId)));
}

/** Node's formatter and `console.log` look up exactly this symbol on a value. */
const INSPECT_CUSTOM: unique symbol = Symbol.for("nodejs.util.inspect.custom");

/** The MUK is exactly the Argon2id output width. Stated once, enforced once. */
const MUK_BYTES = ARGON2_PARAMS.dkLen;

/**
 * The 32-byte Master Unlock Key, wrapped so it cannot be serialised by accident.
 *
 * This is a CLASS rather than a bare `Uint8Array` for the same reason
 * {@link MintedToken} in `token.ts` is a class: so that `toJSON` and the inspect
 * hook can live on the prototype. A bare `Uint8Array` renders through
 * `JSON.stringify` as `{"0":223,"1":238,...}`, a complete and trivially
 * reversible dump, and `console.log` prints every byte. One careless
 * `logger.info({ muk })` would therefore put the ROOT OF THE ENTIRE HUMAN KEY
 * HIERARCHY into a log aggregator -- strictly worse than the `MintedToken`
 * leak, because the MUK unwraps everything the account can reach, including the
 * private keys that unwrap every project data key.
 *
 * The raw bytes are reachable only through {@link bytes}. That name is
 * deliberate: unwrapping the key is a decision, and `grep -rn '\.bytes'` finds
 * every place anyone made it.
 *
 * LIMIT OF THE PROTECTION, STATED PLAINLY. Redaction lives on the prototype, so
 * it is lost the moment the instance is reshaped, exactly as for
 * `MintedToken`. What differs is the failure mode: the bytes live in a
 * `#private` field, which is not an own property, so `{ ...muk }` and
 * `structuredClone(muk)` both produce an EMPTY object rather than a dump. The
 * copy is therefore silent and useless rather than silent and catastrophic --
 * but it is still silent. THE RULE IS THE SAME: pass this instance, never a
 * spread and never a copy.
 *
 * A `#private` field also means this value CANNOT cross a `postMessage`
 * boundary. That matters, because `deriveMUK` should run in a Web Worker: the
 * worker must post the raw bytes back and the main thread must re-wrap them
 * with `new MasterUnlockKey(bytes)`. Posting the instance itself would deliver
 * an empty object, and the length check in the constructor is what stops that
 * mistake from being discovered later, by a decryption that quietly fails.
 *
 * Neither hook protects bytes a caller has already unwrapped. `muk.bytes` is an
 * ordinary `Uint8Array` and dumps in full, and it is the LIVE array rather than
 * a copy, so mutating it corrupts the key in place.
 */
export class MasterUnlockKey {
  readonly #bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    // Checked here rather than trusted, because this constructor is public and
    // is the rehydration path out of a Web Worker. A short key would otherwise
    // flow on to AES-GCM, which accepts 16 and 24 byte keys and would silently
    // downgrade to AES-128 instead of failing.
    if (bytes.length !== MUK_BYTES) {
      throw new Error(`master unlock key must be ${MUK_BYTES} bytes, got ${bytes.length}`);
    }
    this.#bytes = bytes;
  }

  /**
   * The raw key. Every use of this accessor is a deliberate unwrap.
   *
   * Returns the live array, not a copy, so it can be zeroed by a caller that
   * wants to and so an unwrap is never silently a different key. Never log,
   * serialise, or transmit the result.
   */
  get bytes(): Uint8Array {
    return this.#bytes;
  }

  /**
   * Serialises to a placeholder, never to key material.
   *
   * Every JSON path -- a log line, an error report, a response body, a queue
   * message -- routes through here, so the MUK cannot reach one by accident.
   */
  toJSON(): string {
    return "[MasterUnlockKey redacted]";
  }

  /** Keeps `console.log(muk)` from printing the key bytes. */
  [INSPECT_CUSTOM](): string {
    return "[MasterUnlockKey redacted]";
  }
}

/**
 * Derives the Master Unlock Key from a password and a user id.
 *
 * THE MUK NEVER LEAVES THE CLIENT. It is never sent to a server, never written
 * to a log, never persisted, and nothing in this package may serialise it. It
 * wraps the user's X25519 and Ed25519 private keys, so it is the root of the
 * entire human key hierarchy: anyone holding it holds every secret the account
 * can reach.
 *
 * A FORGOTTEN PASSWORD IS UNRECOVERABLE BY DESIGN. There is no reset path
 * through this function and there cannot be one -- the server has nothing to
 * reset, because it has never seen the password or the key. Account recovery
 * runs entirely through the recovery kit, which is a separate high-entropy
 * secret handed to the user at signup, and never through here.
 *
 * ON `async`, STATED PLAINLY: this function is asynchronous in SIGNATURE ONLY.
 * `argon2id` is synchronous and holds the thread for the whole derivation, so
 * on a browser main thread this freezes the tab -- no paint, no input, no
 * progress bar -- for several seconds. `@noble/hashes` also ships
 * `argon2idAsync`, and it does NOT fix this: its yield point is `await
 * nextTick()` where `nextTick = async () => {}`, which drains as a MICROTASK.
 * Microtasks run before rendering and before input, so `argon2idAsync` blocks
 * exactly as hard (measured: zero `setInterval(20ms)` callbacks fired during a
 * 5.9-second run) while costing about 35% more wall time. The sync call is
 * therefore the honest choice.
 *
 * The `async` signature is kept so the UI layer must already treat this as a
 * suspending call, and so this can move into a Web Worker -- the only real fix
 * -- without a breaking API change. Callers on a main thread MUST assume this
 * blocks, and should run it in a Worker.
 */
export async function deriveMUK(password: string, userId: string): Promise<MasterUnlockKey> {
  // Both guards run before the derivation, not after. An empty password is
  // accepted by Argon2id without complaint, and validating afterwards would
  // make every rejected attempt cost a full multi-second grind on the user's
  // own device.
  if (password.length === 0) throw new Error("password must not be empty");
  if (userId.length === 0) throw new Error("userId must not be empty");

  // NFC, per RFC 8265 (PRECIS OpaqueString), and the choice is permanent.
  // "café" and "café" are the same word to the user and to the
  // screen, but different bytes, and which one arrives depends on their OS,
  // keyboard and input method -- a Mac and a Windows box can disagree about the
  // same typed password. Without this line, such a user derives a different MUK
  // on a different device, cannot open their own keys, and the account is
  // unrecoverable through a flaw rather than by design. Changing this to NFD,
  // or removing it, would lock out every existing user with a non-ASCII
  // password.
  // The derivation is untouched by the wrapper: the same bytes as before, handed
  // to a constructor instead of to the caller. The known-answer vector in
  // `muk.test.ts` reads straight through `.bytes` and must never move.
  return new MasterUnlockKey(
    argon2id(utf8.encode(password.normalize("NFC")), mukSalt(userId), { ...ARGON2_PARAMS }),
  );
}
