import { sha256 } from "@noble/hashes/sha256";
import type { Argon2Backend, Argon2Params } from "./argon2";
import { assertArgon2Output, assertConformantArgon2, nobleArgon2 } from "./argon2";
import { concat, randomBytes, utf8 } from "./bytes";
import { INSPECT_CUSTOM } from "./internal";

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
 * (password, account salt, parameters), so any change here produces a DIFFERENT
 * key and every existing wrapped private key becomes unopenable. A future
 * change must be a versioned second derivation with a migration, never an edit
 * to these numbers.
 *
 * FROZEN, not merely `as const`. `as const` is a compile-time assertion and
 * erases to nothing; `ARGON2_PARAMS.m = 8` is a legal JavaScript statement that
 * `tsc` never sees in a consumer written in JS, in a bundle, or behind an
 * `as any`. Now that a caller can supply its own Argon2 backend, the parameters
 * are handed across a boundary on every derivation, and a mutated shared object
 * would weaken every later call in the process with no diff to review.
 */
export const ARGON2_PARAMS = Object.freeze({ m: 65536, t: 3, p: 4, dkLen: 32 } as const);

/**
 * Domain separation label for the MUK salt, following the `sluice/...`
 * convention used by the HKDF `info` strings in `token.ts`, and versioned for
 * the same reason: any change to how the salt is built changes every user's
 * MUK, so a new construction gets a new label rather than an edit to an old one.
 *
 * `/v1` hashed the account's normalised email address. `/v2` hashes a random
 * per-account value instead (see {@link mukSalt}). v2 REPLACES v1 outright --
 * there were no real accounts to migrate -- but it still takes a new label, so
 * the two constructions can never produce the same salt from the same bytes and
 * a v1 vector can never pass for a v2 one.
 */
const SALT_LABEL = "sluice/muk-salt/v2";

/**
 * Width of the per-account salt, in bytes. Random, per account, public. Minted
 * at signup and never changed.
 *
 * 128 bits is the width RFC 9106 recommends for an Argon2 salt, and it is enough
 * that no two accounts will ever draw the same one by chance.
 */
export const ACCOUNT_SALT_BYTES = 16;

/**
 * Mints a fresh account salt. Called ONCE, at signup, and the result is stored
 * server-side next to the account; login fetches it back before deriving.
 *
 * The salt is PUBLIC. It is not a secret and needs no protection beyond
 * integrity: the server hands it to anyone who asks to log in as the account.
 * Its job is uniqueness, not secrecy -- it makes every account's Argon2id a
 * different function, so one table of guessed passwords cannot be run against
 * every account at once. It does NOT hide anything from a targeted attacker;
 * see {@link mukSalt} for exactly what it does and does not buy.
 *
 * NEVER CHANGE AN ACCOUNT'S SALT. The MUK is a function of it, so a new salt is
 * a new key and every private key wrapped under the old one becomes
 * unopenable. Rotating it is a re-wrap operation, not an update to a column.
 */
export function newAccountSalt(): Uint8Array {
  return randomBytes(ACCOUNT_SALT_BYTES);
}

/**
 * Turns an account salt into the Argon2id salt.
 *
 * WHAT THE RANDOM SALT BUYS, STATED EXACTLY. v1 derived the salt from the
 * account's email. v2 uses a random value minted at signup. That buys three
 * things and no more:
 *
 * 1. An email change no longer changes the key. v1 welded the MUK to the
 *    address, so changing it would have orphaned every key the account holds.
 *    The email is now an ordinary mutable field.
 * 2. Precomputation needs the server. v1's salt could be computed offline from
 *    a public address, so an attacker holding a mailing list could build
 *    guess tables for every address on it without ever contacting us. v2's
 *    salt must be fetched per account, and the server can rate-limit that.
 * 3. No table carries over between deployments. Two Sluice installations with
 *    the same user's address no longer share a salt, so work done against one
 *    is worthless against the other.
 *
 * WHAT IT DOES NOT BUY. The salt is public: the server's login-salt endpoint
 * returns it to anyone who asks to log in as the account (only an UNKNOWN
 * address gets a decoy). A targeted attacker who can query the server gets the
 * real salt and can precompute against that one account before any breach. The
 * salt is not secret entropy. THE PASSWORD REMAINS THE ONLY SECRET INPUT, and
 * the Argon2id cost in {@link ARGON2_PARAMS} is the only thing slowing an
 * offline guess.
 *
 * WHY IT IS STILL HASHED WITH A LABEL, when the input is already sixteen random
 * bytes. Not for width: the account salt is a fixed 16 bytes and comfortably
 * clears `@noble/hashes`' 8-byte minimum on its own. The hash is there for
 * domain separation. The same random bytes could, through a future bug or a
 * careless reuse, end up as input to some other derivation in this package; the
 * label guarantees that the MUK salt built from them is unrelated to anything
 * else built from them. It also keeps the Argon2 salt a fixed 32 bytes whatever
 * the account salt's width ever becomes, and puts the version into the
 * construction itself, where the known-answer vector pins it. The label is
 * fixed-length ASCII, so `label || accountSalt` is an unambiguous encoding.
 */
function mukSalt(accountSalt: Uint8Array): Uint8Array {
  return sha256(concat(utf8.encode(SALT_LABEL), accountSalt));
}

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
 * Derives the Master Unlock Key from a password and the account's salt.
 *
 * THE SALT COMES FROM THE SERVER, NOT FROM THE USER. It is minted once by
 * {@link newAccountSalt} at signup and stored beside the account; login fetches
 * it before deriving. It is public, so fetching it reveals nothing, and because
 * it is not the email address, an address change leaves the key untouched.
 *
 * A SERVER-SUPPLIED SALT IS NOT TRUSTED TO BE WELL-FORMED. It must be exactly
 * {@link ACCOUNT_SALT_BYTES} bytes, checked before any work. A wrong-width salt
 * is a bug upstream -- a hex string not decoded, a column truncated -- and it
 * would otherwise derive a perfectly plausible wrong key.
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
 * ON BLOCKING, STATED PLAINLY. The DEFAULT backend is `@noble/hashes`, which is
 * synchronous and holds the thread for the whole derivation, so on a browser
 * main thread it freezes the tab -- no paint, no input, no progress bar -- for
 * several seconds (measured: 5460 ms on a warm desktop x64, four to ten times
 * that on a mid-range phone). `@noble/hashes` also ships `argon2idAsync`, and
 * it does NOT fix this: its yield point is `await nextTick()` where
 * `nextTick = async () => {}`, which drains as a MICROTASK. Microtasks run
 * before rendering and before input, so `argon2idAsync` blocks exactly as hard
 * (measured: zero `setInterval(20ms)` callbacks fired during a 7.5-second run)
 * while costing more wall time. THE ASYNC VARIANT IS NOT A FIX AND MUST NOT BE
 * SUBSTITUTED HERE.
 *
 * THE FIX IS `options.argon2` PLUS A WEB WORKER, and it takes both halves. A
 * WASM backend on the main thread is ten times faster and still blocks; a
 * Worker without a WASM backend still costs the user eleven seconds. The
 * browser application supplies a WASM backend and runs this inside a Worker;
 * see `apps/admin/src/lib/crypto/`.
 *
 * THE BACKEND IS NOT A PARAMETER KNOB. It receives a frozen copy of
 * {@link ARGON2_PARAMS} and is checked against cheap Argon2id conformance
 * vectors before its output is ever accepted, so a backend that is the wrong
 * algorithm, ignores the parameters it is given, or returns the wrong width
 * fails rather than quietly deriving a different key. Read
 * {@link Argon2Backend} for what that check does and does not cover.
 */
export interface DeriveMUKOptions {
  /**
   * A faster Argon2id, at IDENTICAL parameters. Omit it and the audited pure-JS
   * default is used. This is the only supported way to change how the MUK is
   * computed, and it is per call: there is deliberately no global to set.
   */
  readonly argon2?: Argon2Backend;
}

export async function deriveMUK(
  password: string,
  accountSalt: Uint8Array,
  options?: DeriveMUKOptions,
): Promise<MasterUnlockKey> {
  // Both guards run before the derivation, not after. An empty password is
  // accepted by Argon2id without complaint, and validating afterwards would
  // make every rejected attempt cost a full multi-second grind on the user's
  // own device.
  if (password.length === 0) throw new Error("password must not be empty");
  // A runtime check, not just the type, because this signature used to take a
  // string -- the email -- and a JavaScript caller or a cast still written
  // against it must fail here rather than derive the key it was meant to stop
  // deriving.
  // `instanceof Uint8Array` is realm-sensitive: an array built in another realm
  // (an iframe, a `vm` context, jsdom) fails it. If that ever becomes a real
  // caller, the fallback is `ArrayBuffer.isView` plus the
  // `Object.prototype.toString` tag "[object Uint8Array]".
  if (!(accountSalt instanceof Uint8Array) || accountSalt.length !== ACCOUNT_SALT_BYTES) {
    throw new Error(`accountSalt must be ${ACCOUNT_SALT_BYTES} bytes`);
  }
  // Built NOW, not after the await below. The caller's buffer may be mutated or
  // detached across the await (transferred to a Worker, say), so the bytes are
  // captured at the moment they are validated; `concat` copies them.
  const salt = mukSalt(accountSalt);

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
  const backend = options?.argon2 ?? nobleArgon2;

  // Conformance FIRST, so an unusable backend costs two milliseconds and a
  // clear error instead of eleven seconds and a wrong key. The default is
  // checked too: exempting it would mean the one implementation everything else
  // is measured against is the only one never measured.
  await assertConformantArgon2(backend);

  // A frozen copy, so the backend -- which may be a Worker shim, a third-party
  // library, or a test double -- cannot mutate the module-level constant that
  // every subsequent derivation in the process will read.
  const params: Argon2Params = Object.freeze({ ...ARGON2_PARAMS });

  const out = await backend(utf8.encode(password.normalize("NFC")), salt, params);

  // Re-checked at the seam, not merely by the constructor. The constructor
  // says "32 bytes"; this says which component broke, which is the difference
  // between a five-minute fix and an afternoon.
  assertArgon2Output(out, ARGON2_PARAMS.dkLen);
  return new MasterUnlockKey(out);
}
