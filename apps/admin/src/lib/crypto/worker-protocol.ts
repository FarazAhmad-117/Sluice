/**
 * The message contract between the main thread and the MUK worker.
 *
 * WHAT CROSSES THIS BOUNDARY, STATED EXACTLY, because one of the two values is
 * the user's password in cleartext and the other is the root of their entire
 * key hierarchy.
 *
 * TOWARDS THE WORKER: the password string and the account salt. The password
 * has to cross -- `deriveMUK` owns NFC normalisation and salt construction, and
 * splitting those across threads is how two code paths end up normalising
 * differently and deriving two different keys for one user. Structured clone
 * makes a second copy of the string in the worker's heap; the worker is
 * terminated after every derivation, which is the only reliable way to get rid
 * of it, and of the 64 MiB of Argon2 working memory whose final blocks ARE the
 * MUK in recoverable form.
 *
 * THE SALT CROSSES AS LOWERCASE HEX, and it is the worker that turns it back
 * into bytes and `deriveMUK` that checks its width. It is public -- the server
 * returns it to anyone who asks to log in as the account -- so it needs no
 * care beyond arriving intact. A string rather than a `Uint8Array` because it
 * is the form the salt already has on the wire and in the persisted session,
 * and because a transferable buffer is one `transfer` list away from being
 * detached out from under the caller that still needs it. The width is NOT
 * validated only on the main thread: the worker must refuse a crafted or
 * corrupted message on its own, and `deriveMUK` is the one place that rule is
 * written. A server decoy for an unknown address is sixteen bytes too, so it
 * passes the same check and is derived under like any real salt; nothing on
 * this boundary can tell the two apart, and nothing should.
 *
 * BACK FROM THE WORKER: 32 raw bytes, transferred rather than copied, so the
 * worker's view is detached at the moment it is sent. Not a `MasterUnlockKey`:
 * that class keeps its bytes in a `#private` field, which is not an own
 * property, so structured clone would deliver an EMPTY object and the
 * length check in the constructor is what turns that mistake into an error
 * instead of a decryption that quietly fails months later.
 *
 * NOTHING IN EITHER DIRECTION MAY BE LOGGED. There is no `console.log` of a
 * message anywhere in this module or in the worker, and errors carry a message
 * string built by hand, never the request that caused them -- an error object
 * that echoed its input would put the password into whatever collects
 * uncaught worker errors.
 */

/** Derivation request. `password` is CLEARTEXT. Do not log, store or forward. */
export interface DeriveRequest {
  readonly kind: "derive";
  readonly id: number;
  readonly password: string;
  /**
   * The account salt, `toHex` of `ACCOUNT_SALT_BYTES` (16) bytes: 32 lowercase
   * hex characters. Public. Decoded by the worker; width enforced by
   * `deriveMUK`.
   */
  readonly accountSalt: string;
}

/** Memory feasibility check. Carries no secret, so it is safe to log in full. */
export interface ProbeRequest {
  readonly kind: "probe";
  readonly id: number;
  /** Memory cost in KiB, passed in so the worker never has to restate it. */
  readonly kib: number;
}

export type WorkerRequest = DeriveRequest | ProbeRequest;

/**
 * A request before the transport assigns its id.
 *
 * Spelled as a union of `Omit`s rather than `Omit<WorkerRequest, "id">`,
 * because `Omit` does not distribute over a union: the single-type form
 * collapses `DeriveRequest | ProbeRequest` to their COMMON keys and would make
 * `password` invisible to the type checker.
 */
export type WorkerRequestInit = Omit<DeriveRequest, "id"> | Omit<ProbeRequest, "id">;

/** 32 raw MUK bytes. The main thread re-wraps them immediately. */
export interface DeriveSuccess {
  readonly kind: "derived";
  readonly id: number;
  readonly bytes: Uint8Array;
}

export interface ProbeResult {
  readonly kind: "probed";
  readonly id: number;
  readonly ok: boolean;
  readonly reason?: string;
}

/**
 * A failure. `message` is composed from the thrown error's own message, which
 * for every throw site reachable from here -- parameter guards, conformance
 * failures, allocation failures -- names a condition and never echoes the
 * password or the key.
 */
export interface WorkerFailure {
  readonly kind: "failed";
  readonly id: number;
  readonly message: string;
}

export type WorkerResponse = DeriveSuccess | ProbeResult | WorkerFailure;
