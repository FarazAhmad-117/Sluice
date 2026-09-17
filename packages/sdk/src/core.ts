import { verifyRevocation, type RevocationNotice } from "@sluice/crypto";
import { sanitiseForLog } from "./sanitise";
import {
  EXIT_CODE,
  MAX_CLOCK_STEP_MS,
  MAX_DRAIN_MS,
  MIN_MAX_OFFLINE_DURATION_MS,
  NO_PERSISTED_FLOOR,
  type EpochFloor,
  type LogLevel,
  type SecretBundle,
  type ShutdownCause,
  type SluiceCoreOptions,
  type SluiceDecision,
  type SluiceEvent,
} from "./types";

/**
 * THE DECISION CORE. THIS IS THE CODE THAT DECIDES WHEN A CUSTOMER'S PROCESS
 * DIES, AND IT IS THE HIGHEST-SEVERITY CODE IN THE PROJECT.
 *
 * Read section 4.3 of the implementation plan before changing anything here.
 *
 * It is wrong in one direction if a Sluice outage kills every customer fleet at
 * once. It is wrong in the other direction if a stolen token keeps working
 * after an admin revoked it. Those two failures pull against each other, so the
 * design is built around one asymmetry: **only a cryptographic proof may kill a
 * running process, and the absence of information may not.** Connection loss is
 * absence of information. It is therefore never, under any sequence, a reason
 * to exit.
 *
 * WHY THIS CLASS IS PURE AND SYNCHRONOUS. No socket, no HTTP client, no Convex
 * client, no timer, no clock. Every input is an event and every output is a
 * decision, so the entire shutdown behaviour is a function of the event
 * sequence and can be enumerated exhaustively in a test rather than sampled.
 * `test/property.test.ts` does exactly that. The transport is a thin shell that
 * turns sockets into events and decisions into effects; when it arrives, it
 * must not acquire any judgement of its own.
 *
 * THE TIME SOURCE IS NOT TRUSTED, AND THE TWO KINDS OF DEADLINE TREAT IT
 * DIFFERENTLY. This is the same asymmetry as above, applied to the clock.
 *
 * A deadline that MUST fire is the drain: a revoked process that never reaches
 * its deadline is a stolen token still running. So the drain reads `now`
 * directly, fires when it passes the deadline, AND fires immediately if the
 * clock ever steps BACKWARDS during the drain. Every clock anomaly shortens the
 * drain; none can extend it. A shortened drain costs a customer an unflushed
 * telemetry buffer. A drain that never ends costs them the kill switch.
 *
 * A deadline that MUST NOT fire spuriously is `maxOfflineDurationMs`, the one
 * setting that lets an outage kill a fleet. It therefore does NOT subtract
 * timestamps. It accumulates per-event deltas, each clamped to
 * [0, MAX_CLOCK_STEP_MS], so a clock that leaps forward by a year -- a bad NTP
 * sync, a resumed VM, a host that passed a microsecond value -- contributes at
 * most one step instead of instantly exceeding every window. Backwards steps
 * contribute zero. The boot deadline uses the same accumulated clock.
 *
 * THE COST, STATED PLAINLY: a host that ticks less often than
 * MAX_CLOCK_STEP_MS under-counts offline time, so `maxOfflineDurationMs` fires
 * late. Late is the safe direction. A host must tick at least that often.
 *
 * AN EARLIER VERSION CLAMPED `now` TO BE NON-DECREASING AND USED THAT ONE VIEW
 * EVERYWHERE. Do not reintroduce it. A single garbage timestamp -- one event
 * carrying `1e15` -- pinned the clamped clock to the year 33658, after which
 * every real timestamp was ignored, every subsequent drain deadline was
 * unreachable, and the kill switch was dead for the life of the process. The
 * clamp also had no test that failed when it was removed, which is how it
 * survived review.
 */

type State = "booting" | "running" | "draining" | "dead";

/**
 * Must match the strictness `@sluice/crypto` applies internally. An uppercase
 * key decodes to the same bytes but `verifyRevocation` rejects it, so a core
 * built with one would silently never honour a revocation. Fail at
 * construction, where an operator sees it, not during an incident.
 */
const PUBLIC_KEY_HEX_PATTERN = /^[0-9a-f]{64}$/;
const TOKEN_ID_PATTERN = /^[0-9a-f]{32}$/;

/**
 * The internal spelling of "no revocation has been acted on".
 *
 * Private, and never crosses the API boundary in either direction: callers pass
 * {@link NO_PERSISTED_FLOOR} and `epochFloor` hands it back. Epoch 0 is a legal
 * notice epoch, so the empty floor has to sit below it, and a raw `-1` on the
 * public surface is precisely the accident this package now refuses.
 */
const NOTHING_SEEN = -1;

const DEFAULT_DRAIN_MS = 5_000;
const DEFAULT_BOOT_TIMEOUT_MS = 30_000;

/**
 * THE SHUTDOWN GATE.
 *
 * This symbol is module-private and is written into `#verifiedProof` at exactly
 * one place in this file: the branch immediately after `verifyRevocation`
 * returns `true`. `#shutdown` refuses to act on a `"revocation"` cause without
 * it and throws instead.
 *
 * It is deliberately unreachable dead code today. Its job is to be tripped by a
 * future refactor. If someone moves the shutdown call outside the verified
 * branch -- restructures the switch, adds an early return, "simplifies" the
 * ordering -- the result is a thrown error in one process, not a signature-free
 * kill switch across every customer fleet. An exhaustive test can only cover
 * the alphabet it was given; this covers the code.
 */
const VERIFIED: unique symbol = Symbol("sluice/revocation-signature-verified");

interface ShutdownProof {
  readonly cause: ShutdownCause;
  readonly signedReason: string;
  readonly epoch: number | null;
  /** Present only for `cause: "revocation"`, and only after verification. */
  readonly verified?: typeof VERIFIED;
}

function assertIntInRange(name: string, value: number, min: number, max: number): void {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer in [${min}, ${max}], got ${String(value)}`);
  }
}

export class SluiceCore {
  readonly #orgRevocationPublicKey: string;
  readonly #tokenId: string;
  readonly #drainMs: number;
  readonly #maxOfflineDurationMs: number | undefined;
  readonly #bootTimeoutMs: number;

  #state: State = "booting";
  #booted = false;
  #online = false;
  #applied = false;
  #lastBundle: SecretBundle | null = null;
  #pdkEpoch: number | null = null;
  #epochFloor: number;
  /** Last finite `now` seen, verbatim. Drives the drain deadline only. */
  #raw = 0;
  /** Previous `#raw`, for delta accumulation. `null` until the first event. */
  #lastRaw: number | null = null;
  /** Accumulated, per-step-clamped timeline. Never decreases, never leaps. */
  #elapsed = 0;
  #bootStartedElapsed: number | null = null;
  #bootDeadlineElapsed: number | null = null;
  #offlineSinceElapsed: number | null = null;
  #drainStartedRaw: number | null = null;
  #drainDeadlineRaw: number | null = null;
  #verifiedProof: typeof VERIFIED | null = null;

  constructor(options: SluiceCoreOptions) {
    // The org key is checked here and nowhere else, because there is nowhere
    // else it could come from. See `SluiceCoreOptions` for why it must never be
    // fetched: a server that could supply this key could sign its own notices
    // and kill every fleet on the platform at once.
    if (
      typeof options?.orgRevocationPublicKey !== "string" ||
      !PUBLIC_KEY_HEX_PATTERN.test(options.orgRevocationPublicKey)
    ) {
      throw new Error(
        "orgRevocationPublicKey must be 64 lowercase hex characters, supplied by the caller " +
          "from customer-controlled configuration and never fetched from a server",
      );
    }
    if (typeof options.tokenId !== "string" || !TOKEN_ID_PATTERN.test(options.tokenId)) {
      throw new Error("tokenId must be 32 lowercase hex characters");
    }
    this.#orgRevocationPublicKey = options.orgRevocationPublicKey;
    this.#tokenId = options.tokenId;

    // An unbounded drain is a revocation that never lands, so the ceiling is
    // not configurable away. `onRevoke` may delay the exit; it may not cancel it.
    this.#drainMs = options.drainMs ?? DEFAULT_DRAIN_MS;
    assertIntInRange("drainMs", this.#drainMs, 0, MAX_DRAIN_MS);

    this.#bootTimeoutMs = options.bootTimeoutMs ?? DEFAULT_BOOT_TIMEOUT_MS;
    assertIntInRange("bootTimeoutMs", this.#bootTimeoutMs, 0, Number.MAX_SAFE_INTEGER);

    // Default unlimited, per section 4.3. This is the only knob in the package
    // that lets an outage kill a fleet, so the value is checked hard: a `0`, or
    // a few hundred milliseconds, would turn an ordinary reconnect into a
    // fleet-wide outage -- the exact failure the rest of this file prevents.
    this.#maxOfflineDurationMs = options.maxOfflineDurationMs;
    if (this.#maxOfflineDurationMs !== undefined) {
      assertIntInRange(
        "maxOfflineDurationMs",
        this.#maxOfflineDurationMs,
        MIN_MAX_OFFLINE_DURATION_MS,
        Number.MAX_SAFE_INTEGER,
      );
    }

    // No `??` here, deliberately. A default would be a silent off switch: a
    // host that forgot to persist the floor would be replayable on every
    // restart and nothing anywhere would say so. The caller states which case
    // they are in, and `-1` -- the old default, and the value a caller would
    // reach for by habit -- is rejected along with every other negative.
    if (options.initialEpochFloor === NO_PERSISTED_FLOOR) {
      this.#epochFloor = NOTHING_SEEN;
    } else {
      assertIntInRange(
        "initialEpochFloor",
        options.initialEpochFloor as number,
        0,
        Number.MAX_SAFE_INTEGER,
      );
      this.#epochFloor = options.initialEpochFloor as number;
    }
  }

  get state(): State {
    return this.#state;
  }

  get online(): boolean {
    return this.#online;
  }

  /**
   * The highest revocation epoch this core has acted on, or
   * {@link NO_PERSISTED_FLOOR} if it has acted on none.
   *
   * PERSIST THIS AFTER EVERY ACCEPTED NOTICE AND PASS IT BACK AS
   * `initialEpochFloor`; a host that does not is replayable on every restart,
   * because Ed25519 signatures are deterministic and a captured genuine notice
   * verifies forever against a process that has seen nothing.
   *
   * The return type is the same union `initialEpochFloor` accepts, so a host
   * can store this value verbatim and hand it straight back without ever
   * translating a sentinel -- which is how the old `-1` would have leaked into
   * configuration and reopened the replay window it was meant to close.
   *
   * Deduplicating by signature bytes is NOT a substitute and must not be added.
   * Ed25519 admits multiple valid encodings of a signature for one message and
   * noble's verify is permissive about `S`, so an attacker who cannot forge
   * anything can still produce different bytes that verify for the same notice.
   * The epoch is immune to that; a set of seen byte strings is not.
   */
  get epochFloor(): EpochFloor {
    // Returns the same union the constructor takes, so "persist this and pass
    // it back" is always sound -- including on a process that has never seen a
    // revocation, where a raw `-1` would be rejected on the way back in.
    return this.#epochFloor === NOTHING_SEEN ? NO_PERSISTED_FLOOR : this.#epochFloor;
  }

  get drainMs(): number {
    return this.#drainMs;
  }

  get maxOfflineDurationMs(): number | undefined {
    return this.#maxOfflineDurationMs;
  }

  /** The last bundle installed, or null. Never logged by this package. */
  get lastKnownGood(): SecretBundle | null {
    return this.#lastBundle;
  }

  /**
   * Feed one event, get back every decision it produced.
   *
   * An empty array is "do nothing" -- there is no `{ type: "none" }`, because
   * an empty array is the one spelling a caller cannot mishandle.
   *
   * Never throws on hostile input. A malformed notice, a non-finite clock, an
   * unknown event type: all of them produce a log decision and no exit. The one
   * exception is the internal gate in `#shutdown`, which throws on a bug that
   * would otherwise mean an unauthenticated kill.
   */
  handle(event: SluiceEvent): SluiceDecision[] {
    if (this.#state === "dead") return [];
    this.#advanceClock(event?.now);

    const out = this.#dispatch(event, this.#raw);

    // Deadlines are evaluated after EVERY event, not only on `tick`. A host
    // that is slow with its timer, or that only ticks while idle, still exits
    // on time, and `drainMs: 0` exits on the same event rather than waiting for
    // a tick that a shutting-down process may never send.
    if (
      this.#state === "booting" &&
      this.#bootDeadlineElapsed !== null &&
      this.#elapsed >= this.#bootDeadlineElapsed
    ) {
      out.push(...this.#failToStart());
    }
    if (this.#state === "running" && this.#maxOfflineDurationMs !== undefined) {
      const since = this.#offlineSinceElapsed;
      if (since !== null && this.#elapsed - since >= this.#maxOfflineDurationMs) {
        out.push(
          ...this.#shutdown(this.#raw, {
            cause: "offline-limit",
            epoch: null,
            signedReason:
              `offline for ${this.#elapsed - since}ms, past the opted-in maxOfflineDuration ` +
              `of ${this.#maxOfflineDurationMs}ms`,
          }),
        );
      }
    }
    if (this.#state === "draining" && this.#drainDeadlineRaw !== null) {
      // Either the deadline passed, or the clock moved backwards during the
      // drain. Both end it. See the header: every clock anomaly shortens a
      // drain and none may extend one.
      if (this.#raw >= this.#drainDeadlineRaw) {
        out.push(...this.#exit("drain window elapsed"));
      } else if (this.#drainStartedRaw !== null && this.#raw < this.#drainStartedRaw) {
        out.push(
          log(
            "warn",
            "clock-went-backwards",
            "the clock moved backwards during the drain; ending the drain now rather than " +
              "risking a revoked process that never reaches its deadline",
          ),
          ...this.#exit("clock moved backwards during drain"),
        );
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- dispatch

  #dispatch(event: SluiceEvent, now: number): SluiceDecision[] {
    switch (event?.type) {
      case "boot":
        return this.#onBoot(event.cache, now);
      case "bundle":
        return this.#onBundle(event.bundle, now);
      case "epoch-bump":
        return this.#onEpochBump(event.epoch);
      case "revocation":
        return this.#onRevocation(event.notice, event.signature, now);
      case "disconnected":
        return this.#onDisconnected(event.cause, now);
      case "reconnected":
        return this.#onReconnected(now);
      case "drain-complete":
        return this.#state === "draining" ? this.#exit("drain handler finished") : [];
      case "drain-failed":
        return this.#onDrainFailed(event.error);
      case "tick":
        return [];
      default:
        return [
          log(
            "error",
            "unknown-event",
            `ignored an unrecognised event: ${sanitiseForLog(String((event as { type?: unknown })?.type))}`,
          ),
        ];
    }
  }

  #onBoot(cache: SecretBundle | null, now: number): SluiceDecision[] {
    if (this.#booted) {
      // Re-arming the boot deadline from a second boot would let a host
      // postpone `fail-to-start` indefinitely by booting in a loop.
      return [log("error", "double-boot", "boot event received twice; ignored")];
    }
    this.#booted = true;
    this.#bootStartedElapsed = this.#elapsed;
    this.#bootDeadlineElapsed = this.#elapsed + this.#bootTimeoutMs;

    if (!isBundle(cache)) {
      // Nothing to run with and nothing confirmed yet. Stay silent and let the
      // boot deadline decide, so a slow first connection is not a failure.
      return [];
    }

    // Section 4.3: boot with disk cache and no network starts in degraded mode
    // and alarms loudly. Degraded is not a failure state and must never become
    // one -- these are the customer's real secrets, merely unconfirmed.
    this.#state = "running";
    this.#bootDeadlineElapsed = null;
    this.#offlineSinceElapsed = this.#elapsed;
    return [
      log(
        "warn",
        "degraded-start",
        "started from the on-disk cache without confirming it against Sluice: secrets may be " +
          "stale and no revocation can be received until the connection is up",
      ),
      metric("sluice.boot.degraded", 1),
      ...this.#applySecrets(cache, true),
    ];
  }

  #onBundle(bundle: SecretBundle, now: number): SluiceDecision[] {
    if (this.#state !== "booting" && this.#state !== "running") return [];
    if (!isBundle(bundle)) {
      return [
        log("error", "malformed-bundle", "ignored a malformed bundle; keeping last known good"),
      ];
    }
    // A bundle cannot arrive over a dead socket, so receiving one is proof the
    // connection is live.
    const out = this.#markOnline();
    this.#state = "running";
    this.#bootDeadlineElapsed = null;
    if (this.#pdkEpoch === null || bundle.epoch > this.#pdkEpoch) this.#pdkEpoch = bundle.epoch;
    out.push(...this.#applySecrets(bundle, false));
    return out;
  }

  #onEpochBump(epoch: number): SluiceDecision[] {
    if (this.#state !== "booting" && this.#state !== "running") return [];
    if (!Number.isSafeInteger(epoch) || epoch < 0) {
      return [log("error", "malformed-epoch-bump", "ignored a malformed epoch bump")];
    }
    if (this.#pdkEpoch !== null && epoch <= this.#pdkEpoch) return [];
    this.#pdkEpoch = epoch;
    // Section 4.1: an epoch bump means the PDK was re-keyed. Re-fetch. NO crash.
    return [
      log("info", "epoch-bump", `PDK epoch moved to ${epoch}; re-fetching the bundle`),
      { type: "refetch", epoch },
    ];
  }

  /**
   * THE ONLY PATH FROM A HEALTHY PROCESS TO A SHUTDOWN.
   *
   * Three gates, in this order, and the order is load-bearing:
   *
   * 1. IS IT ABOUT US? `verifyRevocation` proves the organisation signed the
   *    notice, not that the notice names this token. Without this check a
   *    single genuine revocation of any one token would kill every process in
   *    the organisation.
   * 2. IS IT AUTHENTIC? A `false` here means DO NOT SHUT DOWN. It never means
   *    "maybe". The server, the network, and anyone who can write to the
   *    database can deliver arbitrary bytes down this channel; none of them can
   *    produce this signature.
   * 3. IS IT FRESH? Ed25519 signatures are deterministic, so a genuine notice
   *    replays forever. The epoch floor is the freshness check.
   *
   * THE FLOOR MOVES ONLY AFTER GATES 1 AND 2 PASS. If an unverified notice
   * could raise it, one forged message carrying `epoch: MAX_SAFE_INTEGER` would
   * permanently immunise a stolen token against every future revocation -- a
   * silent, total failure of the product's central promise. Equally, a genuine
   * notice for someone else's token must not raise our floor, which is why the
   * token check comes first rather than being folded in afterwards.
   *
   * The floor is NOT taken from any server-supplied value. The PDK epoch on a
   * bundle is a different counter in a different namespace, and reading it here
   * would hand a compromised server the same immunisation attack for free.
   */
  #onRevocation(notice: RevocationNotice, signature: Uint8Array, now: number): SluiceDecision[] {
    if (this.#state === "draining") {
      return [log("info", "revocation-during-drain", "already draining; the shutdown stands")];
    }

    // Plain `!==` rather than a constant-time compare, deliberately: the token
    // id is public -- it is uploaded at mint time and stored server-side -- so
    // there is no secret here for a timing side channel to leak.
    const noticeTokenId = (notice as { tokenId?: unknown } | null)?.tokenId;
    if (typeof noticeTokenId !== "string" || noticeTokenId !== this.#tokenId) {
      return [
        log(
          "warn",
          "revocation-other-token",
          `ignored a revocation naming a different token: ${sanitiseForLog(String(noticeTokenId))}`,
        ),
        metric("sluice.revocation.other_token", 1),
      ];
    }

    if (!verifyRevocation(this.#orgRevocationPublicKey, notice, signature)) {
      return [
        log(
          "error",
          "revocation-bad-signature",
          "REJECTED a revocation notice for this token: the signature does not verify against " +
            "the pinned organisation revocation key. The process is NOT exiting. Someone with " +
            "write access to the delivery channel is trying to kill this process.",
        ),
        metric("sluice.revocation.invalid_signature", 1),
      ];
    }

    const epoch = notice.epoch;
    if (epoch <= this.#epochFloor) {
      return [
        log(
          "warn",
          "revocation-replay",
          `ignored a genuine but stale revocation at epoch ${epoch}; already at or past ` +
            `epoch ${this.#epochFloor}`,
        ),
        metric("sluice.revocation.replayed", 1),
      ];
    }

    this.#epochFloor = epoch;
    this.#verifiedProof = VERIFIED;
    return this.#shutdown(now, {
      cause: "revocation",
      epoch,
      signedReason: notice.reason,
      verified: VERIFIED,
    });
  }

  #onDisconnected(cause: string | undefined, now: number): SluiceDecision[] {
    if (this.#state === "draining") return [];
    // Section 4.3, and the reason this file exists: keep the last known good
    // bundle, reconnect with backoff, emit a metric and a WARN. DO NOT EXIT.
    // There is intentionally no path from this method to a shutdown decision.
    const alreadyDown = !this.#online && this.#offlineSinceElapsed !== null;
    this.#online = false;
    if (this.#offlineSinceElapsed === null) this.#offlineSinceElapsed = this.#elapsed;
    if (alreadyDown) return [];
    return [
      log(
        "warn",
        "disconnected",
        `lost the Sluice connection${cause === undefined ? "" : `: ${sanitiseForLog(String(cause))}`}. ` +
          "Keeping the last known good secrets and reconnecting. NOT exiting: a connection " +
          "loss is not a revocation.",
      ),
      metric("sluice.connection.lost", 1),
    ];
  }

  #onReconnected(now: number): SluiceDecision[] {
    if (this.#state === "draining") return [];
    return this.#markOnline();
  }

  #markOnline(): SluiceDecision[] {
    if (this.#online) return [];
    const downtime =
      this.#offlineSinceElapsed === null ? 0 : this.#elapsed - this.#offlineSinceElapsed;
    this.#online = true;
    this.#offlineSinceElapsed = null;
    return [
      log("info", "reconnected", `Sluice connection restored after ${downtime}ms`),
      metric("sluice.connection.downtime_ms", downtime),
    ];
  }

  #onDrainFailed(error: string): SluiceDecision[] {
    if (this.#state !== "draining") return [];
    // The handler is the customer's code and it is allowed to fail. What it is
    // not allowed to do is cancel the exit, so a failure shortens the drain
    // rather than aborting it.
    return [
      log(
        "error",
        "drain-handler-failed",
        `the onRevoke handler failed: ${sanitiseForLog(String(error))}. Exiting now.`,
      ),
      metric("sluice.revocation.drain_failed", 1),
      ...this.#exit("drain handler failed"),
    ];
  }

  // ----------------------------------------------------------------- effects

  #applySecrets(bundle: SecretBundle, degraded: boolean): SluiceDecision[] {
    const previous = this.#lastBundle?.secrets;
    const next = bundle.secrets;
    const changed: string[] = [];
    const removed: string[] = [];
    for (const key of Object.keys(next)) {
      const before = previous !== undefined && own(previous, key) ? previous[key] : undefined;
      if (before !== next[key]) changed.push(key);
    }
    if (previous !== undefined) {
      for (const key of Object.keys(previous)) if (!own(next, key)) removed.push(key);
    }
    this.#lastBundle = bundle;
    if (changed.length === 0 && removed.length === 0) return [];
    this.#applied = true;
    // Section 4.1: a value rotation pushes the new value and fires onChange. It
    // NEVER crashes. If rotating a value killed production nobody would ever
    // rotate anything, and the product's premise would collapse.
    //
    // `changed` and `removed` are key NAMES only. Values are in `bundle` and
    // must never reach a log line.
    return [
      { type: "apply-secrets", bundle, changed: changed.sort(), removed: removed.sort(), degraded },
    ];
  }

  #shutdown(now: number, proof: ShutdownProof): SluiceDecision[] {
    // See VERIFIED above. Unreachable today; it is here so a future refactor
    // that moves this call outside the verified branch fails loudly in one
    // process instead of quietly killing fleets.
    if (
      proof.cause === "revocation" &&
      (proof.verified !== VERIFIED || this.#verifiedProof !== VERIFIED)
    ) {
      throw new Error(
        "BUG: a revocation shutdown was ordered without a verified signature. Refusing to exit.",
      );
    }
    if (this.#state === "draining" || this.#state === "dead") return [];
    this.#state = "draining";
    this.#drainStartedRaw = now;
    this.#drainDeadlineRaw = now + this.#drainMs;
    const reason = sanitiseForLog(proof.signedReason);
    const revoked = proof.cause === "revocation";
    return [
      log(
        revoked ? "error" : "warn",
        revoked ? "revoked" : "offline-limit",
        revoked
          ? `REVOKED by a valid signed notice at epoch ${String(proof.epoch)}. Reason: ${reason}. ` +
              `Draining for ${this.#drainMs}ms, then exiting ${EXIT_CODE}.`
          : `${reason}. Draining for ${this.#drainMs}ms, then exiting ${EXIT_CODE}.`,
      ),
      metric(revoked ? "sluice.revocation.accepted" : "sluice.offline_limit.reached", 1),
      {
        type: "shutdown",
        cause: proof.cause,
        reason,
        signedReason: proof.signedReason,
        epoch: proof.epoch,
        drainMs: this.#drainMs,
      },
    ];
  }

  #exit(why: string): SluiceDecision[] {
    if (this.#state === "dead") return [];
    this.#state = "dead";
    this.#drainDeadlineRaw = null;
    return [{ type: "exit", code: EXIT_CODE, reason: why }];
  }

  #failToStart(): SluiceDecision[] {
    // Section 4.3: boot with no cache and no network fails to start, because
    // there is nothing to run with anyway.
    //
    // THIS IS NOT A SHUTDOWN AND CAN NEVER BECOME ONE. It is reachable only
    // from `booting`, and `booting` is left permanently the first time a cache
    // or a bundle is applied, so it cannot terminate a process that ever had
    // secrets. `#applied` is asserted rather than assumed.
    if (this.#applied) {
      throw new Error("BUG: fail-to-start reached after secrets were applied. Refusing to exit.");
    }
    const waited =
      this.#bootStartedElapsed === null
        ? this.#bootTimeoutMs
        : this.#elapsed - this.#bootStartedElapsed;
    this.#state = "dead";
    this.#bootDeadlineElapsed = null;
    return [
      log(
        "error",
        "boot-failed",
        `no cached secrets and no Sluice connection after ${waited}ms. Failing to start.`,
      ),
      metric("sluice.boot.failed", 1),
      {
        type: "fail-to-start",
        code: EXIT_CODE,
        reason: "no cached secrets and no connection at boot",
      },
    ];
  }

  /**
   * Ingests one `now`. Non-finite values are dropped entirely, so `NaN`,
   * `Infinity` and a missing field leave both timelines exactly as they were
   * rather than poisoning a deadline with arithmetic on `NaN`.
   */
  #advanceClock(now: unknown): void {
    if (typeof now !== "number" || !Number.isFinite(now)) return;
    const delta = this.#lastRaw === null ? 0 : now - this.#lastRaw;
    this.#elapsed += Math.min(Math.max(delta, 0), MAX_CLOCK_STEP_MS);
    this.#lastRaw = now;
    this.#raw = now;
  }
}

function log(level: LogLevel, code: string, message: string): SluiceDecision {
  return { type: "log", level, code, message };
}

function metric(name: string, value: number): SluiceDecision {
  return { type: "metric", name, value };
}

/**
 * Own-property test. `secrets` arrives from a database row, so `in` and bare
 * member access would read inherited names: a bundle with no `toString` key
 * would still report one, and a diff built that way would be wrong in both
 * directions.
 */
function own(object: Readonly<Record<string, string>>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function isBundle(value: unknown): value is SecretBundle {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as SecretBundle).epoch === "number" &&
    typeof (value as SecretBundle).secrets === "object" &&
    (value as SecretBundle).secrets !== null
  );
}
