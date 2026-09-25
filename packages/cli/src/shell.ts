import {
  applyDecisions,
  MAX_CLOCK_STEP_MS,
  NO_PERSISTED_FLOOR,
  sanitiseForLog,
  type EpochFloor,
  type SecretBundle,
  type SluiceCore,
  type SluiceEvent,
  type SluiceHost,
} from "@sluice/sdk";
import { BundleDecryptError, decryptSecrets, readRevocation, type RawBundle } from "./bundle";
import type { TokenIdentity } from "./config";
import type { EpochFloorStore } from "./floor";
import type { BundleCredential, Handshaker } from "./handshake";
import type {
  BundleSource,
  ChildProcessSupervisor,
  Logger,
  TimerHandle,
  Timers,
} from "./ports";

/**
 * THE TRANSPORT SHELL. SOCKETS AND SIGNALS IN, EVENTS TO THE CORE, DECISIONS
 * BACK OUT. IT HAS NO JUDGEMENT OF ITS OWN AND MUST NEVER ACQUIRE ONE.
 *
 * `SluiceCore` is pure and synchronous: events in, decisions out, no network
 * and no clock. Every one of its guarantees is enumerated over an event
 * sequence, which means every one of them is a guarantee about a sequence THIS
 * FILE produces. The core cannot be wrong about a deadline it is never told
 * about, so the ways left to break the kill switch all live here, and all of
 * them are omissions rather than mistakes.
 *
 * THE FOUR OBLIGATIONS FROM `packages/sdk/src/host.ts`, AND WHERE EACH ONE IS.
 *
 *  1. AN INDEPENDENT TIMER, TICKING AT LEAST EVERY `MAX_CLOCK_STEP_MS`.
 *     {@link Shell.start} arms `#tickTimer` FIRST, before the handshake, before
 *     the boot event, before anything that can throw. A shell that stops
 *     ticking leaves a revoked process alive forever, so the tick must not be
 *     downstream of anything that can fail. It is never cleared until the
 *     process is on its way out, and on a real runtime it is not unref'd, so an
 *     otherwise idle process cannot exit 0 mid-drain and look like a clean
 *     shutdown in every dashboard.
 *
 *  2. NEVER WAIT FOR `onRevoke` BEFORE TICKING. `#beginDrain` arms the drain
 *     deadline BEFORE it calls the handler, on the line above the call, and the
 *     handler's result is consumed in a detached continuation. A handler that
 *     hangs forever, returns a thenable that never settles, or throws from its
 *     own `then` getter changes when this process exits by exactly nothing.
 *
 *  3. NEVER HAND CUSTOMER CODE ANYTHING THAT CAN CANCEL THE TIMER. The handler
 *     is called with ONE argument, an already sanitised string, and with no
 *     `this`. It is given no abort controller, no abort signal, no cancellation
 *     token, no `{ cancel }` object and no reference to this shell. Passing one
 *     of those feels like good hygiene and hands back exactly the power the
 *     drain bound exists to take away. Every timer handle is a `#private`
 *     field, so there is nothing to reach even by reflection, and
 *     `shell.test.ts` reads this source to prove the two platform abort types
 *     are not named anywhere in it.
 *
 *  4. PERSIST AND RESTORE THE EPOCH FLOOR. `#pump` compares `core.epochFloor`
 *     after EVERY event and writes it before the resulting decisions are
 *     applied, so the floor is on disk before the `exit` decision that does not
 *     return. It is deliberately not keyed off the shutdown decision: a
 *     decision shape can change, and `epochFloor` moving is the fact that
 *     matters.
 *
 * AND THE FIFTH, WHICH IS THE ONE THIS PRODUCT FOUND ON ITS OWN. A live
 * subscription whose five minute bundle token has expired still re-runs when a
 * revocation lands, and then throws. The SDK sees a transport error, and a
 * transport error never means revocation, so the process carries on from cache
 * forever. `#scheduleRefresh` re-handshakes at half the remaining lifetime, on
 * a timer that belongs to this shell and knows nothing about the subscription,
 * and `#onSubscriptionError` re-handshakes immediately when the query refuses.
 * A workload that stops re-handshaking is un-revokable.
 *
 * ON REENTRANCY. `host.ts` asks that `SluiceCore.handle` is never called
 * synchronously from inside a host callback, because a nested `applyDecisions`
 * can reach `exit` while the outer loop is still running. Every event in this
 * file goes through {@link Shell.#enqueue}, and `#pump` refuses to nest. There
 * is no other way in.
 *
 * WHAT THIS FILE MAY NOT DO, and the test suite checks it by reading this
 * source: it may not decide to exit, it may not decide to signal the child on
 * its own account, and it may not filter, validate or second-guess a revocation
 * notice. The only path from a Sluice decision to a dead child is
 * `#stopChild`, which is reachable only from `host.exit`, which is reachable
 * only from an `exit` or `fail-to-start` decision the core returned.
 */

/**
 * Well under `MAX_CLOCK_STEP_MS`, and not a divisor of it by accident.
 *
 * The core clamps any single clock step to `MAX_CLOCK_STEP_MS` when
 * accumulating the timeline behind `maxOfflineDurationMs` and the boot
 * deadline, so a shell that ticked exactly at the limit would under-count
 * whenever a tick ran even a millisecond late, which is every tick on a busy
 * runtime. A quarter of the limit means four chances to be late.
 */
const TICK_INTERVAL_MS = 15_000;

/** Never re-handshake more often than this, whatever the server claims. */
const MIN_REFRESH_MS = 5_000;

/** The first backoff step after a failed handshake. */
const BASE_BACKOFF_MS = 1_000;

/** The ceiling on backoff. Longer than this and a revocation waits too long. */
const MAX_BACKOFF_MS = 30_000;

export interface ShellOptions {
  readonly core: SluiceCore;
  readonly identity: TokenIdentity;
  readonly timers: Timers;
  readonly logger: Logger;
  readonly handshaker: Handshaker;
  readonly source: BundleSource;
  readonly child: ChildProcessSupervisor;
  readonly floorStore: EpochFloorStore;
  /** Terminates the process. `process.exit` in a real shell. */
  readonly exit: (code: number) => void;
  readonly killGraceMs: number;
  /**
   * The core's own `bootTimeoutMs`, restated here.
   *
   * IT IS DUPLICATED ON PURPOSE AND THE DUPLICATION IS NOT FREE. The core
   * evaluates every deadline on every event, and the routine tick is a quarter
   * of `MAX_CLOCK_STEP_MS`, so a boot timeout shorter than that would be
   * reached late by up to one tick: the process would sit there past the
   * deadline it was given, looking hung. A one-shot timer at exactly the boot
   * deadline removes that, and the cost is that a caller who passes a different
   * number here to the one the core holds gets a tick at the wrong moment,
   * which is harmless because the core, not this timer, decides.
   */
  readonly bootTimeoutMs: number;
  /** The environment the child inherits, before the secrets are overlaid. */
  readonly baseEnv: Record<string, string | undefined>;
  /**
   * OPTIONAL CUSTOMER DRAIN HOOK. It may DELAY the exit up to `drainMs`. It may
   * not cancel it, and nothing it is given can.
   */
  readonly onRevoke?: (reason: string) => unknown;
  /** Spreads a fleet's re-handshakes. Injected so tests are deterministic. */
  readonly jitter?: () => number;
}

/**
 * `draining` IS A SEPARATE PHASE AND IT HAS TO BE.
 *
 * Everything that can put a byte on a socket already refuses to run outside
 * `running`, so entering `draining` the instant the core orders a shutdown
 * silences all of them at once. Without it there is a real hole: a handshake
 * that was already in flight when the notice landed resolves DURING the drain,
 * and its success path opens a brand new subscription on a process that is on
 * its way out. That is traffic after the revocation, from a code path that
 * looks entirely reasonable at its call site.
 *
 * `#enqueue` deliberately does NOT stop at `draining`. The drain's own events,
 * `drain-complete`, `drain-failed` and the deadline tick, all arrive after this
 * point and every one of them is how the process finishes dying.
 */
type Phase = "idle" | "running" | "draining" | "stopping" | "stopped";

export class Shell {
  readonly #core: SluiceCore;
  readonly #identity: TokenIdentity;
  readonly #timers: Timers;
  readonly #logger: Logger;
  readonly #handshaker: Handshaker;
  readonly #source: BundleSource;
  readonly #child: ChildProcessSupervisor;
  readonly #floorStore: EpochFloorStore;
  readonly #exit: (code: number) => void;
  readonly #killGraceMs: number;
  readonly #bootTimeoutMs: number;
  readonly #baseEnv: Record<string, string | undefined>;
  readonly #onRevoke: ((reason: string) => unknown) | undefined;
  readonly #jitter: () => number;
  readonly #host: SluiceHost;

  #phase: Phase = "idle";
  #queue: SluiceEvent[] = [];
  #pumping = false;

  #tickTimer: TimerHandle | null = null;
  #drainTimer: TimerHandle | null = null;
  #refreshTimer: TimerHandle | null = null;
  #killTimer: TimerHandle | null = null;

  #spawned = false;
  #ticks = 0;
  #connected = false;
  #everConnected = false;
  #handshakeInFlight = false;
  #handshakeFailures = 0;
  #bundleSequence = 0;
  #appliedSequence = 0;
  #inFlight = 0;
  #persistedFloor: EpochFloor = NO_PERSISTED_FLOOR;

  #currentUnsubscribe: (() => void) | null = null;
  #retiringUnsubscribe: (() => void) | null = null;
  #generation = 0;

  constructor(options: ShellOptions) {
    this.#core = options.core;
    this.#identity = options.identity;
    this.#timers = options.timers;
    this.#logger = options.logger;
    this.#handshaker = options.handshaker;
    this.#source = options.source;
    this.#child = options.child;
    this.#floorStore = options.floorStore;
    this.#exit = options.exit;
    this.#killGraceMs = options.killGraceMs;
    this.#bootTimeoutMs = options.bootTimeoutMs;
    this.#baseEnv = options.baseEnv;
    this.#onRevoke = options.onRevoke;
    this.#jitter = options.jitter ?? Math.random;
    this.#persistedFloor = options.core.epochFloor;

    this.#host = {
      exit: (code: number) => this.#stopChild(code),
      log: (level, code, message) => this.#logger.log(level, code, message),
      metric: (name, value) => this.#logger.metric(name, value),
      applySecrets: (bundle, changed, removed) => this.#onSecrets(bundle, changed, removed),
      refetch: (epoch) =>
        this.#logger.log(
          "info",
          "refetch",
          `the core asked for the bundle at epoch ${epoch}; the subscription is reactive and ` +
            "has already asked for it",
        ),
      beginDrain: (reason, drainMs) => this.#beginDrain(reason, drainMs),
    };
  }

  /** Observable for the obligation tests. Carries nothing a handler could use. */
  get ticksEmitted(): number {
    return this.#ticks;
  }

  /**
   * True while a handshake or a decryption has not settled.
   *
   * Two asynchronous things happen behind this shell's back, and both are real
   * asynchrony rather than a microtask: a network round trip, and AES-GCM,
   * which on Node resolves off the thread pool. A test driving a virtual clock
   * has no other way to know that the work a tick started has finished, and
   * guessing with a fixed number of event loop turns turns a deterministic
   * clock back into a race. It is a read-only number and nothing acts on it.
   */
  get busy(): boolean {
    return this.#inFlight > 0;
  }

  get tickIntervalMs(): number {
    return TICK_INTERVAL_MS;
  }

  /**
   * ORDER IS LOAD BEARING HERE.
   *
   * The tick is armed before the boot event and before the first handshake,
   * because everything after this line can fail and the tick is what makes
   * every deadline in the core reachable. A shell that armed its timer after a
   * successful connection would have no timer in precisely the case the timer
   * exists for.
   */
  start(): void {
    if (this.#phase !== "idle") return;
    this.#phase = "running";

    this.#tickTimer = this.#timers.setInterval(() => {
      this.#ticks += 1;
      this.#pollConnection();
      this.#enqueue({ type: "tick", now: this.#timers.now() });
    }, TICK_INTERVAL_MS);

    this.#child.onExit((code, signal) => this.#onChildExit(code, signal));

    // NO DISK CACHE, AND THAT IS A DECISION RATHER THAN AN OMISSION. Section
    // 4.3 allows a degraded start from a cache, and the core implements it. A
    // cache of DECRYPTED secrets on disk would put every value this product
    // exists to protect in a file that outlives the process, on the machine
    // most likely to be the one that was compromised. Until there is an
    // encrypted cache with a key that is not also on that disk, this shell has
    // no cache, and boot with no network correctly fails to start.
    this.#enqueue({ type: "boot", cache: null, now: this.#timers.now() });

    // A tick at exactly the boot deadline, so a boot timeout shorter than the
    // routine tick is still reached on time. The core decides what it means;
    // this only guarantees it is asked at the right moment. Harmless once boot
    // has succeeded: `tick` produces no decisions in a running core.
    this.#timers.setTimeout(() => {
      this.#enqueue({ type: "tick", now: this.#timers.now() });
    }, this.#bootTimeoutMs);

    void this.#refreshCredential();
  }

  // ------------------------------------------------------------- event queue

  /**
   * The only way an event reaches the core.
   *
   * Queued rather than dispatched, so that an event raised from inside a host
   * callback cannot re-enter `handle` while the outer decision loop is still
   * running. `host.ts` asks for exactly this.
   */
  #enqueue(event: SluiceEvent): void {
    if (this.#phase === "stopped") return;
    this.#queue.push(event);
    this.#pump();
  }

  #pump(): void {
    if (this.#pumping) return;
    this.#pumping = true;
    try {
      for (;;) {
        const event = this.#queue.shift();
        if (event === undefined) break;
        const decisions = this.#core.handle(event);
        // OBLIGATION FOUR. Before the decisions are applied, because one of
        // them may be `exit`, and `exit` does not return.
        this.#persistFloor();
        applyDecisions(this.#host, decisions);
      }
    } finally {
      this.#pumping = false;
    }
  }

  /**
   * Writes the floor whenever the core moved it.
   *
   * A FAILURE HERE IS LOGGED AND SWALLOWED. This runs on the path to an exit
   * that a revocation ordered. Letting a full disk throw would unwind the pump
   * and leave a revoked process running, which trades a replay window for the
   * failure the whole product exists to prevent.
   */
  #persistFloor(): void {
    const floor = this.#core.epochFloor;
    if (floor === this.#persistedFloor) return;
    this.#persistedFloor = floor;
    try {
      this.#floorStore.save(floor);
    } catch (error) {
      this.#logger.log(
        "error",
        "epoch-floor-write-failed",
        "the revocation epoch floor could not be written to disk, so a restart may accept a " +
          `replay of this notice. The shutdown itself is unaffected. Cause class: ${
            describe(error)
          }.`,
      );
    }
  }

  // ---------------------------------------------------------- the credential

  /**
   * Handshakes, then subscribes, then schedules the next handshake.
   *
   * THIS TIMER IS INDEPENDENT OF THE SUBSCRIPTION ON PURPOSE. A refresh driven
   * by the subscription noticing its own expiry is a refresh that never happens
   * on an idle environment, because a query that is not re-run does not notice
   * anything. The credential expires on a clock, so it is renewed on a clock.
   */
  async #refreshCredential(): Promise<void> {
    if (this.#phase !== "running") return;
    if (this.#handshakeInFlight) return;
    this.#handshakeInFlight = true;
    this.#inFlight += 1;
    try {
      const credential = await this.#handshaker.handshake();
      if (this.#phase !== "running") return;
      this.#handshakeFailures = 0;
      this.#subscribe(credential);
      this.#scheduleRefresh(credential);
    } catch (error) {
      if (this.#phase !== "running") return;
      this.#handshakeFailures += 1;
      // NOT an exit, at any failure count. A handshake endpoint that is down is
      // an outage, and section 4.3 is unambiguous: an outage may never kill a
      // customer's fleet. The process keeps its last known good secrets and
      // keeps trying. Before the first bundle, the core's own boot deadline
      // decides whether there is anything to run with.
      this.#logger.log(
        "warn",
        "handshake-failed",
        `could not renew the Sluice bundle credential: ${sanitiseForLog(message(error))}`,
      );
      this.#logger.metric("sluice.handshake.failed", 1);
      this.#armRefresh(this.#backoffMs());
    } finally {
      this.#handshakeInFlight = false;
      this.#inFlight -= 1;
    }
  }

  #backoffMs(): number {
    const exponent = Math.min(this.#handshakeFailures - 1, 10);
    const ceiling = Math.min(BASE_BACKOFF_MS * 2 ** exponent, MAX_BACKOFF_MS);
    // Full jitter. A fleet whose credentials were all issued in one deploy
    // expires them all at the same moment, and a deterministic backoff turns
    // that into a synchronised stampede against the one unauthenticated
    // endpoint in the product.
    return Math.max(MIN_REFRESH_MS, Math.floor(ceiling * (0.5 + 0.5 * this.#jitter())));
  }

  /**
   * Half the remaining lifetime, floored.
   *
   * Half rather than "shortly before expiry", so a failed renewal still leaves
   * room for several more attempts inside one credential's life. A margin
   * measured from the end gives one attempt and then an un-revokable process.
   */
  #scheduleRefresh(credential: BundleCredential): void {
    const remaining = credential.expiresAt - this.#timers.now();
    this.#armRefresh(Math.max(MIN_REFRESH_MS, Math.floor(remaining / 2)));
  }

  #armRefresh(delayMs: number): void {
    if (this.#refreshTimer !== null) this.#timers.clear(this.#refreshTimer);
    this.#refreshTimer = this.#timers.setTimeout(() => {
      this.#refreshTimer = null;
      void this.#refreshCredential();
    }, delayMs);
  }

  /**
   * Opens a new subscription and retires the previous one.
   *
   * The old subscription is kept until the new one has produced its first
   * event, so a rotation leaves no window in which a revocation could arrive
   * with nobody listening. At most two are ever live: a third rotation retires
   * the pending one immediately rather than accumulating sockets.
   */
  #subscribe(credential: BundleCredential): void {
    this.#generation += 1;
    const generation = this.#generation;

    this.#retireOld();
    this.#retiringUnsubscribe = this.#currentUnsubscribe;

    this.#currentUnsubscribe = this.#source.subscribe(credential.token, {
      onResult: (raw) => this.#onBundle(generation, raw),
      onError: (errorMessage) => this.#onSubscriptionError(generation, errorMessage),
    });
  }

  #retireOld(): void {
    const retiring = this.#retiringUnsubscribe;
    this.#retiringUnsubscribe = null;
    if (retiring === null) return;
    try {
      retiring();
    } catch {
      // A transport that throws on unsubscribe has already given up on that
      // socket. There is nothing to do and nothing worth a log line.
    }
  }

  // --------------------------------------------------------- transport input

  #onBundle(generation: number, raw: RawBundle): void {
    if (this.#phase !== "running") return;
    if (generation === this.#generation) this.#retireOld();
    this.#markConnected();

    // THE NOTICE FIRST, AND WITHOUT TOUCHING A KEY. A revoked token is served
    // its notice and no secrets, and a token whose grant vanished is served its
    // notice and no key. Reading the notice out of the decryption path is what
    // stops either of those from becoming a workload that can never be told.
    const revocation = readRevocation(raw);
    if (revocation !== undefined) {
      this.#enqueue({
        type: "revocation",
        notice: revocation.notice,
        signature: revocation.signature,
        now: this.#timers.now(),
      });
      // A revoked bundle carries no secrets by design. Feeding the empty set to
      // the core would read as "every secret was removed", which is a different
      // and untrue statement.
      if (raw.secrets === undefined || raw.secrets.length === 0) return;
    }

    const sequence = this.#bundleSequence + 1;
    this.#bundleSequence = sequence;
    void this.#decryptAndApply(sequence, raw);
  }

  async #decryptAndApply(sequence: number, raw: RawBundle): Promise<void> {
    this.#inFlight += 1;
    try {
      await this.#decrypt(sequence, raw);
    } finally {
      this.#inFlight -= 1;
    }
  }

  async #decrypt(sequence: number, raw: RawBundle): Promise<void> {
    let bundle: SecretBundle;
    try {
      bundle = await decryptSecrets(this.#identity, raw);
    } catch (error) {
      // NEVER A SHUTDOWN AND NEVER A TRANSPORT ERROR. A bundle that will not
      // open is a bundle this process does not install; the last known good set
      // stays, and at boot the core's own deadline decides. Calling this
      // `disconnected` would be a lie about the socket, and the core's offline
      // accounting would be wrong for as long as it lasted.
      this.#logger.log(
        "error",
        "bundle-unreadable",
        error instanceof BundleDecryptError
          ? `${error.code}: ${sanitiseForLog(error.message)}`
          : `the Sluice bundle could not be read: ${sanitiseForLog(message(error))}`,
      );
      this.#logger.metric("sluice.bundle.unreadable", 1);
      return;
    }
    if (this.#phase !== "running") return;
    // Decryption is asynchronous, so two bundles in flight can finish out of
    // order. Installing the older one would silently roll a rotation back.
    if (sequence < this.#appliedSequence) return;
    this.#appliedSequence = sequence;
    this.#enqueue({ type: "bundle", bundle, now: this.#timers.now() });
  }

  #onSubscriptionError(generation: number, errorMessage: string): void {
    if (this.#phase !== "running") return;
    // A REFUSED QUERY IS NOT A REVOCATION. It is reported as `disconnected`,
    // which the core cannot turn into a shutdown under any sequence.
    this.#enqueue({
      type: "disconnected",
      cause: errorMessage,
      now: this.#timers.now(),
    });
    this.#connected = false;
    // The likeliest cause by far is an expired bundle token, and the whole
    // reason this shell owns a refresh timer is that nobody else will notice.
    // Renewing on the error as well as on the clock is what closes the gap
    // between "the credential died early" and "the next scheduled renewal".
    if (generation === this.#generation) void this.#refreshCredential();
  }

  #pollConnection(): void {
    if (this.#phase !== "running") return;
    let connected: boolean;
    try {
      connected = this.#source.isConnected();
    } catch {
      connected = false;
    }
    if (connected === this.#connected) return;
    if (connected) {
      this.#markConnected();
      return;
    }
    this.#connected = false;
    // Only ever reported once the transport has been up. Announcing a
    // disconnection before the first connection would be a false statement and
    // would start the core's offline clock from a state it was never in.
    if (this.#everConnected) {
      this.#enqueue({ type: "disconnected", now: this.#timers.now() });
    }
  }

  #markConnected(): void {
    if (this.#connected) return;
    this.#connected = true;
    const first = !this.#everConnected;
    this.#everConnected = true;
    if (!first) this.#enqueue({ type: "reconnected", now: this.#timers.now() });
  }

  // ---------------------------------------------------------------- the drain

  /**
   * OBLIGATIONS TWO AND THREE, IN ORDER, IN ONE PLACE.
   *
   * The deadline is armed on the first statement. The socket is closed on the
   * second: once the core has ordered a shutdown nothing on the wire can change
   * it, and a subscription still delivering during a drain is traffic an
   * operator will read as the process still being healthy. The customer handler
   * is called last, with one string and nothing else.
   */
  #beginDrain(reason: string, drainMs: number): void {
    if (this.#drainTimer !== null) return;
    // Before anything else, including the deadline: this is what stops an
    // in-flight handshake from opening a fresh subscription while the process
    // is dying. See the note on `Phase`.
    if (this.#phase === "running") this.#phase = "draining";

    // 1. THE DEADLINE, FIRST, AND INDEPENDENT OF EVERYTHING BELOW IT.
    this.#drainTimer = this.#timers.setTimeout(() => {
      this.#enqueue({ type: "tick", now: this.#timers.now() });
    }, drainMs);

    // 2. SILENCE. No more renewals, no more subscriptions, no more bytes.
    if (this.#refreshTimer !== null) {
      this.#timers.clear(this.#refreshTimer);
      this.#refreshTimer = null;
    }
    this.#closeTransport();

    // 3. THE CUSTOMER'S HANDLER. ONE ARGUMENT. NO `this`. NOTHING CANCELLABLE.
    const handler = this.#onRevoke;
    if (handler === undefined) {
      this.#enqueue({ type: "drain-complete", now: this.#timers.now() });
      return;
    }

    let result: unknown;
    try {
      // `Reflect.apply` rather than `handler.call(undefined, reason)`. A
      // handler is a customer object, and an own `call` or `apply` property on
      // it would otherwise be what ran. `Reflect.apply` reaches the underlying
      // callable directly, with `this` explicitly nothing.
      result = Reflect.apply(handler, undefined, [reason]);
    } catch (error) {
      this.#enqueue({
        type: "drain-failed",
        error: message(error),
        now: this.#timers.now(),
      });
      return;
    }
    try {
      // `Promise.resolve` on a hostile thenable can hang, and that is the whole
      // point: the deadline above is already armed and does not care. What it
      // must not do is throw synchronously out of here, which a `then` getter
      // can, so the subscription itself is wrapped too.
      void Promise.resolve(result).then(
        () => this.#enqueue({ type: "drain-complete", now: this.#timers.now() }),
        (error: unknown) =>
          this.#enqueue({
            type: "drain-failed",
            error: message(error),
            now: this.#timers.now(),
          }),
      );
    } catch (error) {
      this.#enqueue({
        type: "drain-failed",
        error: message(error),
        now: this.#timers.now(),
      });
    }
  }

  // --------------------------------------------------------------- the child

  #onSecrets(bundle: SecretBundle, changed: readonly string[], removed: readonly string[]): void {
    if (this.#spawned) {
      // A PROCESS'S ENVIRONMENT CANNOT BE CHANGED FROM OUTSIDE IT. This is a
      // fact about operating systems, not a limitation of this implementation,
      // and pretending otherwise would be worse than saying so: the honest
      // answer is a log line naming the KEYS that moved, so an operator knows a
      // restart is needed. Restarting the child here would be this shell
      // inventing a termination, which is the one thing it may never do.
      this.#logger.log(
        "warn",
        "secrets-changed-after-start",
        `the secrets for this environment changed after the child started, so the running ` +
          `process still has the old values. Restart it to pick them up. Changed: ` +
          `${nameList(changed)}. Removed: ${nameList(removed)}.`,
      );
      this.#logger.metric("sluice.secrets.changed_after_start", changed.length + removed.length);
      return;
    }
    this.#spawned = true;
    this.#logger.log(
      "info",
      "secrets-installed",
      `injecting ${Object.keys(bundle.secrets).length} secret(s) into the child environment: ` +
        `${nameList(Object.keys(bundle.secrets).sort())}`,
    );
    this.#child.spawn(this.#childEnv(bundle));
  }

  /**
   * The environment the child receives.
   *
   * THE SERVICE TOKEN IS REMOVED. It reaches this process through the
   * environment, and an inherited environment is the default, so without this
   * every child of `sluice run` would hold a credential that can fetch every
   * secret in the environment and is valid until somebody revokes it. Any
   * dependency that dumps `process.env` on a crash would post it to a bug
   * tracker. The match is case-insensitive because Windows environment lookups
   * are, so `Sluice_Token` names the same variable there and a case-sensitive
   * delete would leave it in place on exactly the platform where it still
   * resolves.
   */
  #childEnv(bundle: SecretBundle): Record<string, string> {
    const env: Record<string, string> = {};
    for (const [key, value] of Object.entries(this.#baseEnv)) {
      if (value === undefined) continue;
      if (key.toUpperCase() === "SLUICE_TOKEN") continue;
      env[key] = value;
    }
    for (const [key, value] of Object.entries(bundle.secrets)) {
      env[key] = value;
    }
    return env;
  }

  /**
   * THE ONLY PATH FROM A SLUICE DECISION TO A DEAD CHILD.
   *
   * Reachable from `host.exit` and from nowhere else, and `host.exit` is
   * reachable only from an `exit` or a `fail-to-start` decision that
   * `SluiceCore` returned. There is no other call to `child.signal` in this
   * file except the operator signal relay in `run.ts`, which forwards a signal
   * somebody else sent and originates nothing.
   *
   * SIGTERM, THEN SIGKILL AFTER THE GRACE PERIOD, THEN EXIT REGARDLESS. A child
   * that ignores SIGTERM does not get to keep the secrets: the grace timer
   * fires, SIGKILL goes out, and this process exits immediately afterwards
   * rather than waiting to observe the death. SIGKILL cannot be caught, and a
   * child wedged in an uninterruptible state is a kernel problem that no amount
   * of waiting here improves, while waiting would leave the supervisor alive
   * and looking healthy.
   */
  #stopChild(code: number): void {
    if (this.#phase === "stopping" || this.#phase === "stopped") return;
    this.#phase = "stopping";
    this.#pendingExitCode = code;
    this.#clearTimer("tick");
    this.#clearTimer("drain");
    this.#clearTimer("refresh");
    this.#closeTransport();

    if (!this.#child.started || !this.#child.running) {
      this.#finish(code);
      return;
    }

    this.#child.signal("SIGTERM");
    if (!this.#child.running) {
      this.#finish(code);
      return;
    }
    this.#logger.log(
      "warn",
      "child-ignoring-sigterm",
      `the child has not exited on SIGTERM. Sending SIGKILL in ${this.#killGraceMs}ms.`,
    );
    this.#killTimer = this.#timers.setTimeout(() => {
      this.#killTimer = null;
      this.#child.signal("SIGKILL");
      this.#finish(code);
    }, this.#killGraceMs);
  }

  #onChildExit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.#phase === "stopping") {
      if (this.#killTimer !== null) {
        this.#timers.clear(this.#killTimer);
        this.#killTimer = null;
      }
      // The exit code is the one the core decided, not the child's. This
      // process was revoked; reporting the child's own code would hide that.
      this.#finish(this.#pendingExitCode);
      return;
    }
    if (this.#phase === "stopped") return;

    // THE CHILD ENDED ON ITS OWN. Nothing here killed anything: the supervised
    // process finished, so the supervisor finishes with it and reports what it
    // reported. A signal death has no exit code, and 128 plus the signal number
    // is the shell convention; the number is not knowable from a name here, so
    // a signalled child reports 1 and says which signal in the log.
    this.#logger.log(
      code === 0 ? "info" : "warn",
      "child-exited",
      signal === null
        ? `the child exited with code ${String(code)}`
        : `the child was terminated by ${sanitiseForLog(String(signal))}`,
    );
    this.#phase = "stopping";
    this.#clearTimer("tick");
    this.#clearTimer("drain");
    this.#clearTimer("refresh");
    this.#closeTransport();
    this.#finish(code === null ? 1 : code);
  }

  /** The code the core decided, held across the SIGTERM to SIGKILL window. */
  #pendingExitCode = 1;

  #finish(code: number): void {
    if (this.#phase === "stopped") return;
    this.#phase = "stopped";
    this.#queue = [];
    this.#exit(code);
  }

  #closeTransport(): void {
    this.#retireOld();
    const current = this.#currentUnsubscribe;
    this.#currentUnsubscribe = null;
    try {
      current?.();
    } catch {
      // Already gone. Nothing to report and nothing to do.
    }
    try {
      this.#source.close();
    } catch {
      // Same.
    }
  }

  #clearTimer(which: "tick" | "drain" | "refresh"): void {
    const handle =
      which === "tick" ? this.#tickTimer : which === "drain" ? this.#drainTimer : this.#refreshTimer;
    if (handle === null) return;
    this.#timers.clear(handle);
    if (which === "tick") this.#tickTimer = null;
    else if (which === "drain") this.#drainTimer = null;
    else this.#refreshTimer = null;
  }
}

/** Key names only, never values, and bounded so one bundle cannot fill a screen. */
function nameList(names: readonly string[]): string {
  if (names.length === 0) return "none";
  const shown = names.slice(0, 20).map((name) => sanitiseForLog(name));
  return names.length > 20 ? `${shown.join(", ")} and ${names.length - 20} more` : shown.join(", ");
}

/**
 * A message from an unknown throw, without running anything hostile.
 *
 * `String(error)` calls `toString`, which on an attacker-shaped object is
 * arbitrary code on the shutdown path. Only a genuine string `message` is read,
 * and everything else becomes the class name.
 */
function message(error: unknown): string {
  const raw = (error as { message?: unknown } | null)?.message;
  return typeof raw === "string" ? raw : describe(error);
}

function describe(error: unknown): string {
  const name = (error as { name?: unknown } | null)?.name;
  return typeof name === "string" && /^[A-Za-z]{1,40}$/.test(name) ? name : "unknown";
}
