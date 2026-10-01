import { ed25519 } from "@noble/curves/ed25519";
import {
  mintToken,
  pdkAssociatedData,
  randomBytes,
  seal,
  secretAssociatedData,
  signRevocation,
  toHex,
  tokenIdHash,
  utf8,
  type RevocationNotice,
} from "@sluice/crypto";
import type { LogLevel } from "@sluice/sdk";
import type { RawBundle, RawSecretRow } from "../src/bundle";
import { TokenIdentity } from "../src/config";
import type {
  BundleSource,
  ChildProcessSupervisor,
  Logger,
  SubscriptionHandlers,
  TimerHandle,
  Timers,
} from "../src/ports";
import type { BundleCredential, Handshaker } from "../src/handshake";
import type { EpochFloorStore, FloorLoad } from "../src/floor";
import { NO_PERSISTED_FLOOR, type EpochFloor } from "@sluice/sdk";

export const T0 = 1_764_000_000_000;

interface Scheduled {
  readonly id: number;
  due: number;
  readonly callback: () => void;
  readonly interval: number | undefined;
}

/**
 * A virtual clock.
 *
 * `created` counts every timer ever armed, which is what the "no shell-created
 * timer reachable by customer code" test measures against.
 */
export class FakeTimers implements Timers {
  #now = T0;
  #nextId = 1;
  readonly #scheduled = new Map<number, Scheduled>();
  created = 0;

  now(): number {
    return this.#now;
  }

  setTimeout(callback: () => void, ms: number): TimerHandle {
    return this.#arm(callback, ms, undefined);
  }

  setInterval(callback: () => void, ms: number): TimerHandle {
    return this.#arm(callback, ms, ms);
  }

  clear(handle: TimerHandle): void {
    if (typeof handle === "number") this.#scheduled.delete(handle);
  }

  get pending(): number {
    return this.#scheduled.size;
  }

  /** Every armed interval, so a test can prove the tick never stopped. */
  get intervals(): number {
    let count = 0;
    for (const entry of this.#scheduled.values()) if (entry.interval !== undefined) count += 1;
    return count;
  }

  advance(ms: number): void {
    const target = this.#now + ms;
    for (;;) {
      let next: Scheduled | undefined;
      for (const entry of this.#scheduled.values()) {
        if (next === undefined || entry.due < next.due || (entry.due === next.due && entry.id < next.id)) {
          next = entry;
        }
      }
      if (next === undefined || next.due > target) break;
      this.#now = next.due;
      if (next.interval === undefined) this.#scheduled.delete(next.id);
      else next.due = next.due + next.interval;
      next.callback();
    }
    this.#now = target;
  }

  #arm(callback: () => void, ms: number, interval: number | undefined): TimerHandle {
    const id = this.#nextId;
    this.#nextId += 1;
    this.created += 1;
    this.#scheduled.set(id, { id, due: this.#now + ms, callback, interval });
    return id;
  }
}

export interface FakeSubscription {
  readonly token: string;
  readonly handlers: SubscriptionHandlers;
  active: boolean;
}

export class FakeSource implements BundleSource {
  readonly subscriptions: FakeSubscription[] = [];
  connected = true;
  closed = false;
  /** Every call that would put a byte on a socket. */
  traffic = 0;

  subscribe(bundleToken: string, handlers: SubscriptionHandlers): () => void {
    this.traffic += 1;
    const subscription: FakeSubscription = { token: bundleToken, handlers, active: true };
    this.subscriptions.push(subscription);
    return () => {
      subscription.active = false;
    };
  }

  isConnected(): boolean {
    return this.connected && !this.closed;
  }

  close(): void {
    this.closed = true;
    for (const subscription of this.subscriptions) subscription.active = false;
  }

  get live(): FakeSubscription[] {
    return this.subscriptions.filter((s) => s.active);
  }

  get newest(): FakeSubscription {
    const live = this.live;
    const last = live[live.length - 1];
    if (last === undefined) throw new Error("no live subscription");
    return last;
  }

  emit(raw: RawBundle): void {
    this.newest.handlers.onResult(raw);
  }

  emitError(message: string): void {
    this.newest.handlers.onError(message);
  }
}

export class FakeHandshaker implements Handshaker {
  calls = 0;
  lifetimeMs = 300_000;
  failures = 0;
  #now: () => number;
  #issued = 0;

  constructor(now: () => number) {
    this.#now = now;
  }

  async handshake(): Promise<BundleCredential> {
    this.calls += 1;
    if (this.failures > 0) {
      this.failures -= 1;
      throw new Error("handshake unavailable");
    }
    this.#issued += 1;
    return { token: `jwt-${this.#issued}`, expiresAt: this.#now() + this.lifetimeMs };
  }
}

export class FakeChild implements ChildProcessSupervisor {
  spawnedEnv: Record<string, string> | null = null;
  readonly signals: NodeJS.Signals[] = [];
  started = false;
  running = false;
  /** When true the child ignores SIGTERM, the way a wedged process does. */
  ignoreSigterm = false;
  #onExit: ((code: number | null, signal: NodeJS.Signals | null) => void) | null = null;

  spawn(env: Record<string, string>): void {
    if (this.started) throw new Error("spawned twice");
    this.started = true;
    this.running = true;
    this.spawnedEnv = env;
  }

  signal(signal: NodeJS.Signals): void {
    this.signals.push(signal);
    if (!this.running) return;
    if (signal === "SIGKILL" || (signal === "SIGTERM" && !this.ignoreSigterm)) {
      this.exitWith(null, signal);
    }
  }

  onExit(callback: (code: number | null, signal: NodeJS.Signals | null) => void): void {
    this.#onExit = callback;
  }

  exitWith(code: number | null, signal: NodeJS.Signals | null = null): void {
    if (!this.running) return;
    this.running = false;
    this.#onExit?.(code, signal);
  }
}

export interface LogLine {
  readonly level: LogLevel;
  readonly code: string;
  readonly message: string;
}

export class FakeLogger implements Logger {
  readonly lines: LogLine[] = [];
  readonly metrics: { name: string; value: number }[] = [];

  log(level: LogLevel, code: string, message: string): void {
    this.lines.push({ level, code, message });
  }

  metric(name: string, value: number): void {
    this.metrics.push({ name, value });
  }

  get text(): string {
    return this.lines.map((line) => `${line.level} ${line.code} ${line.message}`).join("\n");
  }

  has(code: string): boolean {
    return this.lines.some((line) => line.code === code);
  }
}

export class FakeFloorStore implements EpochFloorStore {
  saved: EpochFloor[] = [];
  stored: EpochFloor = NO_PERSISTED_FLOOR;
  corrupt = false;
  throwOnSave = false;

  load(): FloorLoad {
    if (this.corrupt) return { ok: false, message: "the stored floor is unusable" };
    return { ok: true, floor: this.stored };
  }

  save(floor: EpochFloor): void {
    this.saved.push(floor);
    if (this.throwOnSave) throw new Error("disk full");
    if (floor !== NO_PERSISTED_FLOOR) this.stored = floor;
  }
}

export interface Org {
  readonly privateKey: Uint8Array;
  readonly publicKeyHex: string;
}

export function orgKeyPair(): Org {
  const privateKey = randomBytes(32);
  return { privateKey, publicKeyHex: toHex(ed25519.getPublicKey(privateKey)) };
}

export const ENVIRONMENT_UID = "env_000102030405060708090a0b0c0d0e0f";

export interface Fixture {
  readonly identity: TokenIdentity;
  readonly rawToken: string;
  readonly pdk: Uint8Array;
  bundleWith(secrets: Record<string, string>, epoch?: number): Promise<RawBundle>;
}

export async function tokenFixture(): Promise<Fixture> {
  const minted = mintToken({ environment: "prod" });
  const identity = TokenIdentity.fromToken(minted.token);
  const pdk = randomBytes(32);
  const wrapped = await seal(
    identity.unwrapKey,
    pdk,
    pdkAssociatedData({
      environmentUid: ENVIRONMENT_UID,
      pdkVersion: 1,
      granteeType: "token",
      granteeId: tokenIdHash({ tokenId: minted.tokenId }),
    }),
  );

  return {
    identity,
    rawToken: minted.token,
    pdk,
    async bundleWith(secrets: Record<string, string>, epoch = 1): Promise<RawBundle> {
      const rows: RawSecretRow[] = [];
      let index = 0;
      for (const [name, value] of Object.entries(secrets)) {
        // Sealed exactly as a client seals them: the name and the value each
        // under their own field, both bound to the secret's permanent id and
        // its version.
        const secretUid = "sec_" + index.toString(16).padStart(32, "0");
        const bind = (field: "name" | "value") =>
          secretAssociatedData({ environmentUid: ENVIRONMENT_UID, secretUid, version: 1, field });
        const sealedName = await seal(pdk, utf8.encode(name), bind("name"));
        const sealedValue = await seal(pdk, utf8.encode(value), bind("value"));
        rows.push({
          secretUid,
          version: 1,
          pdkVersion: 1,
          nameCiphertext: toHex(sealedName.ciphertext),
          nameNonce: toHex(sealedName.nonce),
          valueCiphertext: toHex(sealedValue.ciphertext),
          valueNonce: toHex(sealedValue.nonce),
        });
        index += 1;
      }
      return {
        environmentUid: ENVIRONMENT_UID,
        epoch,
        pdkVersion: 1,
        wrappedPDK: toHex(wrapped.ciphertext),
        pdkNonce: toHex(wrapped.nonce),
        secrets: rows,
      };
    },
  };
}

/** A genuine, signed notice for `identity`, in the shape the bundle carries. */
export function signedNotice(
  org: Org,
  identity: TokenIdentity,
  overrides: Partial<RevocationNotice> = {},
): RawBundle["revocationNotice"] {
  const notice: RevocationNotice = {
    tokenId: identity.tokenIdHex,
    epoch: 1,
    revokedAt: T0,
    reason: "leaked in a public repo",
    ...overrides,
  };
  return { ...notice, signature: toHex(signRevocation(org.privateKey, notice)) };
}

/**
 * How long {@link flush} waits for a busy shell before failing the test.
 *
 * Measured in WALL TIME, not in event loop turns. See {@link flush} for why.
 *
 * Deliberately BELOW vitest's default 5 s test timeout. At 5 s the two would
 * race, and a shell that is genuinely stuck would usually surface as vitest's
 * anonymous "Test timed out" rather than as this file's named error, because
 * `booted()` and earlier awaits have already spent part of the test's budget.
 * Same failure either way; only the diagnosis is lost.
 */
export const FLUSH_BOUND_MS = 3_000;

/**
 * Lets every pending promise settle, including the real ones.
 *
 * `decryptSecrets` runs WebCrypto, which in Node resolves off the libuv thread
 * pool rather than on the microtask queue, so a handful of `await`s is not
 * enough: one bundle is three sequential AEAD opens and each needs its own trip
 * through the event loop.
 *
 * WHY THE BOUND IS TIME AND NOT TURNS. An earlier version gave up after 500
 * `setImmediate` turns and then RETURNED, silently, with the shell still busy.
 * Turns are cheap and fast; thread pool work is neither when the machine is
 * loaded. Under CPU contention (a parallel test run, a busy CI box) one AES-GCM
 * open can outlast 500 empty turns of the event loop, flush returned early,
 * and the next assertion saw the state from BEFORE the bundle. The failure
 * looked like a shell bug, appeared once in a few hundred runs, and would not
 * reproduce, which is the worst way to lose an hour.
 *
 * So with a predicate this waits until `busy()` is false and has stayed false
 * for five further turns, however many turns that takes, bounded only by
 * `boundMs` of wall time. If the bound is hit while the shell is STILL busy it
 * THROWS, naming the cause, rather than letting a test continue against a
 * half-applied state. A slow machine now makes a test slower, never wrong;
 * a genuinely stuck shell makes it fail loudly, here, with a message.
 *
 * WITHOUT A PREDICATE it behaves as it always has: a small fixed number of
 * turns, then return. That form only ever proves ABSENCE (that nothing
 * further happened), and a loaded machine can only make "nothing happened"
 * more likely, never less, so load cannot turn such a test red. It has nothing
 * to wait for, so it has nothing to time out on.
 */
export async function flush(
  busy?: () => boolean,
  boundMs: number = FLUSH_BOUND_MS,
): Promise<void> {
  const turn = (): Promise<void> => new Promise<void>((resolve) => setImmediate(resolve));

  if (busy === undefined) {
    for (let i = 0; i <= 20; i += 1) await turn();
    return;
  }

  const deadline = Date.now() + boundMs;
  let quiet = 0;
  for (;;) {
    await turn();
    if (busy()) {
      quiet = 0;
      if (Date.now() >= deadline) {
        throw new Error(`flush: shell still busy after ${boundMs} ms`);
      }
      continue;
    }
    // A few extra turns after the last operation settled, so the events it
    // enqueued have been pumped and anything it started has a chance to appear.
    // Not bounded by the deadline: the shell is idle, and five turns of an idle
    // event loop always complete.
    quiet += 1;
    if (quiet >= 5) return;
  }
}
