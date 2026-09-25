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

export const ENVIRONMENT_ID = "k17abcdefghijklmnopqrstuvwxyz01";

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
      granteeType: "token",
      granteeId: tokenIdHash({ tokenId: minted.tokenId }),
    }),
  );
  const aad = secretAssociatedData({ environmentId: ENVIRONMENT_ID });

  return {
    identity,
    rawToken: minted.token,
    pdk,
    async bundleWith(secrets: Record<string, string>, epoch = 1): Promise<RawBundle> {
      const rows: RawSecretRow[] = [];
      let index = 0;
      for (const [name, value] of Object.entries(secrets)) {
        const sealedName = await seal(pdk, utf8.encode(name), aad);
        const sealedValue = await seal(pdk, utf8.encode(value), aad);
        rows.push({
          secretId: `sec${index}`,
          lineageId: `lin${index}`,
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
        environmentId: ENVIRONMENT_ID,
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
 * Lets every pending promise settle, including the real ones.
 *
 * `decryptSecrets` runs WebCrypto, which in Node resolves off the thread pool
 * rather than on the microtask queue, so a handful of `await`s is not enough:
 * one bundle is three sequential AEAD opens and each needs its own trip through
 * the event loop. This is generous on purpose. A flush that is too short turns
 * a deterministic virtual clock back into a race, and the failure looks like a
 * shell bug rather than a test bug, which is the worst way to lose an hour.
 */
export async function flush(busy?: () => boolean, times = 500): Promise<void> {
  let quiet = 0;
  for (let i = 0; i < times; i += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (busy === undefined) {
      if (i >= 20) return;
      continue;
    }
    if (busy()) {
      quiet = 0;
      continue;
    }
    // A few extra turns after the last operation settled, so the events it
    // enqueued have been pumped and anything it started has a chance to appear.
    quiet += 1;
    if (quiet >= 5) return;
  }
}
