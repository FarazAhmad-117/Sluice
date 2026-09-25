import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import { MAX_CLOCK_STEP_MS, NO_PERSISTED_FLOOR, SluiceCore } from "@sluice/sdk";
import { toHex } from "@sluice/crypto";
import { Shell } from "../src/shell";
import {
  FakeChild,
  FakeFloorStore,
  FakeHandshaker,
  FakeLogger,
  FakeSource,
  FakeTimers,
  flush,
  orgKeyPair,
  signedNotice,
  T0,
  tokenFixture,
  type Fixture,
  type Org,
} from "./fakes";

interface Harness {
  readonly shell: Shell;
  readonly timers: FakeTimers;
  readonly source: FakeSource;
  readonly handshaker: FakeHandshaker;
  readonly child: FakeChild;
  readonly logger: FakeLogger;
  readonly floor: FakeFloorStore;
  readonly exits: number[];
  readonly onRevokeCalls: unknown[][];
  tick(ms: number): Promise<void>;
}

interface HarnessOptions {
  readonly onRevoke?: (...args: unknown[]) => unknown;
  readonly drainMs?: number;
  readonly killGraceMs?: number;
  readonly bootTimeoutMs?: number;
  readonly baseEnv?: Record<string, string | undefined>;
}

/**
 * Wraps a handler so the call is recorded without changing its receiver.
 *
 * `function` rather than an arrow, so that whatever `this` the shell supplies
 * is passed through verbatim and the test can assert it is `undefined`.
 */
function recorder(
  inner: (...args: unknown[]) => unknown,
  calls: unknown[][],
): (reason: string) => unknown {
  return function recorded(this: unknown, ...args: unknown[]): unknown {
    calls.push(args);
    return inner.apply(this, args);
  } as (reason: string) => unknown;
}

function harness(fixture: Fixture, org: Org, options: HarnessOptions = {}): Harness {
  const timers = new FakeTimers();
  const source = new FakeSource();
  const handshaker = new FakeHandshaker(() => timers.now());
  const child = new FakeChild();
  const logger = new FakeLogger();
  const floor = new FakeFloorStore();
  const exits: number[] = [];
  const onRevokeCalls: unknown[][] = [];

  const core = new SluiceCore({
    orgRevocationPublicKey: org.publicKeyHex,
    tokenId: fixture.identity.tokenIdHex,
    initialEpochFloor: NO_PERSISTED_FLOOR,
    drainMs: options.drainMs ?? 5_000,
    bootTimeoutMs: options.bootTimeoutMs ?? 30_000,
  });

  const shell = new Shell({
    core,
    identity: fixture.identity,
    timers,
    logger,
    handshaker,
    source,
    child,
    floorStore: floor,
    exit: (code: number) => {
      exits.push(code);
    },
    killGraceMs: options.killGraceMs ?? 5_000,
    bootTimeoutMs: options.bootTimeoutMs ?? 30_000,
    baseEnv: options.baseEnv ?? { PATH: "/usr/bin", SLUICE_TOKEN: fixture.rawToken },
    jitter: () => 0,
    ...(options.onRevoke === undefined
      ? {}
      : {
          // Read out of `options` FIRST. Calling `options.onRevoke(...)` would
          // make `this` the options object and quietly defeat the assertion
          // that the shell hands the handler no receiver at all.
          onRevoke: recorder(options.onRevoke, onRevokeCalls),
        }),
  });

  return {
    shell,
    timers,
    source,
    handshaker,
    child,
    logger,
    floor,
    exits,
    onRevokeCalls,
    /**
     * Advances the virtual clock in steps, letting real promises settle
     * between them.
     *
     * One big jump would be a lie about elapsed time. A timer callback that
     * starts an asynchronous operation, such as a handshake, cannot finish
     * inside a synchronous `advance`, so the follow-up timer it would arm never
     * exists and a whole hour produces exactly one renewal. Stepping models
     * what actually happens on a wall clock.
     */
    async tick(ms: number) {
      const step = 2_500;
      let remaining = ms;
      while (remaining > 0) {
        const slice = Math.min(step, remaining);
        timers.advance(slice);
        remaining -= slice;
        await flush(() => shell.busy);
      }
    },
  };
}

let fixture: Fixture;
let org: Org;

beforeEach(async () => {
  fixture = await tokenFixture();
  org = orgKeyPair();
});

async function booted(options: HarnessOptions = {}): Promise<Harness> {
  const h = harness(fixture, org, options);
  h.shell.start();
  await flush(() => h.shell.busy);
  h.source.emit(await fixture.bundleWith({ DATABASE_URL: "postgres://real" }));
  await flush(() => h.shell.busy);
  return h;
}

describe("Shell: the happy path", () => {
  it("handshakes, subscribes, decrypts and spawns the child with the secrets", async () => {
    const h = await booted();
    expect(h.handshaker.calls).toBe(1);
    expect(h.source.subscriptions).toHaveLength(1);
    expect(h.child.started).toBe(true);
    expect(h.child.spawnedEnv?.DATABASE_URL).toBe("postgres://real");
    expect(h.exits).toEqual([]);
  });

  it("keeps the parent environment and strips the service token from the child", async () => {
    const h = await booted();
    expect(h.child.spawnedEnv?.PATH).toBe("/usr/bin");
    expect(h.child.spawnedEnv?.SLUICE_TOKEN).toBeUndefined();
    expect(JSON.stringify(h.child.spawnedEnv)).not.toContain("slc_");
  });

  it("spawns the child exactly once, however many bundles arrive", async () => {
    const h = await booted();
    h.source.emit(await fixture.bundleWith({ DATABASE_URL: "postgres://rotated" }, 2));
    await flush(() => h.shell.busy);
    expect(h.child.spawnedEnv?.DATABASE_URL).toBe("postgres://real");
    expect(h.logger.has("secrets-changed-after-start")).toBe(true);
  });

  it("mirrors the child's own exit rather than inventing one", async () => {
    const h = await booted();
    h.child.exitWith(3);
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([3]);
  });
});

describe("Shell: obligation one, an independent timer at least every MAX_CLOCK_STEP_MS", () => {
  it("arms the tick before anything that can fail", async () => {
    const h = harness(fixture, org);
    h.shell.start();
    expect(h.timers.intervals).toBeGreaterThan(0);
  });

  it("ticks strictly more often than the core's maximum clock step", async () => {
    const h = await booted();
    const before = h.timers.now();
    await h.tick(MAX_CLOCK_STEP_MS);
    expect(h.shell.ticksEmitted).toBeGreaterThanOrEqual(
      Math.floor(MAX_CLOCK_STEP_MS / (h.timers.now() - before)) + 1,
    );
    expect(h.shell.tickIntervalMs).toBeLessThan(MAX_CLOCK_STEP_MS);
  });

  it("keeps ticking through a total transport outage", async () => {
    const h = await booted();
    h.source.connected = false;
    const before = h.shell.ticksEmitted;
    await h.tick(MAX_CLOCK_STEP_MS * 4);
    expect(h.shell.ticksEmitted).toBeGreaterThan(before + 3);
    expect(h.exits).toEqual([]);
  });
});

describe("Shell: obligations two and three, the drain cannot be cancelled", () => {
  it("THE REQUIRED TEST: exits with a hanging handler, no traffic, and no reachable timer", async () => {
    let handlerArgs: unknown[] = [];
    let handlerThis: unknown = "not captured";
    const h = await booted({
      drainMs: 5_000,
      onRevoke: function hostile(this: unknown, ...args: unknown[]) {
        handlerArgs = args;
        handlerThis = this;
        // Never resolves. The whole point.
        return new Promise(() => {});
      },
    });

    const trafficBefore = h.source.traffic;
    const handshakesBefore = h.handshaker.calls;

    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);

    // CONDITION THREE. The handler received one argument, a string, and nothing
    // that refers to a timer, a controller or the shell.
    expect(h.onRevokeCalls).toHaveLength(1);
    expect(handlerArgs).toHaveLength(1);
    expect(typeof handlerArgs[0]).toBe("string");
    expect(handlerThis).toBeUndefined();
    expect(Object.keys(h.shell)).toEqual([]);

    expect(h.exits).toEqual([]);

    // CONDITION ONE. The drain deadline is reached by the shell's own timer.
    await h.tick(5_000);
    expect(h.exits).toEqual([1]);

    // CONDITION TWO. Nothing went out on a socket between the notice and the exit.
    expect(h.source.traffic).toBe(trafficBefore);
    expect(h.handshaker.calls).toBe(handshakesBefore);
    expect(h.source.closed).toBe(true);
  });

  it("does not let a handshake already in flight open a socket during the drain", async () => {
    // The hole this closes: a renewal that was in flight when the notice landed
    // resolves mid-drain, and its success path subscribes. Nothing about that
    // call site looks wrong, and the result is traffic after a revocation.
    let release: (() => void) | null = null;
    const h = await booted({ drainMs: 5_000, onRevoke: () => new Promise(() => {}) });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const inner = h.handshaker.handshake.bind(h.handshaker);
    h.handshaker.handshake = async () => {
      await gate;
      return await inner();
    };
    // Start a renewal and leave it hanging.
    h.source.emitError("Bundle refused.");
    await flush(() => h.shell.busy);
    const subscriptionsBefore = h.source.subscriptions.length;

    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);

    // Now let the in-flight handshake finish, mid-drain.
    release!();
    await flush();
    expect(h.source.subscriptions.length).toBe(subscriptionsBefore);

    await h.tick(5_000);
    expect(h.exits).toEqual([1]);
    expect(h.source.subscriptions.length).toBe(subscriptionsBefore);
  });

  it("does not wait for the handler before arming the deadline", async () => {
    let called = false;
    const h = await booted({
      onRevoke: () => {
        called = true;
        return new Promise(() => {});
      },
    });
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);
    expect(called).toBe(true);
    expect(h.timers.pending).toBeGreaterThan(0);
  });

  it("exits early when the handler finishes inside the window", async () => {
    const h = await booted({ drainMs: 30_000, onRevoke: async () => {} });
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([1]);
  });

  it("exits when the handler throws, because a failure may not cancel a revocation", async () => {
    const h = await booted({
      drainMs: 30_000,
      onRevoke: () => {
        throw new Error("flush failed");
      },
    });
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([1]);
  });

  it("survives a handler that returns a thenable which throws on subscription", async () => {
    const h = await booted({
      drainMs: 5_000,
      onRevoke: () => ({
        get then(): never {
          throw new Error("hostile thenable");
        },
      }),
    });
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);
    await h.tick(5_000);
    expect(h.exits).toEqual([1]);
  });

  it("gives the child SIGTERM and then SIGKILL, and exits one either way", async () => {
    const h = await booted({ drainMs: 0, killGraceMs: 4_000 });
    h.child.ignoreSigterm = true;
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);
    expect(h.child.signals).toEqual(["SIGTERM"]);
    expect(h.exits).toEqual([]);
    await h.tick(4_000);
    expect(h.child.signals).toEqual(["SIGTERM", "SIGKILL"]);
    expect(h.exits).toEqual([1]);
  });

  it("exits as soon as a well behaved child goes away, without waiting out the grace", async () => {
    const h = await booted({ drainMs: 0, killGraceMs: 60_000 });
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity),
    });
    await flush(() => h.shell.busy);
    expect(h.child.signals).toEqual(["SIGTERM"]);
    expect(h.exits).toEqual([1]);
  });
});

describe("Shell: obligation four, the epoch floor survives a restart", () => {
  it("persists the floor the moment the core accepts a notice, before the exit", async () => {
    const h = await booted({ drainMs: 0 });
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity, { epoch: 12 }),
    });
    await flush(() => h.shell.busy);
    expect(h.floor.saved).toContain(12);
    expect(h.floor.stored).toBe(12);
    expect(h.exits).toEqual([1]);
  });

  it("does not let a failed write keep a revoked process alive", async () => {
    const h = await booted({ drainMs: 0 });
    h.floor.throwOnSave = true;
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity, { epoch: 4 }),
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([1]);
    expect(h.logger.has("epoch-floor-write-failed")).toBe(true);
  });

  it("writes nothing when nothing was accepted", async () => {
    const h = await booted();
    await h.tick(MAX_CLOCK_STEP_MS * 3);
    expect(h.floor.saved).toEqual([]);
  });

  it("refuses a replay once the floor is restored", async () => {
    const h = harness(fixture, org, { drainMs: 0 });
    // A core restored from a stored floor, which is what a restart looks like.
    const restored = new Shell({
      core: new SluiceCore({
        orgRevocationPublicKey: org.publicKeyHex,
        tokenId: fixture.identity.tokenIdHex,
        initialEpochFloor: 5,
        drainMs: 0,
      }),
      identity: fixture.identity,
      timers: h.timers,
      logger: h.logger,
      handshaker: h.handshaker,
      source: h.source,
      child: h.child,
      floorStore: h.floor,
      exit: (code: number) => h.exits.push(code),
      killGraceMs: 1_000,
      bootTimeoutMs: 30_000,
      baseEnv: {},
      jitter: () => 0,
    });
    restored.start();
    await flush(() => h.shell.busy);
    h.source.emit(await fixture.bundleWith({ A: "b" }));
    await flush(() => h.shell.busy);
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity, { epoch: 5 }),
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([]);
    expect(h.logger.has("revocation-replay")).toBe(true);
  });
});

describe("Shell: the expired bundle token", () => {
  it("re-handshakes well before the five minute credential expires", async () => {
    const h = await booted();
    expect(h.handshaker.calls).toBe(1);
    await h.tick(200_000);
    expect(h.handshaker.calls).toBeGreaterThan(1);
    expect(h.source.subscriptions.length).toBeGreaterThan(1);
    expect(h.source.newest.token).not.toBe(h.source.subscriptions[0]!.token);
  });

  it("A REVOCATION STILL LANDS ON A PROCESS PAST THE ORIGINAL TOKEN'S LIFETIME", async () => {
    const h = await booted({ drainMs: 0 });
    const original = h.source.subscriptions[0]!.token;

    // Well past five minutes. The original credential is long dead.
    await h.tick(20 * 60_000);
    expect(h.timers.now() - T0).toBeGreaterThan(300_000);
    expect(h.source.newest.token).not.toBe(original);
    expect(h.source.live.every((s) => s.token !== original)).toBe(true);

    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity, { epoch: 2 }),
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([1]);
  });

  it("re-handshakes immediately when the live query refuses, without exiting", async () => {
    const h = await booted();
    const before = h.handshaker.calls;
    h.source.emitError("Bundle refused.");
    await flush(() => h.shell.busy);
    expect(h.handshaker.calls).toBeGreaterThan(before);
    expect(h.exits).toEqual([]);
  });

  it("keeps retrying with backoff when the handshake endpoint is down, and never exits", async () => {
    const h = await booted();
    h.handshaker.failures = 50;
    await h.tick(20 * 60_000);
    expect(h.handshaker.calls).toBeGreaterThan(3);
    expect(h.exits).toEqual([]);
    expect(h.logger.has("handshake-failed")).toBe(true);
  });

  it("holds at most two live subscriptions while a credential is rotated", async () => {
    const h = await booted();
    for (let i = 0; i < 10; i += 1) await h.tick(200_000);
    expect(h.source.live.length).toBeLessThanOrEqual(2);
  });
});

describe("Shell: availability, section 4.3", () => {
  it("ignores an invalid signature, warns loudly and does NOT exit", async () => {
    const h = await booted();
    const forged = signedNotice(org, fixture.identity)!;
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: { ...forged, signature: "0".repeat(128) },
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([]);
    expect(h.logger.has("revocation-bad-signature")).toBe(true);
    expect(h.child.signals).toEqual([]);
  });

  it("ignores a genuine notice that names another token", async () => {
    const other = await tokenFixture();
    const h = await booted();
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, other.identity),
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([]);
    expect(h.logger.has("revocation-other-token")).toBe(true);
  });

  it("keeps the last known good secrets when the socket drops, and does not exit", async () => {
    const h = await booted();
    h.source.connected = false;
    await h.tick(MAX_CLOCK_STEP_MS * 10);
    expect(h.exits).toEqual([]);
    expect(h.logger.has("disconnected")).toBe(true);
    h.source.connected = true;
    await h.tick(MAX_CLOCK_STEP_MS);
    expect(h.logger.has("reconnected")).toBe(true);
  });

  it("fails to start with no cache and no network, without spawning anything", async () => {
    const h = harness(fixture, org, { bootTimeoutMs: 10_000 });
    h.handshaker.failures = 100;
    h.shell.start();
    await h.tick(11_000);
    expect(h.exits).toEqual([1]);
    expect(h.child.started).toBe(false);
    expect(h.logger.has("boot-failed")).toBe(true);
  });

  it("does not exit when a bundle cannot be decrypted, at any point after boot", async () => {
    const h = await booted();
    const broken = await fixture.bundleWith({ A: "b" }, 2);
    h.source.emit({ ...broken, wrappedPDK: undefined, pdkNonce: undefined, pdkVersion: undefined });
    await flush(() => h.shell.busy);
    await h.tick(MAX_CLOCK_STEP_MS * 3);
    expect(h.exits).toEqual([]);
    expect(h.logger.has("bundle-unreadable")).toBe(true);
  });

  it("delivers a notice even when the grant has vanished, which is the point of the split", async () => {
    const h = await booted({ drainMs: 0 });
    h.source.emit({
      environmentId: "k17abcdefghijklmnopqrstuvwxyz01",
      epoch: 1,
      secrets: [],
      revocationNotice: signedNotice(org, fixture.identity, { epoch: 3 }),
    });
    await flush(() => h.shell.busy);
    expect(h.exits).toEqual([1]);
  });
});

describe("Shell: nothing secret reaches a log", () => {
  it("never prints a value, a token, a key or a JWT", async () => {
    const h = await booted({ drainMs: 0 });
    h.source.emit(await fixture.bundleWith({ API_KEY: "sk-live-canary-0001" }, 2));
    await flush(() => h.shell.busy);
    h.source.emitError("Bundle refused.");
    await flush(() => h.shell.busy);
    h.source.emit({
      ...(await fixture.bundleWith({}, 3)),
      revocationNotice: signedNotice(org, fixture.identity, { epoch: 9 }),
    });
    await flush(() => h.shell.busy);

    const text = h.logger.text;
    expect(text).not.toContain("sk-live-canary-0001");
    expect(text).not.toContain("postgres://real");
    expect(text).not.toContain(fixture.rawToken);
    expect(text).not.toContain(toHex(fixture.identity.tokenSecret));
    expect(text).not.toContain(toHex(fixture.identity.unwrapKey));
    expect(text).not.toContain(toHex(fixture.pdk));
    for (const subscription of h.source.subscriptions) {
      expect(text).not.toContain(subscription.token);
    }
    expect(text).not.toMatch(/[\u2013\u2014]/);
  });

  it("sanitises an attacker chosen reason before it can reach a terminal", async () => {
    const h = await booted({ drainMs: 0 });
    h.source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity, {
        reason: "all\u001b[2Jclear‮esrever\r\nINFO nothing happened",
      }),
    });
    await flush(() => h.shell.busy);
    const text = h.logger.text;
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("‮");
    expect(text).not.toContain("\r");
    expect(text.split("\n").some((line) => line.startsWith("INFO"))).toBe(false);
  });
});

describe("Shell: the only path to killing the child", () => {
  it("has exactly one signal call site reachable from a Sluice decision", () => {
    const source = readFileSync(
      fileURLToPath(new URL("../src/shell.ts", import.meta.url)),
      "utf8",
    );
    const sites = source.match(/\.signal\(/g) ?? [];
    // Both are inside `#stopChild`: the SIGTERM and the SIGKILL that follows
    // it. `#stopChild` is reachable only from `host.exit`, which is reachable
    // only from an `exit` or `fail-to-start` decision the core returned. The
    // only other place in this package that signals the child is the operator
    // signal relay in `run.ts`, which forwards a signal somebody else sent.
    expect(sites).toHaveLength(2);
    expect(source.match(/#stopChild\(/g) ?? []).toHaveLength(2);
    expect(source).not.toContain("AbortController");
    expect(source).not.toContain("AbortSignal");
  });

  it("never signals the child on any sequence that is not a core shutdown", async () => {
    const h = await booted();
    h.source.emitError("Bundle refused.");
    h.source.connected = false;
    await h.tick(MAX_CLOCK_STEP_MS * 20);
    h.source.connected = true;
    await h.tick(MAX_CLOCK_STEP_MS * 2);
    const forged = signedNotice(org, fixture.identity)!;
    h.source.emit({
      ...(await fixture.bundleWith({}, 2)),
      revocationNotice: { ...forged, signature: "1".repeat(128) },
    });
    await flush(() => h.shell.busy);
    expect(h.child.signals).toEqual([]);
    expect(h.exits).toEqual([]);
  });
});
