import { beforeEach, describe, expect, it } from "vitest";
import { signRevocation } from "@sluice/crypto";
import { SluiceCore } from "../src/core";
import { MAX_DRAIN_MS, MIN_MAX_OFFLINE_DURATION_MS } from "../src/types";
import {
  bundle,
  makeCore,
  notice,
  orgKeyPair,
  pick,
  signedRevocation,
  tokenIdHex,
  types,
  type Org,
} from "./helpers";

let org: Org;
let tokenId: string;

beforeEach(() => {
  org = orgKeyPair();
  tokenId = tokenIdHex();
});

/** Boot a core into the ordinary running state and discard the boot noise. */
function running(core: SluiceCore, at = 1000): SluiceCore {
  core.handle({ type: "boot", now: at, cache: null });
  core.handle({ type: "bundle", now: at + 1, bundle: bundle() });
  return core;
}

describe("construction", () => {
  it("requires the org revocation public key and refuses a malformed one", () => {
    expect(() => new SluiceCore({ orgRevocationPublicKey: "", tokenId })).toThrow(
      /orgRevocationPublicKey/,
    );
    expect(() => new SluiceCore({ orgRevocationPublicKey: "zz", tokenId })).toThrow(
      /orgRevocationPublicKey/,
    );
    // Uppercase hex decodes to the same bytes but is a second spelling of one
    // organisation; `verifyRevocation` rejects it, so reject it at boot where
    // the failure is loud instead of at revocation time where it is fatal.
    expect(
      () =>
        new SluiceCore({
          orgRevocationPublicKey: org.publicKeyHex.toUpperCase(),
          tokenId,
        }),
    ).toThrow(/orgRevocationPublicKey/);
  });

  it("refuses a malformed token id", () => {
    expect(
      () => new SluiceCore({ orgRevocationPublicKey: org.publicKeyHex, tokenId: "nope" }),
    ).toThrow(/tokenId/);
  });

  it("caps drainMs, because an unbounded drain is a revocation that never lands", () => {
    expect(() => makeCore(org, tokenId, { drainMs: MAX_DRAIN_MS + 1 })).toThrow(/drainMs/);
    expect(() => makeCore(org, tokenId, { drainMs: -1 })).toThrow(/drainMs/);
    expect(() => makeCore(org, tokenId, { drainMs: Number.NaN })).toThrow(/drainMs/);
    expect(() => makeCore(org, tokenId, { drainMs: MAX_DRAIN_MS })).not.toThrow();
    expect(() => makeCore(org, tokenId, { drainMs: 0 })).not.toThrow();
  });

  it("defaults drainMs to 5000 per section 4.3", () => {
    expect(makeCore(org, tokenId).drainMs).toBe(5000);
  });

  it("defaults maxOfflineDuration to unlimited and refuses a trigger-happy one", () => {
    expect(makeCore(org, tokenId).maxOfflineDurationMs).toBeUndefined();
    expect(() => makeCore(org, tokenId, { maxOfflineDurationMs: 0 })).toThrow(
      /maxOfflineDurationMs/,
    );
    expect(() =>
      makeCore(org, tokenId, { maxOfflineDurationMs: MIN_MAX_OFFLINE_DURATION_MS - 1 }),
    ).toThrow(/maxOfflineDurationMs/);
    expect(() =>
      makeCore(org, tokenId, { maxOfflineDurationMs: MIN_MAX_OFFLINE_DURATION_MS }),
    ).not.toThrow();
  });

  it("starts with an epoch floor of -1 and accepts a restored one", () => {
    expect(makeCore(org, tokenId).epochFloor).toBe(-1);
    expect(makeCore(org, tokenId, { initialEpochFloor: 12 }).epochFloor).toBe(12);
    expect(() => makeCore(org, tokenId, { initialEpochFloor: -2 })).toThrow(/initialEpochFloor/);
    expect(() => makeCore(org, tokenId, { initialEpochFloor: 1.5 })).toThrow(/initialEpochFloor/);
  });
});

describe("boot", () => {
  it("with no cache emits nothing and waits for the network", () => {
    const core = makeCore(org, tokenId);
    expect(types(core.handle({ type: "boot", now: 0, cache: null }))).toEqual([]);
    expect(core.state).toBe("booting");
  });

  it("with no cache and no network fails to start once the boot deadline passes", () => {
    const core = makeCore(org, tokenId, { bootTimeoutMs: 10_000 });
    core.handle({ type: "boot", now: 0, cache: null });
    expect(types(core.handle({ type: "disconnected", now: 10 }))).toContain("log");
    expect(types(core.handle({ type: "tick", now: 9_999 }))).toEqual([]);
    const out = core.handle({ type: "tick", now: 10_000 });
    expect(pick(out, "fail-to-start")).toHaveLength(1);
    expect(core.state).toBe("dead");
  });

  it("fail-to-start is emitted exactly once and the core goes quiet", () => {
    const core = makeCore(org, tokenId, { bootTimeoutMs: 10 });
    core.handle({ type: "boot", now: 0, cache: null });
    expect(pick(core.handle({ type: "tick", now: 99 }), "fail-to-start")).toHaveLength(1);
    expect(core.handle({ type: "tick", now: 100 })).toEqual([]);
    expect(core.handle({ type: "bundle", now: 101, bundle: bundle() })).toEqual([]);
  });

  it("with a disk cache and no network starts degraded and alarms loudly", () => {
    const core = makeCore(org, tokenId);
    const out = core.handle({ type: "boot", now: 0, cache: bundle({ A: "1" }) });
    const applied = pick(out, "apply-secrets");
    expect(applied).toHaveLength(1);
    expect(applied[0]?.degraded).toBe(true);
    expect(applied[0]?.changed).toEqual(["A"]);
    const warns = pick(out, "log").filter((l) => l.level === "warn" || l.level === "error");
    expect(warns.length).toBeGreaterThan(0);
    expect(core.state).toBe("running");
  });

  it("never fails to start after secrets have been applied, whatever the clock does", () => {
    const core = makeCore(org, tokenId, { bootTimeoutMs: 10 });
    core.handle({ type: "boot", now: 0, cache: bundle() });
    core.handle({ type: "disconnected", now: 1 });
    const out = core.handle({ type: "tick", now: 1_000_000_000 });
    expect(pick(out, "fail-to-start")).toHaveLength(0);
    expect(pick(out, "exit")).toHaveLength(0);
  });

  it("clears degraded once the wire confirms a bundle", () => {
    const core = makeCore(org, tokenId);
    core.handle({ type: "boot", now: 0, cache: bundle({ A: "1" }) });
    const out = core.handle({ type: "bundle", now: 5, bundle: bundle({ A: "2" }) });
    expect(pick(out, "apply-secrets")[0]?.degraded).toBe(false);
  });

  it("ignores a second boot rather than restarting its deadlines", () => {
    const core = makeCore(org, tokenId, { bootTimeoutMs: 10 });
    core.handle({ type: "boot", now: 0, cache: null });
    const out = core.handle({ type: "boot", now: 5, cache: null });
    expect(pick(out, "log").some((l) => l.level === "error")).toBe(true);
    expect(pick(core.handle({ type: "tick", now: 10 }), "fail-to-start")).toHaveLength(1);
  });
});

describe("value rotation and epoch bumps never crash", () => {
  it("reports changed and removed key names, never values", () => {
    const core = running(makeCore(org, tokenId));
    const out = core.handle({
      type: "bundle",
      now: 2000,
      bundle: bundle({ DATABASE_URL: "postgres://b", NEW: "n" }),
    });
    const applied = pick(out, "apply-secrets")[0];
    expect(applied?.changed).toEqual(["DATABASE_URL", "NEW"]);
    expect(applied?.removed).toEqual([]);
    expect(JSON.stringify(applied?.changed)).not.toContain("postgres");
  });

  it("emits no apply-secrets for an identical bundle", () => {
    const core = running(makeCore(org, tokenId));
    expect(pick(core.handle({ type: "bundle", now: 2000, bundle: bundle() }), "apply-secrets"))
      .toHaveLength(0);
  });

  it("reports removals", () => {
    const core = running(makeCore(org, tokenId));
    const out = core.handle({ type: "bundle", now: 2000, bundle: bundle({}) });
    expect(pick(out, "apply-secrets")[0]?.removed).toEqual(["DATABASE_URL"]);
  });

  it("an epoch bump asks for a re-fetch and never shuts down", () => {
    const core = running(makeCore(org, tokenId));
    const out = core.handle({ type: "epoch-bump", now: 2000, epoch: 2 });
    expect(pick(out, "refetch")).toEqual([{ type: "refetch", epoch: 2 }]);
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(core.state).toBe("running");
  });

  it("ignores a stale or repeated epoch bump", () => {
    const core = running(makeCore(org, tokenId));
    expect(pick(core.handle({ type: "epoch-bump", now: 2000, epoch: 1 }), "refetch")).toHaveLength(0);
    core.handle({ type: "epoch-bump", now: 2001, epoch: 3 });
    expect(pick(core.handle({ type: "epoch-bump", now: 2002, epoch: 3 }), "refetch")).toHaveLength(0);
  });

  it("a PDK epoch never moves the revocation epoch floor", () => {
    // If it did, a server that bumped the environment epoch to a large number
    // would permanently disable this token's kill switch.
    const core = running(makeCore(org, tokenId));
    core.handle({ type: "bundle", now: 2000, bundle: bundle({ A: "1" }, 9_000) });
    core.handle({ type: "epoch-bump", now: 2001, epoch: 9_001 });
    expect(core.epochFloor).toBe(-1);
    const out = core.handle({ ...signedRevocation(org, notice({ tokenId, epoch: 0 }), 2002) });
    expect(pick(out, "shutdown")).toHaveLength(1);
  });
});

describe("connection loss", () => {
  it("warns, emits a metric and keeps the last known good bundle", () => {
    const core = running(makeCore(org, tokenId));
    const out = core.handle({ type: "disconnected", now: 2000, cause: "socket closed" });
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(pick(out, "exit")).toHaveLength(0);
    expect(pick(out, "apply-secrets")).toHaveLength(0);
    expect(pick(out, "log").some((l) => l.level === "warn")).toBe(true);
    expect(pick(out, "metric").length).toBeGreaterThan(0);
    expect(core.state).toBe("running");
    expect(core.online).toBe(false);
  });

  it("never exits however long it stays down, by default", () => {
    const core = running(makeCore(org, tokenId));
    core.handle({ type: "disconnected", now: 2000 });
    for (let day = 1; day <= 400; day++) {
      const out = core.handle({ type: "tick", now: 2000 + day * 86_400_000 });
      expect(pick(out, "shutdown")).toHaveLength(0);
      expect(pick(out, "exit")).toHaveLength(0);
    }
    expect(core.state).toBe("running");
  });

  it("reports recovery on reconnect and re-arms the offline clock", () => {
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 10_000 }));
    core.handle({ type: "disconnected", now: 2000 });
    const out = core.handle({ type: "reconnected", now: 11_000 });
    expect(pick(out, "log").some((l) => l.level === "info")).toBe(true);
    expect(core.online).toBe(true);
    // 11s elapsed since the drop, but the drop is over, so nothing fires.
    expect(pick(core.handle({ type: "tick", now: 100_000 }), "shutdown")).toHaveLength(0);
  });

  it("collapses repeated disconnects rather than restarting the offline clock", () => {
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 10_000 }));
    core.handle({ type: "disconnected", now: 2000 });
    core.handle({ type: "disconnected", now: 8000 });
    const out = core.handle({ type: "tick", now: 12_000 });
    expect(pick(out, "shutdown")).toHaveLength(1);
  });
});

describe("maxOfflineDuration, the one opt-in that lets an outage kill a fleet", () => {
  it("does not fire before the configured window", () => {
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 10_000 }));
    core.handle({ type: "disconnected", now: 2000 });
    expect(pick(core.handle({ type: "tick", now: 11_999 }), "shutdown")).toHaveLength(0);
  });

  it("fires at the window with cause offline-limit, not revocation", () => {
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 10_000 }));
    core.handle({ type: "disconnected", now: 2000 });
    const shutdown = pick(core.handle({ type: "tick", now: 12_000 }), "shutdown")[0];
    expect(shutdown?.cause).toBe("offline-limit");
    expect(shutdown?.epoch).toBeNull();
  });

  it("does not fire while connected, however long the process runs", () => {
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 1_000 }));
    expect(pick(core.handle({ type: "tick", now: 10_000_000 }), "shutdown")).toHaveLength(0);
  });
});

describe("revocation, the only path to a shutdown on a running process", () => {
  it("a valid signature for this token drains then exits(1)", () => {
    const core = running(makeCore(org, tokenId));
    const n = notice({ tokenId, epoch: 4, reason: "token leaked" });
    const out = core.handle(signedRevocation(org, n, 2000));
    const shutdown = pick(out, "shutdown")[0];
    expect(shutdown?.cause).toBe("revocation");
    expect(shutdown?.epoch).toBe(4);
    expect(shutdown?.drainMs).toBe(5000);
    expect(shutdown?.reason).toBe("token leaked");
    expect(core.state).toBe("draining");

    expect(pick(core.handle({ type: "tick", now: 6_999 }), "exit")).toHaveLength(0);
    const exited = pick(core.handle({ type: "tick", now: 7_000 }), "exit");
    expect(exited).toEqual([{ type: "exit", code: 1, reason: expect.any(String) }]);
    expect(core.state).toBe("dead");
  });

  it("sanitises the reason for logging and keeps the signed bytes separately", () => {
    const core = running(makeCore(org, tokenId));
    const hostile = "leaked[2J\rall fine‮";
    const out = core.handle(signedRevocation(org, notice({ tokenId, epoch: 1, reason: hostile }), 2000));
    const shutdown = pick(out, "shutdown")[0];
    expect(shutdown?.reason).toBe("leaked�[2J�all fine�");
    expect(shutdown?.signedReason).toBe(hostile);
    // No log line may carry the raw control characters.
    for (const line of pick(out, "log")) {
      expect(line.message).not.toMatch(/[ --‪-‮]/);
    }
  });

  it("an INVALID signature is ignored, warned loudly, and does not exit", () => {
    const core = running(makeCore(org, tokenId));
    const n = notice({ tokenId, epoch: 4 });
    const out = core.handle({
      type: "revocation",
      now: 2000,
      notice: n,
      signature: new Uint8Array(64),
    });
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(pick(out, "exit")).toHaveLength(0);
    expect(pick(out, "log").some((l) => l.level === "error")).toBe(true);
    expect(pick(out, "metric").length).toBeGreaterThan(0);
    expect(core.state).toBe("running");
    expect(core.epochFloor).toBe(-1);
  });

  it("a signature from a DIFFERENT org key is ignored", () => {
    const core = running(makeCore(org, tokenId));
    const impostor = orgKeyPair();
    const n = notice({ tokenId, epoch: 4 });
    const out = core.handle({
      type: "revocation",
      now: 2000,
      notice: n,
      signature: signRevocation(impostor.privateKey, n),
    });
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(core.state).toBe("running");
  });

  it("a genuine notice for ANOTHER token is ignored and cannot poison the floor", () => {
    const core = running(makeCore(org, tokenId));
    const other = tokenIdHex();
    const out = core.handle(signedRevocation(org, notice({ tokenId: other, epoch: 900 }), 2000));
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(core.epochFloor).toBe(-1);
    expect(core.state).toBe("running");
    // And our own kill switch still works afterwards.
    expect(
      pick(core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2001)), "shutdown"),
    ).toHaveLength(1);
  });

  it("kills a process that is still booting with no secrets at all", () => {
    // A token stolen before the process ever connected is still a stolen token.
    const core = makeCore(org, tokenId, { bootTimeoutMs: 10_000 });
    core.handle({ type: "boot", now: 0, cache: null });
    const out = core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 100));
    expect(pick(out, "shutdown")).toHaveLength(1);
    expect(core.state).toBe("draining");
    // And the boot deadline must not race the drain to produce a second
    // terminal decision.
    const later = core.handle({ type: "tick", now: 20_000 });
    expect(pick(later, "fail-to-start")).toHaveLength(0);
    expect(pick(later, "exit")).toHaveLength(1);
  });

  it("a tampered notice body is ignored", () => {
    const core = running(makeCore(org, tokenId));
    const n = notice({ tokenId, epoch: 4 });
    const signature = signRevocation(org.privateKey, n);
    const out = core.handle({
      type: "revocation",
      now: 2000,
      notice: { ...n, epoch: 5 },
      signature,
    });
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(core.epochFloor).toBe(-1);
  });

  it("an unsigned notice cannot raise the epoch floor and disable the kill switch", () => {
    // The ordering hazard: if the floor moved before verification, one forged
    // notice at a huge epoch would permanently immunise a stolen token.
    const core = running(makeCore(org, tokenId));
    core.handle({
      type: "revocation",
      now: 2000,
      notice: notice({ tokenId, epoch: Number.MAX_SAFE_INTEGER }),
      signature: new Uint8Array(64),
    });
    expect(core.epochFloor).toBe(-1);
    expect(
      pick(core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2001)), "shutdown"),
    ).toHaveLength(1);
  });
});

describe("replay and epoch monotonicity", () => {
  it("refuses a replayed notice at or below the floor", () => {
    const core = running(makeCore(org, tokenId, { initialEpochFloor: 5 }));
    for (const epoch of [0, 1, 4, 5]) {
      const out = core.handle(signedRevocation(org, notice({ tokenId, epoch }), 2000));
      expect(pick(out, "shutdown")).toHaveLength(0);
      expect(pick(out, "log").some((l) => l.level === "warn" || l.level === "error")).toBe(true);
    }
    expect(core.state).toBe("running");
    expect(pick(core.handle(signedRevocation(org, notice({ tokenId, epoch: 6 }), 2001)), "shutdown"))
      .toHaveLength(1);
  });

  it("exposes the floor so a host can persist it", () => {
    const core = running(makeCore(org, tokenId));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 3 }), 2000));
    expect(core.epochFloor).toBe(3);
  });

  it("a replay two ways round: out-of-order arrivals never un-revoke", () => {
    const core = running(makeCore(org, tokenId));
    const high = signedRevocation(org, notice({ tokenId, epoch: 9 }), 2000);
    const low = signedRevocation(org, notice({ tokenId, epoch: 2 }), 2001);
    expect(pick(core.handle(high), "shutdown")).toHaveLength(1);
    expect(pick(core.handle(low), "shutdown")).toHaveLength(0);
    expect(core.state).toBe("draining");
    expect(core.epochFloor).toBe(9);
  });

  it("two valid notices at the SAME epoch order one shutdown, not two", () => {
    const core = running(makeCore(org, tokenId));
    const n = notice({ tokenId, epoch: 3 });
    expect(pick(core.handle(signedRevocation(org, n, 2000)), "shutdown")).toHaveLength(1);
    expect(pick(core.handle(signedRevocation(org, n, 2001)), "shutdown")).toHaveLength(0);
  });

  it("a second, higher revocation during drain does not extend the drain", () => {
    const core = running(makeCore(org, tokenId, { drainMs: 5000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 2 }), 6000));
    expect(pick(core.handle({ type: "tick", now: 7000 }), "exit")).toHaveLength(1);
  });

  it("rejects a malformed notice without throwing", () => {
    const core = running(makeCore(org, tokenId));
    const broken = { tokenId, epoch: "1", revokedAt: 0, reason: "x" } as never;
    const out = core.handle({ type: "revocation", now: 2000, notice: broken, signature: new Uint8Array(64) });
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(core.state).toBe("running");
  });
});

describe("drain", () => {
  it("a revocation while already disconnected still kills, and reconnecting does not cancel it", () => {
    const core = running(makeCore(org, tokenId));
    core.handle({ type: "disconnected", now: 2000 });
    expect(pick(core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2100)), "shutdown"))
      .toHaveLength(1);
    core.handle({ type: "reconnected", now: 2200 });
    core.handle({ type: "bundle", now: 2300, bundle: bundle({ NEW: "v" }) });
    expect(core.state).toBe("draining");
    expect(pick(core.handle({ type: "tick", now: 7100 }), "exit")).toHaveLength(1);
    expect(core.state).toBe("dead");
  });

  it("ignores secrets and epoch bumps once draining", () => {
    const core = running(makeCore(org, tokenId));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    expect(pick(core.handle({ type: "bundle", now: 2100, bundle: bundle({ X: "1" }) }), "apply-secrets"))
      .toHaveLength(0);
    expect(pick(core.handle({ type: "epoch-bump", now: 2101, epoch: 99 }), "refetch")).toHaveLength(0);
  });

  it("exits early when the handler reports it finished draining", () => {
    const core = running(makeCore(org, tokenId));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    const out = core.handle({ type: "drain-complete", now: 2500 });
    expect(pick(out, "exit")).toHaveLength(1);
    expect(core.state).toBe("dead");
  });

  it("exits immediately and loudly when the handler throws", () => {
    const core = running(makeCore(org, tokenId));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    const out = core.handle({ type: "drain-failed", now: 2100, error: "pool.close threw[2J" });
    expect(pick(out, "exit")).toHaveLength(1);
    expect(pick(out, "log").some((l) => l.level === "error")).toBe(true);
    for (const line of pick(out, "log")) expect(line.message).not.toContain("");
  });

  it("a hanging handler is overridden by the drain deadline", () => {
    const core = running(makeCore(org, tokenId, { drainMs: 1000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    // No drain-complete ever arrives. The clock alone ends it.
    expect(pick(core.handle({ type: "tick", now: 3000 }), "exit")).toHaveLength(1);
  });

  it("drainMs of 0 exits on the very next event rather than never", () => {
    const core = running(makeCore(org, tokenId, { drainMs: 0 }));
    const out = core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    expect(pick(out, "shutdown")).toHaveLength(1);
    expect(pick(out, "exit")).toHaveLength(1);
    expect(core.state).toBe("dead");
  });

  it("drain-complete outside a drain is ignored", () => {
    const core = running(makeCore(org, tokenId));
    expect(pick(core.handle({ type: "drain-complete", now: 2000 }), "exit")).toHaveLength(0);
    expect(core.state).toBe("running");
  });

  it("emits exit exactly once and then goes silent forever", () => {
    const core = running(makeCore(org, tokenId));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    expect(pick(core.handle({ type: "tick", now: 9000 }), "exit")).toHaveLength(1);
    for (const now of [9001, 9002, 9003]) {
      expect(core.handle({ type: "tick", now })).toEqual([]);
    }
    expect(core.handle(signedRevocation(org, notice({ tokenId, epoch: 50 }), 9004))).toEqual([]);
  });
});

describe("the clock is not trusted", () => {
  it("a backwards clock jump during a drain ends the drain rather than postponing it", () => {
    // A revoked process that never reaches its deadline is a stolen token still
    // running. Every clock anomaly must shorten a drain, never extend one.
    const core = running(makeCore(org, tokenId, { drainMs: 1000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 10_000));
    const out = core.handle({ type: "tick", now: 0 });
    expect(pick(out, "exit")).toHaveLength(1);
    expect(pick(out, "log").some((l) => l.code === "clock-went-backwards")).toBe(true);
    expect(core.state).toBe("dead");
  });

  it("one garbage forward timestamp does not make every later deadline unreachable", () => {
    // The regression this replaces: clamping `now` to be non-decreasing pinned
    // the clock to a far-future value forever, so no drain deadline was ever
    // reached again and the kill switch was dead for the life of the process.
    const core = running(makeCore(org, tokenId, { drainMs: 1000 }));
    core.handle({ type: "tick", now: 1e15 });
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 10_000));
    expect(pick(core.handle({ type: "tick", now: 11_000 }), "exit")).toHaveLength(1);
  });

  it("a non-finite now does not corrupt a deadline", () => {
    const core = running(makeCore(org, tokenId, { drainMs: 1000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 10_000));
    core.handle({ type: "tick", now: Number.NaN });
    core.handle({ type: "tick", now: Number.POSITIVE_INFINITY });
    expect(core.state).toBe("draining");
    expect(pick(core.handle({ type: "tick", now: 11_000 }), "exit")).toHaveLength(1);
  });

  it("a garbage clock reading on the revocation event itself still exits", () => {
    // The drain deadline is `now + drainMs` taken from the revocation event. A
    // host that read a far-future clock at exactly that moment would otherwise
    // set a deadline real time never reaches, and the revoked process would run
    // forever. The backwards-step rule catches it on the next real timestamp.
    const core = running(makeCore(org, tokenId, { drainMs: 5000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 1e15));
    expect(core.state).toBe("draining");
    expect(pick(core.handle({ type: "tick", now: 2100 }), "exit")).toHaveLength(1);
  });

  it("a far-past clock reading on the revocation event can only shorten the drain", () => {
    // The deadline lands in the bogus frame, so once real timestamps resume the
    // drain ends no later than it would have: 5000 absolute, against a
    // revocation whose real time was 1001. Shorter is the safe direction.
    const core = running(makeCore(org, tokenId, { drainMs: 5000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 0));
    expect(pick(core.handle({ type: "tick", now: 4_999 }), "exit")).toHaveLength(0);
    expect(pick(core.handle({ type: "tick", now: 5_000 }), "exit")).toHaveLength(1);
  });

  it("an extreme far-past reading exits on the next real timestamp", () => {
    const core = running(makeCore(org, tokenId, { drainMs: 5000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), -1e15));
    expect(pick(core.handle({ type: "tick", now: 2100 }), "exit")).toHaveLength(1);
  });

  it("a frozen clock is the one case the core cannot resolve, and it does not pretend to", () => {
    // Documented limit, asserted so it cannot change silently: with a clock
    // that never advances, no time-based deadline can fire. The defence is a
    // supervisor outside the process, not a crude event counter in here that
    // would truncate every legitimate drain.
    const core = running(makeCore(org, tokenId, { drainMs: 5000 }));
    core.handle(signedRevocation(org, notice({ tokenId, epoch: 1 }), 2000));
    for (let i = 0; i < 50; i++) {
      expect(pick(core.handle({ type: "tick", now: 2000 }), "exit")).toHaveLength(0);
    }
    expect(core.state).toBe("draining");
  });

  it("a forward clock jump cannot trigger an offline shutdown while connected", () => {
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 1_000 }));
    expect(pick(core.handle({ type: "tick", now: 1e15 }), "shutdown")).toHaveLength(0);
  });

  it("a single implausible forward jump cannot reach maxOfflineDuration", () => {
    // Subtracting timestamps would make one bad NTP sync look like a century
    // offline and kill the fleet. The accumulated clock caps each step.
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 600_000 }));
    core.handle({ type: "disconnected", now: 2000 });
    const out = core.handle({ type: "tick", now: 1e15 });
    expect(pick(out, "shutdown")).toHaveLength(0);
    expect(core.state).toBe("running");
  });

  it("but a genuinely long outage still reaches maxOfflineDuration by small steps", () => {
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 600_000 }));
    core.handle({ type: "disconnected", now: 2000 });
    let now = 2000;
    let shutdowns = 0;
    for (let i = 0; i < 30; i++) {
      now += 30_000;
      shutdowns += pick(core.handle({ type: "tick", now }), "shutdown").length;
    }
    expect(shutdowns).toBe(1);
  });

  it("a clock stuck at one value never reaches maxOfflineDuration", () => {
    // Fail-safe: no progress means no elapsed time, so an outage cannot kill.
    const core = running(makeCore(org, tokenId, { maxOfflineDurationMs: 1_000 }));
    core.handle({ type: "disconnected", now: 2000 });
    for (let i = 0; i < 100; i++) {
      expect(pick(core.handle({ type: "tick", now: 2000 }), "shutdown")).toHaveLength(0);
    }
  });
});
