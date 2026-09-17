import { describe, expect, it } from "vitest";
import { applyDecisions } from "../src/host";
import type { SecretBundle, SluiceDecision, SluiceHost } from "../src/types";

interface Recorder extends SluiceHost {
  readonly calls: string[];
}

function recorder(overrides: Partial<SluiceHost> = {}): Recorder {
  const calls: string[] = [];
  return {
    calls,
    exit(code) {
      calls.push(`exit:${code}`);
    },
    log(level, code) {
      calls.push(`log:${level}:${code}`);
    },
    metric(name, value) {
      calls.push(`metric:${name}=${value}`);
    },
    applySecrets(_bundle, changed) {
      calls.push(`apply:${changed.join(",")}`);
    },
    refetch(epoch) {
      calls.push(`refetch:${epoch}`);
    },
    beginDrain(_reason, drainMs) {
      calls.push(`drain:${drainMs}`);
    },
    ...overrides,
  };
}

const bundle: SecretBundle = { epoch: 1, secrets: { A: "1" } };

describe("applyDecisions", () => {
  it("routes every decision type to the right host method, in order", () => {
    const host = recorder();
    applyDecisions(host, [
      { type: "log", level: "warn", code: "disconnected", message: "m" },
      { type: "metric", name: "sluice.connection.lost", value: 1 },
      { type: "apply-secrets", bundle, changed: ["A"], removed: [], degraded: false },
      { type: "refetch", epoch: 3 },
      {
        type: "shutdown",
        cause: "revocation",
        reason: "r",
        signedReason: "r",
        epoch: 7,
        drainMs: 5000,
      },
      { type: "exit", code: 1, reason: "done" },
    ]);
    expect(host.calls).toEqual([
      "log:warn:disconnected",
      "metric:sluice.connection.lost=1",
      "apply:A",
      "refetch:3",
      "drain:5000",
      "exit:1",
    ]);
  });

  it("exits on fail-to-start", () => {
    const host = recorder();
    applyDecisions(host, [{ type: "fail-to-start", code: 1, reason: "no cache, no network" }]);
    expect(host.calls).toEqual(["exit:1"]);
  });

  it("tolerates a host with only the required methods", () => {
    const calls: string[] = [];
    const minimal: SluiceHost = {
      exit: (c) => calls.push(`exit:${c}`),
      log: () => calls.push("log"),
      metric: () => calls.push("metric"),
    };
    expect(() =>
      applyDecisions(minimal, [
        { type: "apply-secrets", bundle, changed: [], removed: [], degraded: true },
        { type: "refetch", epoch: 1 },
        {
          type: "shutdown",
          cause: "revocation",
          reason: "r",
          signedReason: "r",
          epoch: 1,
          drainMs: 1,
        },
        { type: "exit", code: 1, reason: "x" },
      ]),
    ).not.toThrow();
    expect(calls.at(-1)).toBe("exit:1");
  });

  describe("a broken host cannot prevent an exit", () => {
    it("when applySecrets throws", () => {
      const host = recorder({
        applySecrets: () => {
          throw new Error("boom");
        },
      });
      applyDecisions(host, [
        { type: "apply-secrets", bundle, changed: ["A"], removed: [], degraded: false },
        { type: "exit", code: 1, reason: "x" },
      ]);
      expect(host.calls).toContain("exit:1");
    });

    it("when beginDrain throws", () => {
      // The customer's drain handler is the single likeliest thing to fail
      // during the incident that triggered the revocation.
      const host = recorder({
        beginDrain: () => {
          throw new Error("pool.close failed");
        },
      });
      applyDecisions(host, [
        {
          type: "shutdown",
          cause: "revocation",
          reason: "r",
          signedReason: "r",
          epoch: 1,
          drainMs: 5000,
        },
        { type: "exit", code: 1, reason: "x" },
      ]);
      expect(host.calls).toContain("exit:1");
    });

    it("when log itself throws", () => {
      const host = recorder({
        log: () => {
          throw new Error("logger is down");
        },
      });
      applyDecisions(host, [
        { type: "log", level: "error", code: "revoked", message: "m" },
        { type: "exit", code: 1, reason: "x" },
      ]);
      expect(host.calls).toEqual(["exit:1"]);
    });

    it("when metric throws", () => {
      const host = recorder({
        metric: () => {
          throw new Error("statsd is down");
        },
      });
      applyDecisions(host, [
        { type: "metric", name: "n", value: 1 },
        { type: "exit", code: 1, reason: "x" },
      ]);
      expect(host.calls).toContain("exit:1");
    });
  });

  it("calls exit at most once even if handed two exit decisions", () => {
    const host = recorder();
    applyDecisions(host, [
      { type: "exit", code: 1, reason: "a" },
      { type: "exit", code: 1, reason: "b" },
      { type: "fail-to-start", code: 1, reason: "c" },
    ]);
    expect(host.calls.filter((c) => c.startsWith("exit"))).toEqual(["exit:1"]);
  });

  it("does not swallow an exit that throws, because nothing can follow it", () => {
    // `process.exit` does not return. A host whose exit throws is broken in a
    // way this package cannot paper over, and hiding it would leave a revoked
    // process running with no trace of why.
    const host = recorder({
      exit: () => {
        throw new Error("exit refused");
      },
    });
    expect(() => applyDecisions(host, [{ type: "exit", code: 1, reason: "x" }])).toThrow(
      /exit refused/,
    );
  });

  it("ignores an unknown decision shape rather than throwing", () => {
    const host = recorder();
    expect(() =>
      applyDecisions(host, [{ type: "not-a-real-decision" } as unknown as SluiceDecision]),
    ).not.toThrow();
  });
});
