import { describe, expect, it } from "vitest";
import { sanitiseForLog } from "@sluice/sdk";
import type { RawBundle } from "../src/bundle";
import {
  ConsoleLogger,
  guardSubscriptionHandlers,
  NodeChildProcessSupervisor,
  NodeTimers,
  stripControls,
} from "../src/node-runtime";
import { FakeLogger } from "./fakes";

function childExit(
  supervisor: NodeChildProcessSupervisor,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve) => {
    supervisor.onExit((code, signal) => resolve({ code, signal }));
  });
}

// These tests spawn a real `node` child, which on a loaded machine (a parallel
// run, Windows process creation, a cold disk cache) can take seconds to start
// and exit. The explicit timeout matches `end-to-end.test.ts`: a slow spawn
// should make the run slower, not red.
const SPAWNS_REAL_NODE_MS = 15_000;

describe("NodeChildProcessSupervisor", () => {
  it("runs a real child with exactly the environment it was given", async () => {
    const logger = new FakeLogger();
    const supervisor = new NodeChildProcessSupervisor(
      process.execPath,
      ["-e", "process.exit(process.env.SLUICE_CANARY === 'injected' ? 7 : 9)"],
      logger,
    );
    const exited = childExit(supervisor);
    supervisor.spawn({ SLUICE_CANARY: "injected" });
    expect(supervisor.started).toBe(true);
    expect(await exited).toEqual({ code: 7, signal: null });
    expect(supervisor.running).toBe(false);
  }, SPAWNS_REAL_NODE_MS);

  it("reports a command that does not exist as an exit rather than a throw", async () => {
    const logger = new FakeLogger();
    const supervisor = new NodeChildProcessSupervisor(
      "sluice-no-such-command-anywhere",
      [],
      logger,
    );
    const exited = childExit(supervisor);
    expect(() => supervisor.spawn({})).not.toThrow();
    expect((await exited).code).toBe(1);
    expect(logger.has("child-spawn-failed")).toBe(true);
    expect(logger.text).not.toMatch(/[\u2013\u2014]/);
  }, SPAWNS_REAL_NODE_MS);

  it("kills a real child that is doing nothing in particular", async () => {
    const logger = new FakeLogger();
    const supervisor = new NodeChildProcessSupervisor(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      logger,
    );
    const exited = childExit(supervisor);
    supervisor.spawn({});
    supervisor.signal("SIGKILL");
    const result = await exited;
    expect(result.code === null || result.code !== 0).toBe(true);
    expect(supervisor.running).toBe(false);
  }, SPAWNS_REAL_NODE_MS);

  it("ignores a signal after the child is gone", async () => {
    const supervisor = new NodeChildProcessSupervisor(
      process.execPath,
      ["-e", "0"],
      new FakeLogger(),
    );
    const exited = childExit(supervisor);
    supervisor.spawn({});
    await exited;
    expect(() => supervisor.signal("SIGTERM")).not.toThrow();
  }, SPAWNS_REAL_NODE_MS);

  it("spawns at most once", async () => {
    const supervisor = new NodeChildProcessSupervisor(
      process.execPath,
      ["-e", "0"],
      new FakeLogger(),
    );
    const exited = childExit(supervisor);
    supervisor.spawn({});
    supervisor.spawn({});
    await exited;
    expect(supervisor.started).toBe(true);
  }, SPAWNS_REAL_NODE_MS);
});

describe("guardSubscriptionHandlers, the transport boundary", () => {
  it("contains a throwing handler, logs it sanitised, and keeps delivering", () => {
    const logger = new FakeLogger();
    const received: unknown[] = [];
    let throwNext = true;
    const guarded = guardSubscriptionHandlers(
      {
        onResult: (raw) => {
          if (throwNext) {
            throwNext = false;
            throw new TypeError("Cannot read properties of null\u001b[2J");
          }
          received.push(raw);
        },
        onError: () => {
          throw "not even an Error";
        },
      },
      logger,
    );
    const bundle = { secrets: null } as unknown as RawBundle;
    expect(() => guarded.onResult(bundle)).not.toThrow();
    expect(() => guarded.onError("expired")).not.toThrow();
    guarded.onResult(bundle);
    expect(received).toEqual([bundle]);
    const failures = logger.lines.filter((line) => line.code === "bundle-handler-failed");
    expect(failures).toHaveLength(2);
    expect(logger.text).not.toContain("\u001b");
  });

  it("does not let a throwing logger undo the guard", () => {
    const guarded = guardSubscriptionHandlers(
      {
        onResult: () => {
          throw new Error("handler");
        },
        onError: () => undefined,
      },
      {
        log: () => {
          throw new Error("logger");
        },
        metric: () => undefined,
      },
    );
    expect(() => guarded.onResult({} as RawBundle)).not.toThrow();
  });
});

describe("NodeTimers", () => {
  it("clears both kinds of timer through one method", async () => {
    const timers = new NodeTimers();
    let fired = 0;
    const timeout = timers.setTimeout(() => {
      fired += 1;
    }, 1);
    const interval = timers.setInterval(() => {
      fired += 1;
    }, 1);
    timers.clear(timeout);
    timers.clear(interval);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(fired).toBe(0);
  });

  it("reports a clock that moves", () => {
    const timers = new NodeTimers();
    expect(timers.now()).toBeGreaterThan(1_700_000_000_000);
  });
});

describe("ConsoleLogger", () => {
  it("writes one line per record and nothing to stdout", () => {
    const lines: string[] = [];
    const logger = new ConsoleLogger((line) => lines.push(line));
    logger.log("warn", "disconnected", "lost the connection");
    logger.metric("sluice.connection.lost", 1);
    expect(lines).toEqual(["sluice warn disconnected: lost the connection\n"]);
  });

  it("strips escape sequences that reached it unsanitised", () => {
    const lines: string[] = [];
    new ConsoleLogger((line) => lines.push(line)).log(
      "error",
      "revoked",
      "wiped\u001b[2Jand‮reversed\rand forged\n",
    );
    const written = lines[0]!;
    expect(written).not.toContain("\u001b");
    expect(written).not.toContain("‮");
    expect(written).not.toContain("\r");
    expect(written.split("\n")).toHaveLength(2);
  });
});

describe("stripControls", () => {
  it("agrees with the SDK's sanitiser on every input short enough for both", () => {
    const samples = [
      "",
      "ordinary text",
      "escape \u001b[2J here",
      "carriage \r return",
      "newline \n forged",
      "bidi ‮ override",
      "c1 \u009b control",
      "del \u007f",
      "lone \ud800 surrogate",
      "emoji \u{1f600} survives",
      "accents survive: eaiou",
      "a".repeat(200),
    ];
    for (const sample of samples) {
      expect(stripControls(sample)).toBe(sanitiseForLog(sample));
    }
  });

  it("does not truncate, which is the one difference and the reason it exists", () => {
    const long = "x".repeat(4_000);
    expect(stripControls(long)).toHaveLength(4_000);
    expect(sanitiseForLog(long).length).toBeLessThan(400);
  });

  it("never throws on a non string", () => {
    expect(stripControls(undefined as unknown as string)).toBe("<non-string message>");
  });
});
