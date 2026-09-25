import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mintToken } from "@sluice/crypto";
import { HELP, main, VERSION } from "../src/main";
import { CONFIG_EXIT_CODE, run } from "../src/run";
import { floorFilePath } from "../src/floor";
import { TokenIdentity } from "../src/config";
import { FakeLogger, FakeSource } from "./fakes";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "sluice-main-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function capture() {
  const out: string[] = [];
  const exits: number[] = [];
  return {
    out,
    exits,
    stdout: (text: string) => out.push(text),
    exit: (code: number) => exits.push(code),
  };
}

describe("main", () => {
  it("prints help and exits zero", () => {
    const c = capture();
    main({ argv: ["--help"], env: {}, exit: c.exit, stdout: c.stdout });
    expect(c.out.join("")).toBe(HELP);
    expect(c.exits).toEqual([0]);
  });

  it("prints a version and exits zero", () => {
    const c = capture();
    main({ argv: ["--version"], env: {}, exit: c.exit, stdout: c.stdout });
    expect(c.out.join("")).toBe(`${VERSION}\n`);
    expect(c.exits).toEqual([0]);
  });

  it("exits two on a usage error, never one, because one means revoked", () => {
    const c = capture();
    main({ argv: ["run", "npm", "start"], env: {}, exit: c.exit, stdout: c.stdout });
    expect(c.exits).toEqual([CONFIG_EXIT_CODE]);
  });

  it("documents the token stripping and the offline knob in the help text", () => {
    expect(HELP).toContain("SLUICE_MAX_OFFLINE_MS");
    expect(HELP).toContain("removed from the child's environment");
    expect(HELP).not.toMatch(/[\u2013\u2014]/);
  });
});

describe("run", () => {
  function env(overrides: Record<string, string | undefined> = {}) {
    return {
      SLUICE_TOKEN: mintToken({ environment: "prod" }).token,
      SLUICE_ORG_REVOCATION_PUBLIC_KEY: "a".repeat(64),
      SLUICE_CONVEX_URL: "https://deployment.convex.cloud",
      SLUICE_STATE_DIR: dir,
      ...overrides,
    };
  }

  it("exits two on bad configuration without starting anything", () => {
    const c = capture();
    const logger = new FakeLogger();
    run("node", ["-e", "0"], {
      env: env({ SLUICE_ORG_REVOCATION_PUBLIC_KEY: "nope" }),
      exit: c.exit,
      logger,
    });
    expect(c.exits).toEqual([CONFIG_EXIT_CODE]);
    expect(logger.has("config-invalid")).toBe(true);
  });

  it("REFUSES TO START on an unreadable epoch floor rather than reopening the window", () => {
    const c = capture();
    const logger = new FakeLogger();
    const configured = env();
    // Written for the right token, then corrupted, which is what a half written
    // file or a truncated volume looks like.
    const hash = TokenIdentity.fromToken(configured.SLUICE_TOKEN).tokenIdHashHex;
    writeFileSync(floorFilePath(dir, hash), "{", "utf8");
    run("node", ["-e", "0"], {
      env: configured,
      exit: c.exit,
      logger,
      sourceFactory: () => new FakeSource(),
    });
    expect(c.exits).toEqual([CONFIG_EXIT_CODE]);
    expect(logger.has("epoch-floor-unreadable")).toBe(true);
  });

  it("says out loud that a first boot has no floor, and starts anyway", () => {
    const c = capture();
    const logger = new FakeLogger();
    const source = new FakeSource();
    run("node", ["-e", "0"], {
      env: env(),
      exit: c.exit,
      logger,
      sourceFactory: () => source,
    });
    expect(logger.has("first-boot")).toBe(true);
    expect(c.exits).toEqual([]);
    source.close();
  });

  it("never exits one for a configuration problem, because one means revoked", () => {
    for (const broken of [
      { SLUICE_TOKEN: "not-a-token" },
      { SLUICE_ORG_REVOCATION_PUBLIC_KEY: "A".repeat(64) },
      { SLUICE_CONVEX_URL: "http://evil.example" },
      { SLUICE_DRAIN_MS: "later" },
    ]) {
      const c = capture();
      run("node", ["-e", "0"], {
        env: env(broken),
        exit: c.exit,
        logger: new FakeLogger(),
        sourceFactory: () => new FakeSource(),
      });
      expect(c.exits).toEqual([CONFIG_EXIT_CODE]);
    }
  });
});
