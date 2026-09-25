import { describe, expect, it } from "vitest";
import { parseArgv } from "../src/argv";

describe("parseArgv", () => {
  it("splits the child command off the double dash", () => {
    expect(parseArgv(["run", "--", "npm", "start"])).toEqual({
      kind: "run",
      command: "npm",
      args: ["start"],
    });
  });

  it("keeps flags that belong to the child on the child's side", () => {
    expect(parseArgv(["run", "--", "node", "--enable-source-maps", "app.js"])).toEqual({
      kind: "run",
      command: "node",
      args: ["--enable-source-maps", "app.js"],
    });
  });

  it("keeps a second double dash for the child, because it is the child's argument", () => {
    expect(parseArgv(["run", "--", "npm", "run", "x", "--", "-v"])).toEqual({
      kind: "run",
      command: "npm",
      args: ["run", "x", "--", "-v"],
    });
  });

  it("refuses run with no double dash rather than guessing where the command starts", () => {
    expect(parseArgv(["run", "npm", "start"])).toEqual({
      kind: "usage-error",
      message:
        "sluice run needs a double dash before the command to run: sluice run -- npm start",
    });
  });

  it("refuses an empty command after the double dash", () => {
    expect(parseArgv(["run", "--"])).toEqual({
      kind: "usage-error",
      message: "sluice run needs a command after the double dash: sluice run -- npm start",
    });
  });

  it("answers help and version", () => {
    expect(parseArgv(["--help"])).toEqual({ kind: "help" });
    expect(parseArgv(["-h"])).toEqual({ kind: "help" });
    expect(parseArgv([])).toEqual({ kind: "help" });
    expect(parseArgv(["--version"])).toEqual({ kind: "version" });
  });

  it("names an unknown subcommand without echoing anything else", () => {
    expect(parseArgv(["frobnicate"])).toEqual({
      kind: "usage-error",
      message: 'unknown command "frobnicate". The only command is: sluice run -- <command>',
    });
  });

  it("sanitises a hostile subcommand name before it can reach a terminal", () => {
    const parsed = parseArgv(["\u001b[2Jwipe"]);
    expect(parsed.kind).toBe("usage-error");
    expect(parsed.kind === "usage-error" && parsed.message).not.toContain("\u001b");
  });

  it("never emits an em dash or an en dash", () => {
    const messages = [
      parseArgv(["run"]),
      parseArgv(["run", "--"]),
      parseArgv(["nope"]),
    ].map((p) => (p.kind === "usage-error" ? p.message : ""));
    for (const message of messages) {
      expect(message).not.toMatch(/[\u2013\u2014]/);
    }
  });
});
