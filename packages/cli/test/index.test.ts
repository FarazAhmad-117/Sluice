import { describe, expect, it } from "vitest";
import * as cli from "../src/index";

/**
 * THE EXPORT SURFACE, PINNED.
 *
 * `packages/crypto` and `packages/sdk` each have one of these and say why: on a
 * package that decides when a customer's process dies, an export added without
 * argument is how a future caller acquires a back door. Adding one has to show
 * up in a diff as an edit to two files.
 */
const EXPECTED = [
  "BundleDecryptError",
  "CONFIG_EXIT_CODE",
  "ConsoleLogger",
  "ConvexBundleSource",
  "FileEpochFloorStore",
  "HELP",
  "HandshakeError",
  "HttpHandshaker",
  "NodeChildProcessSupervisor",
  "NodeTimers",
  "Shell",
  "TokenIdentity",
  "VERSION",
  "decryptSecrets",
  "defaultStateDir",
  "floorFilePath",
  "loadConfig",
  "main",
  "parseArgv",
  "readRevocation",
  "run",
  "stripControls",
].sort();

describe("the public surface of @sluice/cli", () => {
  it("is exactly this list", () => {
    expect(Object.keys(cli).sort()).toEqual(EXPECTED);
  });

  it("offers no way to order a shutdown or to kill the child", () => {
    for (const name of Object.keys(cli)) {
      expect(name).not.toMatch(/^(shutdown|revoke|kill|terminate|forceExit)$/i);
    }
  });

  it("exposes nothing on a Shell instance that a drain handler could use", () => {
    // `Shell` is exported so an embedder with a different transport can reuse
    // it. What that buys them is a constructor, `start`, and two read-only
    // numbers. Every timer handle is a `#private` field, so there is nothing to
    // reach even by reflection.
    const surface = Object.getOwnPropertyNames(cli.Shell.prototype).sort();
    expect(surface).toEqual(["busy", "constructor", "start", "ticksEmitted", "tickIntervalMs"].sort());
  });
});
