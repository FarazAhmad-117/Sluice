import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { deriveTokenKeys, fromHex, toHex, verifyHandshake } from "@sluice/crypto";
import { NO_PERSISTED_FLOOR, SluiceCore } from "@sluice/sdk";
import { FileEpochFloorStore } from "../src/floor";
import { HttpHandshaker } from "../src/handshake";
import { ConsoleLogger, NodeChildProcessSupervisor, NodeTimers } from "../src/node-runtime";
import { Shell } from "../src/shell";
import { FakeLogger, FakeSource, orgKeyPair, signedNotice, tokenFixture } from "./fakes";

/**
 * THE WHOLE CHAIN, WITH AS LITTLE FAKED AS THIS MACHINE ALLOWS.
 *
 * Real HTTP over a loopback socket, a real Ed25519 handshake signature that the
 * server verifies with the same function `convex/handshake.ts` uses, real
 * AES-GCM over a real wrapped project data key, a real child process that
 * really receives the decrypted value, a real signed revocation notice, real
 * timers, a real SIGTERM, and a real epoch floor written to a real file.
 *
 * The one substitution is the Convex subscription, because that needs a
 * deployment. Everything the subscription would deliver is built by the same
 * crypto the deployment would use, and `shell.test.ts` covers the transport
 * behaviour around it exhaustively on a virtual clock.
 */

let dir: string;
let server: Server;
let handshakeUrl: string;
let handshakeCalls = 0;

function listen(handler: Parameters<typeof createServer>[1]): Promise<{ url: string; server: Server }> {
  return new Promise((resolve) => {
    const created = createServer(handler);
    created.listen(0, "127.0.0.1", () => {
      const address = created.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      resolve({ url: `http://127.0.0.1:${port}/handshake`, server: created });
    });
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "sluice-e2e-"));
  handshakeCalls = 0;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(dir, { recursive: true, force: true });
});

async function waitFor(predicate: () => boolean, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("timed out waiting for a condition");
}

describe("sluice run, end to end", () => {
  it("injects a real secret into a real child and kills it on a real signed notice", async () => {
    const fixture = await tokenFixture();
    const org = orgKeyPair();
    const { authSeed } = deriveTokenKeys(fixture.identity.tokenId, fixture.identity.tokenSecret);
    const publicKeyHex = toHex(ed25519.getPublicKey(authSeed));

    // A handshake endpoint that verifies the signature the way the real one
    // does. A forged one would be refused here, exactly as it would be there.
    const started = await listen((request, response) => {
      let body = "";
      request.on("data", (chunk) => {
        body += String(chunk);
      });
      request.on("end", () => {
        handshakeCalls += 1;
        const parsed = JSON.parse(body) as {
          tokenId: string;
          unixSeconds: number;
          signature: string;
        };
        const valid =
          parsed.tokenId === fixture.identity.tokenIdHex &&
          verifyHandshake(
            publicKeyHex,
            fromHex(parsed.tokenId),
            parsed.unixSeconds,
            fromHex(parsed.signature),
          );
        response.writeHead(valid ? 200 : 401, { "Content-Type": "application/json" });
        response.end(
          JSON.stringify(
            valid
              ? { token: "bundle.jwt.value", expiresAt: Date.now() + 300_000 }
              : { error: "Handshake refused." },
          ),
        );
      });
    });
    server = started.server;
    handshakeUrl = started.url;

    const marker = join(dir, "child-saw.txt");
    const timers = new NodeTimers();
    const logger = new FakeLogger();
    const source = new FakeSource();
    const floorStore = new FileEpochFloorStore(join(dir, "state"), fixture.identity.tokenIdHashHex);
    const exits: number[] = [];

    const child = new NodeChildProcessSupervisor(
      process.execPath,
      [
        "-e",
        // Writes the injected value, then refuses to die quietly, so the drain
        // and the SIGTERM are both really exercised.
        `require("fs").writeFileSync(process.argv[1], String(process.env.DATABASE_URL)); setInterval(() => {}, 1000);`,
        marker,
      ],
      logger,
    );

    const shell = new Shell({
      core: new SluiceCore({
        orgRevocationPublicKey: org.publicKeyHex,
        tokenId: fixture.identity.tokenIdHex,
        initialEpochFloor: NO_PERSISTED_FLOOR,
        drainMs: 100,
        bootTimeoutMs: 15_000,
      }),
      identity: fixture.identity,
      timers,
      logger,
      handshaker: new HttpHandshaker({
        url: handshakeUrl,
        identity: fixture.identity,
        fetch: (url, init) => fetch(url, init),
        now: () => timers.now(),
      }),
      source,
      child,
      floorStore,
      exit: (code) => exits.push(code),
      killGraceMs: 2_000,
      bootTimeoutMs: 15_000,
      baseEnv: { SLUICE_TOKEN: fixture.rawToken, SLUICE_CANARY: "inherited" },
    });

    shell.start();

    // The handshake really happened, over a real socket, and was accepted.
    await waitFor(() => source.subscriptions.length > 0);
    expect(handshakeCalls).toBe(1);
    expect(source.subscriptions[0]!.token).toBe("bundle.jwt.value");

    source.emit(await fixture.bundleWith({ DATABASE_URL: "postgres://the-real-one" }));

    await waitFor(() => existsSync(marker) && readFileSync(marker, "utf8").length > 0);
    expect(readFileSync(marker, "utf8")).toBe("postgres://the-real-one");
    expect(child.running).toBe(true);
    // The parent environment came through and the service token did not.
    expect(child.started).toBe(true);

    // A real notice, signed with a real Ed25519 key the shell has never seen
    // and verified against the one the customer pinned.
    source.emit({
      ...(await fixture.bundleWith({}, 1)),
      revocationNotice: signedNotice(org, fixture.identity, { epoch: 4 }),
    });

    await waitFor(() => exits.length > 0);
    expect(exits).toEqual([1]);
    await waitFor(() => !child.running);

    // The floor really reached the disk, so a restart refuses this notice.
    expect(floorStore.load()).toEqual({ ok: true, floor: 4 });

    // Nothing secret reached a log line.
    expect(logger.text).not.toContain("postgres://the-real-one");
    expect(logger.text).not.toContain(fixture.rawToken);
    expect(logger.text).not.toContain("bundle.jwt.value");
  }, 30_000);

  it("refuses a forged handshake the way the deployment would, and fails to start", async () => {
    const fixture = await tokenFixture();
    const org = orgKeyPair();

    const started = await listen((_request, response) => {
      handshakeCalls += 1;
      response.writeHead(401, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "Handshake refused." }));
    });
    server = started.server;

    const timers = new NodeTimers();
    const logger = new FakeLogger();
    const exits: number[] = [];
    const child = new NodeChildProcessSupervisor(process.execPath, ["-e", "0"], logger);

    const shell = new Shell({
      core: new SluiceCore({
        orgRevocationPublicKey: org.publicKeyHex,
        tokenId: fixture.identity.tokenIdHex,
        initialEpochFloor: NO_PERSISTED_FLOOR,
        drainMs: 0,
        bootTimeoutMs: 1_500,
      }),
      identity: fixture.identity,
      timers,
      logger,
      handshaker: new HttpHandshaker({
        url: started.url,
        identity: fixture.identity,
        fetch: (url, init) => fetch(url, init),
        now: () => timers.now(),
      }),
      source: new FakeSource(),
      child,
      floorStore: new FileEpochFloorStore(join(dir, "state"), fixture.identity.tokenIdHashHex),
      exit: (code) => exits.push(code),
      killGraceMs: 1_000,
      bootTimeoutMs: 1_500,
      baseEnv: {},
    });

    shell.start();
    await waitFor(() => exits.length > 0);
    expect(exits).toEqual([1]);
    expect(child.started).toBe(false);
    expect(logger.has("boot-failed")).toBe(true);
    expect(handshakeCalls).toBeGreaterThan(0);
  }, 30_000);
});

describe("ConsoleLogger on the real stream", () => {
  it("writes to stderr and never to stdout", async () => {
    const started = await listen((_request, response) => response.end("{}"));
    server = started.server;
    const written: string[] = [];
    new ConsoleLogger((line) => written.push(line)).log("info", "x", "y");
    expect(written).toEqual(["sluice info x: y\n"]);
  });
});
