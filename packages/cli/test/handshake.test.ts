import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { deriveTokenKeys, fromHex, mintToken, verifyHandshake } from "@sluice/crypto";
import { TokenIdentity } from "../src/config";
import { HandshakeError, HttpHandshaker } from "../src/handshake";

const URL_ = "https://deployment.convex.site/handshake";
const NOW = 1_764_000_000_000;

interface Call {
  readonly url: string;
  readonly init: RequestInit;
}

function harness(responder: (call: Call) => Promise<Response> | Response) {
  const minted = mintToken({ environment: "prod" });
  const identity = TokenIdentity.fromToken(minted.token);
  const calls: Call[] = [];
  const handshaker = new HttpHandshaker({
    url: URL_,
    identity,
    now: () => NOW,
    fetch: async (url: string, init: RequestInit) => {
      const call = { url, init };
      calls.push(call);
      return await responder(call);
    },
  });
  return { minted, identity, calls, handshaker };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("HttpHandshaker", () => {
  it("signs a handshake the server's own verifier accepts", async () => {
    const { minted, calls, handshaker } = harness(() =>
      json(200, { token: "jwt.value.here", expiresAt: NOW + 300_000 }),
    );
    await handshaker.handshake();

    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toBe(URL_);
    expect(call.init.method).toBe("POST");
    const body = JSON.parse(String(call.init.body)) as {
      tokenId: string;
      unixSeconds: number;
      signature: string;
    };
    expect(body.tokenId).toMatch(/^[0-9a-f]{32}$/);
    expect(body.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(body.unixSeconds).toBe(Math.floor(NOW / 1000));

    const { authSeed } = deriveTokenKeys(minted.tokenId, minted.tokenSecret);
    const publicKey = Buffer.from(ed25519.getPublicKey(authSeed)).toString("hex");
    expect(
      verifyHandshake(publicKey, minted.tokenId, body.unixSeconds, fromHex(body.signature)),
    ).toBe(true);
  });

  it("returns the credential and its expiry", async () => {
    const { handshaker } = harness(() =>
      json(200, { token: "jwt.value.here", expiresAt: NOW + 300_000 }),
    );
    await expect(handshaker.handshake()).resolves.toEqual({
      token: "jwt.value.here",
      expiresAt: NOW + 300_000,
    });
  });

  it("never sends the token secret or the unwrap key over the wire", async () => {
    const { minted, calls, handshaker } = harness(() =>
      json(200, { token: "jwt.value.here", expiresAt: NOW + 300_000 }),
    );
    await handshaker.handshake();
    const wire = String(calls[0]!.init.body) + JSON.stringify(calls[0]!.init.headers ?? {});
    expect(wire).not.toContain(Buffer.from(minted.tokenSecret).toString("hex"));
    expect(wire).not.toContain(Buffer.from(minted.unwrapKey).toString("hex"));
    expect(wire).not.toContain(minted.token);
  });

  it("turns a refusal into a named error that names no credential", async () => {
    const { handshaker } = harness(() => json(401, { error: "Handshake refused." }));
    const error = await handshaker.handshake().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HandshakeError);
    expect((error as Error).message).toContain("401");
    expect((error as Error).message).not.toContain("jwt");
  });

  it("passes the clock skew refusal through, because it is the one actionable one", async () => {
    const { handshaker } = harness(() =>
      json(400, { error: "The handshake timestamp is outside the acceptance window." }),
    );
    const error = await handshaker.handshake().catch((e: unknown) => e);
    expect((error as Error).message).toContain("acceptance window");
  });

  it("sanitises a hostile error body before it can reach a terminal", async () => {
    const { handshaker } = harness(() => json(400, { error: "\u001b[2Jgone‮reversed" }));
    const error = await handshaker.handshake().catch((e: unknown) => e);
    expect((error as Error).message).not.toContain("\u001b");
    expect((error as Error).message).not.toContain("‮");
  });

  it("refuses a response with no token", async () => {
    const { handshaker } = harness(() => json(200, { expiresAt: NOW + 300_000 }));
    await expect(handshaker.handshake()).rejects.toBeInstanceOf(HandshakeError);
  });

  it("refuses a credential that has already expired", async () => {
    const { handshaker } = harness(() => json(200, { token: "jwt", expiresAt: NOW - 1 }));
    await expect(handshaker.handshake()).rejects.toBeInstanceOf(HandshakeError);
  });

  it("refuses a non JSON body without echoing it", async () => {
    const { handshaker } = harness(
      () => new Response("<html>\u001b[2J secret-looking-body </html>", { status: 200 }),
    );
    const error = await handshaker.handshake().catch((e: unknown) => e);
    expect((error as Error).message).not.toContain("secret-looking-body");
    expect((error as Error).message).not.toContain("\u001b");
  });

  it("wraps a transport failure rather than letting a stack trace carry the url", async () => {
    const { handshaker } = harness(() => {
      throw new Error("getaddrinfo ENOTFOUND");
    });
    const error = await handshaker.handshake().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HandshakeError);
    expect((error as Error).message).toContain("could not be reached");
  });

  it("never emits an em dash or an en dash", async () => {
    const cases = [
      harness(() => json(401, { error: "Handshake refused." })),
      harness(() => json(200, { token: "jwt" })),
      harness(() => {
        throw new Error("boom");
      }),
    ];
    for (const { handshaker } of cases) {
      const error = await handshaker.handshake().catch((e: unknown) => e);
      expect((error as Error).message).not.toMatch(/[\u2013\u2014]/);
    }
  });
});
