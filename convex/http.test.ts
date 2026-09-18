import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { convexTest } from "convex-test";
import {
  mintToken,
  signHandshake,
  signRevocation,
  toHex,
  tokenIdHash,
  fromHex,
} from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import { verifyBundleToken } from "./lib/jwt";
import { handshakeSignatureHash } from "./lib/handshake";
import {
  getHandshakeNonce,
  getServiceTokenByIdHash,
  patchServiceToken,
} from "./repo/tokens";
import { listAuditEventsByActor } from "./repo/audit";

export const modules = import.meta.glob("./**/*.ts");

/**
 * A project data key wrapped to the creator. Opaque to the server by design:
 * it is minted in the browser and this deployment has never held the plaintext.
 * `createEnvironment` writes it into `pdkGrants` in the same transaction that
 * creates the environment, because an environment without one is an environment
 * whose secrets nobody can ever read.
 */
const WRAP = {
  wrappedPDK: "dd".repeat(48),
  pdkNonce: "0a1b2c3d4e5f60718293a4b5",
} as const;

type Harness = ReturnType<typeof convexTest>;

const SIGNING_KEY =
  "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

/**
 * A handshake is authenticated entirely by what the SDK sends, so the refusal
 * must not tell an attacker which of several reasons applied. This is the one
 * string every rejected handshake gets.
 */
const REFUSED = "Handshake refused.";

beforeEach(() => {
  process.env.JWT_SIGNING_KEY = SIGNING_KEY;
});

afterEach(() => {
  delete process.env.JWT_SIGNING_KEY;
});

/**
 * THE CLOCK IS FROZEN FOR THIS WHOLE FILE, AND THAT IS NOT A CONVENIENCE.
 *
 * The acceptance window is sixty seconds either side of SERVER time, and the
 * server reads its clock after the test has read its own. With a real clock the
 * boundary cases are races rather than assertions: a request built at `now + 61`
 * becomes `now + 60` and is ACCEPTED if a single second boundary happens to pass
 * between the two reads, so the test that proves the window is closed is exactly
 * the one that fails intermittently. The past side drifts the safe way and the
 * future side does not, which is the kind of asymmetry that gets diagnosed as
 * "flaky" and retried rather than read.
 *
 * Freezing removes the elapsed time entirely, so `+61` means `+61` at both ends
 * and the boundary is a fact rather than a probability. Verified that
 * `convex-test` is happy with a stopped clock: it assigns commit timestamps
 * from `Date.now()` and explicitly bumps by one when the clock has not moved.
 */
const FROZEN_NOW = Date.parse("2026-09-18T12:00:00.000Z");

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(FROZEN_NOW);
});

afterEach(() => {
  vi.useRealTimers();
});


type Actor = { userId: Id<"users">; sessionToken: string };

async function seedUser(t: Harness, email: string): Promise<Actor> {
  const sessionToken = `session-for-${email}`;
  const userId = await t.run(async (ctx) =>
    insertUser(ctx, {
      email: normaliseEmail(email),
      authVerifierHash: "hash",
      publicKey: "11".repeat(32),
      verifyKey: "22".repeat(32),
      wrappedPrivateKey: "wrapped-private-key-blob",
      wrappedSigningKey: "wrapped-signing-key-blob",
    }),
  );
  await t.run(async (ctx) =>
    insertSession(ctx, {
      userId,
      tokenHash: hashSessionToken(sessionToken),
      createdAt: Date.now(),
      expiresAt: Date.now() + SESSION_LIFETIME_MS,
    }),
  );
  return { userId, sessionToken };
}

/**
 * The organisation revocation keypair, built out of the package's own public
 * surface. `mintToken` produces an Ed25519 seed and the matching public key,
 * which is exactly the pair `signRevocation` and `verifyRevocation` want, so no
 * test here reaches past `@sluice/crypto` for a curve primitive.
 */
function revocationKeypair() {
  const minted = mintToken({ environment: "revocation" });
  return { privateKey: minted.authSeed, publicKey: minted.upload.publicKey };
}

async function world(t: Harness) {
  const admin = await seedUser(t, "admin@example.test");
  const keys = revocationKeypair();

  const orgId = await t.mutation(api.orgs.createOrg, {
    sessionToken: admin.sessionToken,
    name: "Acme Rockets",
    slug: "acme",
    revocationPublicKey: keys.publicKey,
    wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  });
  const projectId = await t.mutation(api.projects.createProject, {
    sessionToken: admin.sessionToken,
    orgId,
    name: "API",
    slug: "api",
  });
  const environmentId = await t.mutation(api.environments.createEnvironment, {
    sessionToken: admin.sessionToken,
    projectId,
    name: "production",
    ...WRAP,
  });

  return { admin, keys, orgId, projectId, environmentId };
}

/**
 * Mints a real token with `@sluice/crypto` and registers it through the real
 * mutation, so the stored `tokenIdHash` is produced by the shipping code path
 * and not by a fixture that agrees with itself.
 */
async function issueToken(
  t: Harness,
  admin: Actor,
  environmentId: Id<"environments">,
  options: { expiresAt?: number } = {},
) {
  const minted = mintToken({ environment: "production" });
  const serviceTokenId = await t.mutation(api.tokens.createServiceToken, {
    sessionToken: admin.sessionToken,
    environmentId,
    tokenId: minted.upload.tokenId,
    publicKey: minted.upload.publicKey,
    wrappedPDK: "cc".repeat(48),
    pdkNonce: "0102030405060708090a0b0c",
    ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
  });
  return { minted, serviceTokenId };
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

type Minted = ReturnType<typeof mintToken>;

function handshakeBody(minted: Minted, unixSeconds: number) {
  return {
    tokenId: minted.upload.tokenId,
    unixSeconds,
    signature: toHex(
      signHandshake(minted.tokenId, minted.tokenSecret, unixSeconds),
    ),
  };
}

async function handshake(t: Harness, body: unknown): Promise<Response> {
  return await t.fetch("/handshake", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("the handshake", () => {
  it("issues a bundle token for a correctly signed request", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted, serviceTokenId } = await issueToken(t, admin, environmentId);

    const response = await handshake(t, handshakeBody(minted, nowSeconds()));
    expect(response.status).toBe(200);

    const body = (await response.json()) as { token: string; expiresAt: number };
    expect(verifyBundleToken({ token: body.token, now: Date.now() })).toEqual({
      subject: serviceTokenId,
    });
    expect(body.expiresAt).toBeGreaterThan(Date.now());
  });

  it("records the nonce, the last-seen time and an audit event", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    const unixSeconds = nowSeconds();
    const body = handshakeBody(minted, unixSeconds);
    expect((await handshake(t, body)).status).toBe(200);

    const hash = tokenIdHash({ tokenId: minted.tokenId });
    const signatureHash = handshakeSignatureHash({
      signature: fromHex(body.signature),
    });

    const nonce = await t.run(async (ctx) => getHandshakeNonce(ctx, signatureHash));
    expect(nonce).not.toBeNull();
    expect(nonce?.expiresAt).toBeGreaterThan(Date.now());

    const stored = await t.run(async (ctx) => getServiceTokenByIdHash(ctx, hash));
    expect(stored?.lastSeenAt).toBeTypeOf("number");

    const events = await t.run(async (ctx) => listAuditEventsByActor(ctx, hash, 10));
    expect(events.map((event) => event.action)).toEqual(["token.handshake"]);
    expect(events[0]?.actorType).toBe("token");
    // The actor is the HASH. A plaintext token id in an append-only table is a
    // permanent, queryable copy of the identifier the hash exists to protect.
    expect(events[0]?.actorId).not.toBe(minted.upload.tokenId);
  });

  it("rejects a replay of the identical signature on the second attempt", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    // Ed25519 is deterministic, so this is byte for byte the same request.
    const body = handshakeBody(minted, nowSeconds());
    expect((await handshake(t, body)).status).toBe(200);

    const second = await handshake(t, body);
    expect(second.status).toBe(401);
    expect((await second.json()) as { error: string }).toEqual({ error: REFUSED });
  });

  it("lets exactly one of two concurrent identical replays through", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    const body = handshakeBody(minted, nowSeconds());
    const responses = await Promise.all([
      handshake(t, body),
      handshake(t, body),
    ]);

    const statuses = responses.map((response) => response.status).sort();
    // Check-then-insert as two calls is a time-of-check-to-time-of-use race in
    // which both of these observe "absent" and both succeed. That is precisely
    // the attack `handshakeNonces` exists to stop, so the claim has to be one
    // mutation that inserts and fails on conflict.
    expect(statuses).toEqual([200, 401]);
  });

  it("rejects a timestamp 61 seconds old and 61 seconds ahead", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    for (const offset of [-61, 61]) {
      const response = await handshake(
        t,
        handshakeBody(minted, nowSeconds() + offset),
      );
      expect(response.status).toBe(400);
    }
  });

  it("accepts the two timestamps exactly on the boundary", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    // The other half of the assertion above. Without it, a window of zero
    // seconds would pass every rejection test in this file, and the first
    // machine with a one second clock offset would find out in production.
    for (const offset of [-60, 60]) {
      const response = await handshake(
        t,
        handshakeBody(minted, nowSeconds() + offset),
      );
      expect(response.status, `offset ${offset}`).toBe(200);
    }
  });

  it("does the timestamp check before any cryptography", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    // A garbage signature over an out-of-window timestamp. If the window were
    // checked after verification the server would have done the Ed25519 work
    // for an attacker who supplied nothing valid at all. The observable proof
    // is that this is refused as a clock problem rather than as an auth one.
    const response = await handshake(t, {
      tokenId: minted.upload.tokenId,
      unixSeconds: nowSeconds() - 4000,
      signature: "00".repeat(64),
    });
    expect(response.status).toBe(400);
    expect((await response.json()) as { error: string }).not.toEqual({
      error: REFUSED,
    });
  });

  it("rejects a timestamp that is not a non-negative safe integer", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    for (const unixSeconds of [-1, 1.5, Number.NaN, 2 ** 53, -0]) {
      const response = await handshake(t, {
        tokenId: minted.upload.tokenId,
        unixSeconds,
        signature: "00".repeat(64),
      });
      expect(response.status).toBe(400);
    }
  });

  it("does not let a signature valid for one token authenticate another", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const first = await issueToken(t, admin, environmentId);
    const second = await issueToken(t, admin, environmentId);

    const unixSeconds = nowSeconds();
    const response = await handshake(t, {
      // The victim's id, the attacker's signature.
      tokenId: second.minted.upload.tokenId,
      unixSeconds,
      signature: toHex(
        signHandshake(first.minted.tokenId, first.minted.tokenSecret, unixSeconds),
      ),
    });
    expect(response.status).toBe(401);
  });

  it("fails a revoked token even with a perfectly valid signature", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId, keys } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    const revokedAt = Date.now();
    const notice = {
      tokenId: minted.upload.tokenId,
      epoch: 1,
      revokedAt,
      reason: "Laptop stolen.",
    };
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: admin.sessionToken,
      tokenId: notice.tokenId,
      epoch: notice.epoch,
      revokedAt: notice.revokedAt,
      reason: notice.reason,
      signature: toHex(signRevocation(keys.privateKey, notice)),
    });

    const response = await handshake(t, handshakeBody(minted, nowSeconds()));
    expect(response.status).toBe(401);
    expect((await response.json()) as { error: string }).toEqual({ error: REFUSED });
  });

  it("fails an expired token even with a perfectly valid signature", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId, {
      expiresAt: Date.now() - 1,
    });

    expect((await handshake(t, handshakeBody(minted, nowSeconds()))).status).toBe(
      401,
    );
  });

  it("fails an unknown token id exactly as it fails a bad signature", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    const unixSeconds = nowSeconds();

    // A token id that was never registered, signed correctly by whoever holds
    // it. Nothing about the response may reveal that no such token exists.
    const stranger = mintToken({ environment: "production" });
    const unknown = await handshake(t, handshakeBody(stranger, unixSeconds));

    // A registered token id with a signature that does not verify.
    const wrong = await handshake(t, {
      tokenId: minted.upload.tokenId,
      unixSeconds,
      signature: toHex(
        signHandshake(minted.tokenId, stranger.tokenSecret, unixSeconds),
      ),
    });

    expect(unknown.status).toBe(wrong.status);
    expect(await unknown.text()).toBe(await wrong.text());
    expect(unknown.status).toBe(401);
  });

  it("refuses a malformed body without telling the caller anything else", async () => {
    const t = convexTest(schema, modules);
    await world(t);

    const bodies: unknown[] = [
      "not json at all",
      {},
      { tokenId: "not hex", unixSeconds: nowSeconds(), signature: "00".repeat(64) },
      { tokenId: "AB".repeat(16), unixSeconds: nowSeconds(), signature: "00".repeat(64) },
      { tokenId: "ab".repeat(16), unixSeconds: nowSeconds(), signature: "00".repeat(63) },
      { tokenId: "ab".repeat(16), unixSeconds: `${nowSeconds()}`, signature: "00".repeat(64) },
    ];

    for (const body of bodies) {
      const response = await t.fetch("/handshake", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: typeof body === "string" ? body : JSON.stringify(body),
      });
      expect(response.status).toBe(400);
    }
  });

  it("never returns the token secret, the token id or the signing key", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);

    const response = await handshake(t, handshakeBody(minted, nowSeconds()));
    const text = await response.text();

    expect(text).not.toContain(toHex(minted.tokenSecret));
    expect(text).not.toContain(minted.upload.tokenId);
    expect(text).not.toContain(SIGNING_KEY);
  });

  it("survives a status that is neither active nor revoked by refusing", async () => {
    const t = convexTest(schema, modules);
    const { admin, environmentId } = await world(t);
    const { minted } = await issueToken(t, admin, environmentId);
    const hash = tokenIdHash({ tokenId: minted.tokenId });

    await t.run(async (ctx) => {
      const row = await getServiceTokenByIdHash(ctx, hash);
      if (row === null) throw new Error("fixture did not register the token");
      await patchServiceToken(ctx, row._id, { status: "revoked" });
    });

    expect((await handshake(t, handshakeBody(minted, nowSeconds()))).status).toBe(
      401,
    );
  });
});
