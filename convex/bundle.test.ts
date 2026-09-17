import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { convexTest } from "convex-test";
import {
  mintToken,
  signHandshake,
  signRevocation,
  toHex,
  tokenIdHash,
  verifyRevocation,
} from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import { BUNDLE_TOKEN_LIFETIME_MS, signBundleToken } from "./lib/jwt";
import { patchEnvironment } from "./repo/environments";
import { getServiceTokenByIdHash, patchServiceToken } from "./repo/tokens";
import * as bundleModule from "./bundle";

export const modules = import.meta.glob("./**/*.ts");

type Harness = ReturnType<typeof convexTest>;
type Actor = { userId: Id<"users">; sessionToken: string };

const REFUSED = "Bundle refused.";

const SIGNING_KEY =
  "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

beforeEach(() => {
  process.env.JWT_SIGNING_KEY = SIGNING_KEY;
});

afterEach(() => {
  delete process.env.JWT_SIGNING_KEY;
});

/**
 * Frozen, for the reason `http.test.ts` sets out at length: every fixture here
 * goes through the real handshake, whose acceptance window is measured against
 * server time read after the test read its own. A stopped clock turns elapsed
 * time into zero, so nothing in this file can depend on how long a machine
 * under load took to get from one line to the next.
 */
const FROZEN_NOW = Date.parse("2026-09-18T12:00:00.000Z");

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(FROZEN_NOW);
});

afterEach(() => {
  vi.useRealTimers();
});

const NAME_CIPHERTEXT = "aa".repeat(24);
const VALUE_CIPHERTEXT = "bb".repeat(40);

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

async function tenant(t: Harness, actor: Actor, slug: string) {
  const keys = mintToken({ environment: "revocation" });
  const orgId = await t.mutation(api.orgs.createOrg, {
    sessionToken: actor.sessionToken,
    name: "Acme Rockets",
    slug,
    revocationPublicKey: keys.upload.publicKey,
    wrappedRevocationKey: "wrapped-revocation-key-blob",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  });
  const projectId = await t.mutation(api.projects.createProject, {
    sessionToken: actor.sessionToken,
    orgId,
    name: "API",
    slug: "api",
  });
  const production = await t.mutation(api.environments.createEnvironment, {
    sessionToken: actor.sessionToken,
    projectId,
    name: "production",
  });
  const staging = await t.mutation(api.environments.createEnvironment, {
    sessionToken: actor.sessionToken,
    projectId,
    name: "staging",
  });
  return { keys, orgId, projectId, production, staging };
}

let nonceCounter = 0;
function freshNonces() {
  nonceCounter += 1;
  const stem = nonceCounter.toString(16).padStart(4, "0");
  return {
    nameNonce: `${stem}0102030405060708090a`.slice(0, 24),
    valueNonce: `${stem}ff02030405060708090a`.slice(0, 24),
  };
}

async function addSecret(
  t: Harness,
  actor: Actor,
  environmentId: Id<"environments">,
  valueCiphertext = VALUE_CIPHERTEXT,
) {
  return await t.mutation(api.secrets.createSecret, {
    sessionToken: actor.sessionToken,
    environmentId,
    nameCiphertext: NAME_CIPHERTEXT,
    valueCiphertext,
    ...freshNonces(),
  });
}

/**
 * Registers a token through the real mutation and authenticates it through the
 * real handshake endpoint, so the credential the bundle sees is the one the
 * shipping path produces rather than one this file minted for itself.
 */
async function issueAndHandshake(
  t: Harness,
  actor: Actor,
  environmentId: Id<"environments">,
) {
  const minted = mintToken({ environment: "production" });
  const serviceTokenId = await t.mutation(api.tokens.createServiceToken, {
    sessionToken: actor.sessionToken,
    environmentId,
    tokenId: minted.upload.tokenId,
    publicKey: minted.upload.publicKey,
    wrappedPDK: "cc".repeat(48),
    pdkNonce: "0102030405060708090a0b0c",
  });

  const unixSeconds = Math.floor(Date.now() / 1000);
  const response = await t.fetch("/handshake", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tokenId: minted.upload.tokenId,
      unixSeconds,
      signature: toHex(
        signHandshake(minted.tokenId, minted.tokenSecret, unixSeconds),
      ),
    }),
  });
  if (response.status !== 200) {
    throw new Error(`fixture handshake failed with ${response.status}`);
  }
  const { token } = (await response.json()) as { token: string };
  return { minted, serviceTokenId, bundleToken: token };
}

const SECRET_FIELDS = [
  "lineageId",
  "nameCiphertext",
  "nameNonce",
  "pdkVersion",
  "secretId",
  "valueCiphertext",
  "valueNonce",
  "version",
];

describe("the bundle", () => {
  it("serves one token only its own environment's secrets", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const acme = await tenant(t, alice, "acme");
    const other = await tenant(t, mallory, "mallory-co");

    const mine = await addSecret(t, alice, acme.production, "11".repeat(40));
    await addSecret(t, alice, acme.staging, "22".repeat(40));
    await addSecret(t, mallory, other.production, "33".repeat(40));

    const { bundleToken } = await issueAndHandshake(t, alice, acme.production);
    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });

    expect(bundle.environmentId).toBe(acme.production);
    expect(bundle.secrets.map((secret) => secret.secretId)).toEqual([
      mine.secretId,
    ]);
    // Not merely "the other rows are absent": nothing about the sibling
    // environment or the other tenant appears anywhere in the payload.
    const serialised = JSON.stringify(bundle);
    expect(serialised).not.toContain(acme.staging);
    expect(serialised).not.toContain("22".repeat(40));
    expect(serialised).not.toContain("33".repeat(40));
  });

  it("excludes superseded and deleted secrets", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");

    const kept = await addSecret(t, alice, acme.production, "11".repeat(40));
    const replaced = await addSecret(t, alice, acme.production, "22".repeat(40));
    const removed = await addSecret(t, alice, acme.production, "33".repeat(40));

    const updated = await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: replaced.secretId,
      nameCiphertext: NAME_CIPHERTEXT,
      valueCiphertext: "44".repeat(40),
      ...freshNonces(),
    });
    await t.mutation(api.secrets.deleteSecret, {
      sessionToken: alice.sessionToken,
      secretId: removed.secretId,
    });

    const { bundleToken } = await issueAndHandshake(t, alice, acme.production);
    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });

    expect(bundle.secrets.map((secret) => secret.secretId).sort()).toEqual(
      [kept.secretId, updated.secretId].sort(),
    );
    // The superseded row's ciphertext must not travel either: a workload that
    // installed both versions of one lineage would have no way to tell which
    // is current, because the name is ciphertext.
    expect(JSON.stringify(bundle)).not.toContain("22".repeat(40));
  });

  /**
   * THE REQUIRED TEST. Both sides of the join written by the real code, read
   * back through the real query.
   *
   * `serviceTokens` stores only `tokenIdHash` and `revocations` carries both
   * forms of the id, so the bundle joins on the hash. If the two write sites
   * ever computed it differently NOTHING WOULD THROW: the join would return
   * an empty list, the notice would never reach the bundle, and the revoked
   * token would keep working. Every fixture that seeds both hashes by hand
   * passes regardless, because a hand-seeded fixture agrees with itself, which
   * is the entire trap this test exists to avoid falling into.
   */
  it("delivers a revocation written through the real path", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    await addSecret(t, alice, acme.production);

    const { minted, bundleToken } = await issueAndHandshake(
      t,
      alice,
      acme.production,
    );

    const before = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(before.revocationNotice).toBeUndefined();

    const notice = {
      tokenId: minted.upload.tokenId,
      epoch: 7,
      revokedAt: Date.now(),
      reason: "Laptop stolen.",
    };
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...notice,
      signature: toHex(signRevocation(acme.keys.authSeed, notice)),
    });

    const after = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(after.revocationNotice).toBeDefined();
    expect(after.revocationNotice).toMatchObject(notice);

    // And the notice the bundle ships actually verifies under the org key the
    // customer pinned, which is the only thing that makes an SDK act on it.
    const delivered = after.revocationNotice as {
      tokenId: string;
      epoch: number;
      revokedAt: number;
      reason: string;
      signature: string;
    };
    expect(
      verifyRevocation(
        acme.keys.upload.publicKey,
        {
          tokenId: delivered.tokenId,
          epoch: delivered.epoch,
          revokedAt: delivered.revokedAt,
          reason: delivered.reason,
        },
        Uint8Array.from(
          (delivered.signature.match(/../g) ?? []).map((byte) =>
            Number.parseInt(byte, 16),
          ),
        ),
      ),
    ).toBe(true);
  });

  /**
   * The negative control for the test above: if the two write sites disagreed
   * by one byte, would anything notice? This proves the assertion is load
   * bearing rather than incidentally true.
   */
  it("would find nothing if the two stored hashes disagreed", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    const { minted, bundleToken } = await issueAndHandshake(
      t,
      alice,
      acme.production,
    );

    const notice = {
      tokenId: minted.upload.tokenId,
      epoch: 7,
      revokedAt: Date.now(),
      reason: "Laptop stolen.",
    };
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...notice,
      signature: toHex(signRevocation(acme.keys.authSeed, notice)),
    });

    // Move the token's stored hash by one character, exactly as a second,
    // slightly different hashing construction at the other write site would.
    const hash = tokenIdHash({ tokenId: minted.tokenId });
    await t.run(async (ctx) => {
      const row = await getServiceTokenByIdHash(ctx, hash);
      if (row === null) throw new Error("fixture did not register the token");
      await patchServiceToken(ctx, row._id, {
        tokenIdHash: `${hash.slice(0, -1)}${hash.endsWith("0") ? "1" : "0"}`,
      });
    });

    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });
    // Silently no notice, and the token carries on. Nothing throws. That is
    // what a one-character drift buys, and why one construction is shared.
    expect(bundle.revocationNotice).toBeUndefined();
  });

  it("keeps serving the notice to a revoked token instead of locking it out", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    await addSecret(t, alice, acme.production);
    const { minted, bundleToken } = await issueAndHandshake(
      t,
      alice,
      acme.production,
    );

    const notice = {
      tokenId: minted.upload.tokenId,
      epoch: 1,
      revokedAt: Date.now(),
      reason: "Rotated.",
    };
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...notice,
      signature: toHex(signRevocation(acme.keys.authSeed, notice)),
    });

    // THE TRAP THIS TEST EXISTS FOR. Refusing a revoked token here looks like
    // the obvious hardening and is the single worst thing this query could do:
    // the signed notice is the ONLY thing that makes a workload shut itself
    // down, and it reaches that workload through this query. Slamming the door
    // would leave every revoked process running, holding the secrets it
    // already had, and never told.
    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(bundle.revocationNotice).toBeDefined();
    // It stops receiving secrets, which is the server's half of the defence
    // against an SDK that ignores the notice.
    expect(bundle.secrets).toEqual([]);
  });

  it("delivers the highest epoch when a token was revoked more than once", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    const { minted, bundleToken } = await issueAndHandshake(
      t,
      alice,
      acme.production,
    );

    for (const epoch of [2, 5]) {
      const notice = {
        tokenId: minted.upload.tokenId,
        epoch,
        revokedAt: Date.now(),
        reason: `Revocation ${epoch}.`,
      };
      await t.mutation(api.tokens.revokeServiceToken, {
        sessionToken: alice.sessionToken,
        ...notice,
        signature: toHex(signRevocation(acme.keys.authSeed, notice)),
      });
    }

    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });
    // The SDK keeps a floor on the highest epoch it has acted on and ignores
    // anything at or below it, so shipping an older notice would be shipping
    // one the SDK is required to discard.
    expect(bundle.revocationNotice?.epoch).toBe(5);
  });

  it("changes the wrapped PDK a token receives when the epoch bumps", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    const { minted, bundleToken } = await issueAndHandshake(
      t,
      alice,
      acme.production,
    );

    const before = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(before.epoch).toBe(0);
    expect(before.wrappedPDK).toBe("cc".repeat(48));

    // A re-key: the environment's epoch moves and the project data key is
    // re-wrapped for the token, in one transaction. Both halves, because a
    // bumped epoch with a stale wrapped key hands the token a blob that opens
    // a key the stored ciphertext is no longer under.
    const hash = tokenIdHash({ tokenId: minted.tokenId });
    await t.run(async (ctx) => {
      const row = await getServiceTokenByIdHash(ctx, hash);
      if (row === null) throw new Error("fixture did not register the token");
      await patchEnvironment(ctx, acme.production, { epoch: 1 });
      await patchServiceToken(ctx, row._id, {
        epoch: 1,
        wrappedPDK: "ee".repeat(48),
        nonce: "aabbccddeeff001122334455",
      });
    });

    const after = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(after.epoch).toBe(1);
    expect(after.wrappedPDK).toBe("ee".repeat(48));
    expect(after.pdkNonce).toBe("aabbccddeeff001122334455");
  });

  it("carries nothing that could be plaintext", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    await addSecret(t, alice, acme.production);
    const { bundleToken } = await issueAndHandshake(t, alice, acme.production);

    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });

    // Structural, by inspecting the declared return validator rather than the
    // one value this test happened to produce. A field added later that could
    // hold a name or a value fails here before anyone ships it.
    const returns = JSON.parse(
      (bundleModule.getBundle as unknown as { exportReturns: () => string }).exportReturns(),
    ) as { value: Record<string, { fieldType: { value?: Record<string, unknown> } }> };

    expect(Object.keys(returns.value).sort()).toEqual([
      "environmentId",
      "epoch",
      "pdkNonce",
      "pdkVersion",
      "revocationNotice",
      "secrets",
      "wrappedPDK",
    ]);
    expect(Object.keys(bundle.secrets[0] ?? {}).sort()).toEqual(SECRET_FIELDS);
    for (const field of ["name", "value", "secretName", "secretValue"]) {
      expect(Object.keys(returns.value)).not.toContain(field);
      expect(Object.keys(bundle.secrets[0] ?? {})).not.toContain(field);
    }
  });

  it("refuses a token issued for a different service token", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    const mine = await addSecret(t, alice, acme.production, "11".repeat(40));

    const first = await issueAndHandshake(t, alice, acme.production);
    const second = await issueAndHandshake(t, alice, acme.staging);

    // The bundle resolves its environment from the row named by the token's
    // subject, so a credential minted for one service token cannot address
    // another's environment however it is presented.
    const bundle = await t.query(api.bundle.getBundle, {
      token: second.bundleToken,
    });
    expect(bundle.environmentId).toBe(acme.staging);
    expect(bundle.secrets).toEqual([]);

    const own = await t.query(api.bundle.getBundle, {
      token: first.bundleToken,
    });
    expect(own.secrets.map((secret) => secret.secretId)).toEqual([mine.secretId]);
  });

  it("refuses a forged, expired, absent or unknown credential identically", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    const { serviceTokenId, bundleToken } = await issueAndHandshake(
      t,
      alice,
      acme.production,
    );

    // Signed under a different key.
    const forged = (() => {
      const previous = process.env.JWT_SIGNING_KEY;
      process.env.JWT_SIGNING_KEY = "aa".repeat(32);
      const token = signBundleToken({ subject: serviceTokenId, now: Date.now() });
      process.env.JWT_SIGNING_KEY = previous;
      return token;
    })();

    // Correctly signed, but for a service token document that does not exist.
    const orphan = signBundleToken({
      subject: "kd7000000000000000000000000",
      now: Date.now(),
    });

    // Correctly signed and genuinely expired.
    const stale = signBundleToken({
      subject: serviceTokenId,
      now: Date.now() - BUNDLE_TOKEN_LIFETIME_MS - 1,
    });

    // Correctly signed, and the subject is not a document id at all. A get on
    // a malformed id throws rather than returning null, so without
    // normalisation this is a server error instead of a refusal, which is a
    // second observably different failure path. (Worded the long way round
    // because `repo/repo.test.ts` greps source text and cannot tell a mention
    // of the database handle from a use of it.)
    const nonsense = signBundleToken({ subject: "not-an-id", now: Date.now() });

    for (const token of [forged, orphan, stale, nonsense, "", "not.a.token"]) {
      await expect(
        t.query(api.bundle.getBundle, { token }),
      ).rejects.toThrow(REFUSED);
    }

    // And the real one still works, so none of the above passed because the
    // fixture was broken.
    await expect(
      t.query(api.bundle.getBundle, { token: bundleToken }),
    ).resolves.toBeDefined();
  });

  it("never echoes the bundle token it was given", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    await addSecret(t, alice, acme.production);
    const { bundleToken } = await issueAndHandshake(t, alice, acme.production);

    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(JSON.stringify(bundle)).not.toContain(bundleToken);

    let message = "";
    try {
      await t.query(api.bundle.getBundle, { token: "a-distinctive-bad-token" });
    } catch (error) {
      message = String((error as { data?: unknown }).data ?? error);
    }
    expect(message).not.toContain("a-distinctive-bad-token");
  });

  it("takes no session token and no user id", async () => {
    const args = JSON.parse(
      (bundleModule.getBundle as unknown as { exportArgs: () => string }).exportArgs(),
    ) as { value: Record<string, unknown> };
    // A service token has no user. Giving this query a session argument would
    // be the wrong repair for the right instinct: the credential it takes is
    // the one the handshake issued and nothing else.
    expect(Object.keys(args.value)).toEqual(["token"]);
  });
});
