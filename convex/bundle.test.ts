import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { convexTest } from "convex-test";
import {
  mintToken,
  newId,
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
import {
  getPDKGrant,
  patchEnvironment,
  patchPDKGrant,
} from "./repo/environments";
import {
  getServiceTokenByIdHash,
  insertServiceToken,
  patchServiceToken,
} from "./repo/tokens";
import * as bundleModule from "./bundle";

/**
 * A token's sealed name and id, as `createServiceToken` now requires. Opaque
 * to the server, so any well-formed hex of the right widths will do here: a
 * 20 byte name ciphertext, a 32 byte id ciphertext (16 + the tag), 12 byte
 * nonces.
 */
const TOKEN_META = {
  nameCiphertext: "ab".repeat(20),
  nameNonce: "0c0b0a090807060504030201",
  tokenIdCiphertext: "cd".repeat(32),
  tokenIdNonce: "1c1b1a191817161514131211",
  target: "server",
} as const;

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
  // The key version the wrap above was made under, which the client states
  // and `createEnvironment` checks: a new environment starts at 1.
  pdkVersion: 1,
} as const;

type Harness = ReturnType<typeof convexTest>;
type Actor = {
  userId: Id<"users">;
  // The permanent id, for building associated data and for asserting on
  // what a handler returns. Never passed as an argument for the same reason
  // `userId` is not.
  uid: string;
  sessionToken: string;
};

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
  const uid = newId("usr");
  const userId = await t.run(async (ctx) =>
    insertUser(ctx, {
      uid,
      accountSalt: "30".repeat(16),
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
  return { userId, uid, sessionToken };
}

async function tenant(t: Harness, actor: Actor, slug: string) {
  const keys = mintToken({ environment: "revocation" });
  const orgId = await t.mutation(api.orgs.createOrg, {
    sessionToken: actor.sessionToken,
    orgUid: newId("org"),
    name: "Acme Rockets",
    slug,
    revocationPublicKey: keys.upload.publicKey,
    wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  });
  const projectId = await t.mutation(api.projects.createProject, {
    sessionToken: actor.sessionToken,
    orgId,
    name: "API",
    slug: "api",
  });
  const productionUid = newId("env");
  const stagingUid = newId("env");
  const production = await t.mutation(api.environments.createEnvironment, {
    sessionToken: actor.sessionToken,
    environmentUid: productionUid,
    projectId,
    name: "production",
    ...WRAP,
  });
  const staging = await t.mutation(api.environments.createEnvironment, {
    sessionToken: actor.sessionToken,
    environmentUid: stagingUid,
    projectId,
    name: "staging",
    ...WRAP,
  });
  return {
    keys,
    orgId,
    projectId,
    production,
    staging,
    productionUid,
    stagingUid,
  };
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
    // Minted by the client, as the dashboard mints it, and stated at the only
    // version a new secret has.
    secretUid: newId("sec"),
    version: 1,
    pdkVersion: 1,
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
    ...TOKEN_META,
    environmentId,
    tokenId: minted.upload.tokenId,
    publicKey: minted.upload.publicKey,
    wrappedPDK: "cc".repeat(48),
    pdkNonce: "0102030405060708090a0b0c",
    pdkVersion: 1,
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

// `secretUid` and `version` are the slot each row was sealed under, and the
// SDK rebuilds the associated data from them. `secretId`, a Convex document
// id, is deliberately absent: see the note on `secretShape` in `bundle.ts`.
const SECRET_FIELDS = [
  "nameCiphertext",
  "nameNonce",
  "pdkVersion",
  "secretUid",
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

    expect(bundle.environmentUid).toBe(acme.productionUid);
    expect(bundle.secrets.map((secret) => secret.secretUid)).toEqual([
      mine.secretUid,
    ]);
    // Not merely "the other rows are absent": nothing about the sibling
    // environment or the other tenant appears anywhere in the payload.
    const serialised = JSON.stringify(bundle);
    expect(serialised).not.toContain(acme.staging);
    expect(serialised).not.toContain(acme.stagingUid);
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
      version: 2,
      pdkVersion: 1,
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

    expect(
      bundle.secrets
        .map((secret) => `${secret.secretUid}@${secret.version}`)
        .sort(),
    ).toEqual(
      [`${kept.secretUid}@1`, `${replaced.secretUid}@2`].sort(),
    );
    // The new version kept the secret's permanent id.
    expect(updated.secretUid).toBe(replaced.secretUid);
    // The superseded row's ciphertext must not travel either: a workload that
    // installed both versions of one secret would have no way to tell which
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

  it("changes the wrapped PDK a token receives when the key is re-wrapped", async () => {
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
    expect(before.pdkVersion).toBe(1);

    // A re-key: the environment's epoch and key version move and the project
    // data key is re-wrapped for the token, in one transaction. Every half,
    // because a bumped version with a stale wrapped key hands the token a blob
    // that opens a key the stored ciphertext is no longer under.
    const hash = tokenIdHash({ tokenId: minted.tokenId });
    await t.run(async (ctx) => {
      const grant = await getPDKGrant(ctx, acme.production, "token", hash);
      if (grant === null) throw new Error("fixture did not write the grant");
      await patchEnvironment(ctx, acme.production, { epoch: 1, pdkVersion: 2 });
      await patchPDKGrant(ctx, grant._id, {
        wrappedPDK: "ee".repeat(48),
        nonce: "aabbccddeeff001122334455",
        pdkVersion: 2,
      });
    });

    const after = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(after.epoch).toBe(1);
    expect(after.wrappedPDK).toBe("ee".repeat(48));
    expect(after.pdkNonce).toBe("aabbccddeeff001122334455");
    expect(after.pdkVersion).toBe(2);
  });

  /**
   * THE WRAPPED KEY COMES OFF THE GRANT AND THE VERSION COMES OFF THE SAME ROW.
   *
   * Reporting `environments.pdkVersion` beside a wrapped key from `pdkGrants`
   * would be two rows describing one key, free to disagree, which is the whole
   * reason `serviceTokens.wrappedPDK` was deleted. Mid re-key they DO disagree,
   * and the answer a client can act on is the version of the key it was handed.
   */
  it("reports the version of the key it hands over, not the environment's", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    const { bundleToken } = await issueAndHandshake(t, alice, acme.production);

    // The environment moves on; this token has not been re-wrapped yet.
    await t.run(async (ctx) =>
      patchEnvironment(ctx, acme.production, { pdkVersion: 7 }),
    );

    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });
    expect(bundle.pdkVersion).toBe(1);
    expect(bundle.wrappedPDK).toBe("cc".repeat(48));
  });

  /**
   * RULE ONE, APPLIED TO A MISSING GRANT.
   *
   * A token with no grant cannot open anything, and the reflex is to refuse the
   * bundle. That reflex is the bug: refusing also withholds the signed
   * revocation notice, so a token whose grant vanished could never be told it
   * was revoked, which is the one failure this product cannot have.
   */
  it("still delivers the revocation notice when there is no grant", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");

    // A token row with no grant beside it. `createServiceToken` cannot produce
    // this state, which is the point: it is written through the repository so
    // the query is exercised against the state a future writer could leave
    // behind rather than against the one the current writer happens to produce.
    const minted = mintToken({ environment: "production" });
    const hash = tokenIdHash({ tokenId: minted.tokenId });
    const serviceTokenId = await t.run(async (ctx) =>
      insertServiceToken(ctx, {
        environmentId: acme.production,
        orgId: acme.orgId,
        tokenIdHash: hash,
        publicKey: minted.upload.publicKey,
        epoch: 0,
        status: "active",
      }),
    );

    const payload = {
      tokenId: minted.upload.tokenId,
      epoch: 1,
      revokedAt: 1_800_000_000_000,
      reason: "Grant removed.",
    };
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...payload,
      signature: toHex(signRevocation(acme.keys.authSeed, payload)),
    });

    const bundle = await t.query(api.bundle.getBundle, {
      token: signBundleToken({
        subject: serviceTokenId,
        now: Date.now(),
      }),
    });
    expect(bundle.wrappedPDK).toBeUndefined();
    expect(bundle.pdkNonce).toBeUndefined();
    expect(bundle.pdkVersion).toBeUndefined();
    expect(bundle.revocationNotice?.epoch).toBe(1);
    expect(bundle.revocationNotice?.reason).toBe("Grant removed.");
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
      "environmentUid",
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

  /**
   * THE PERMANENT ID REPLACES THE DOCUMENT ID, IT DOES NOT JOIN IT.
   *
   * The client builds the secret associated data from whatever environment
   * identifier the bundle hands it. Handing it the Convex id as well would
   * leave the deployment-local value one typo away from being bound into
   * ciphertext, so the declared return type must not carry it and the payload
   * must not contain it anywhere.
   */
  it("serves the environment's permanent id and never its Convex id", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    await addSecret(t, alice, acme.production);
    const { bundleToken } = await issueAndHandshake(t, alice, acme.production);

    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });

    expect(bundle.environmentUid).toBe(acme.productionUid);
    expect(Object.keys(bundle)).not.toContain("environmentId");
    expect(JSON.stringify(bundle)).not.toContain(acme.production);

    const returns = JSON.parse(
      (bundleModule.getBundle as unknown as { exportReturns: () => string }).exportReturns(),
    ) as { value: Record<string, unknown> };
    expect(Object.keys(returns.value)).not.toContain("environmentId");
    expect(Object.keys(returns.value)).toContain("environmentUid");
  });

  /**
   * EVERY INPUT TO THE ASSOCIATED DATA, AND NOTHING DEPLOYMENT-LOCAL.
   *
   * The SDK opens each row under `secretAssociatedData({ environmentUid,
   * secretUid, version, field })` and the grant under `pdkAssociatedData({
   * environmentUid, pdkVersion, ... })`, so the bundle must carry exactly what
   * the client sealed under. And it must NOT carry the secret's Convex
   * document id: it is not in the associated data, and a client holding it is
   * one confusion away from treating it as the secret's identity.
   */
  it("carries each row's secretUid and version and the grant's pdkVersion, and no secretId", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const acme = await tenant(t, alice, "acme");
    const created = await addSecret(t, alice, acme.production, "11".repeat(40));
    const updated = await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: created.secretId,
      version: 2,
      pdkVersion: 1,
      nameCiphertext: NAME_CIPHERTEXT,
      valueCiphertext: "44".repeat(40),
      ...freshNonces(),
    });
    const { bundleToken } = await issueAndHandshake(t, alice, acme.production);

    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });

    expect(bundle.pdkVersion).toBe(1);
    expect(bundle.secrets).toHaveLength(1);
    expect(bundle.secrets[0]?.secretUid).toBe(created.secretUid);
    expect(bundle.secrets[0]?.secretUid).toMatch(/^sec_[0-9a-f]{32}$/);
    expect(bundle.secrets[0]?.version).toBe(2);

    // Neither document id, nor the field name, anywhere in the payload.
    const serialised = JSON.stringify(bundle);
    expect(serialised).not.toContain("secretId");
    expect(serialised).not.toContain(created.secretId);
    expect(serialised).not.toContain(updated.secretId);

    // And the declared return type agrees with the value.
    const returns = JSON.parse(
      (bundleModule.getBundle as unknown as { exportReturns: () => string }).exportReturns(),
    );
    const declared = JSON.stringify(returns);
    expect(declared).not.toContain('"secretId"');
    expect(declared).toContain('"secretUid"');
    expect(declared).toContain('"pdkVersion"');
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
    expect(bundle.environmentUid).toBe(acme.stagingUid);
    expect(bundle.secrets).toEqual([]);

    const own = await t.query(api.bundle.getBundle, {
      token: first.bundleToken,
    });
    expect(own.secrets.map((secret) => secret.secretUid)).toEqual([mine.secretUid]);
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
