import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { convexTest } from "convex-test";
import {
  MasterUnlockKey,
  mintToken,
  newId,
  pdkAssociatedData,
  randomBytes,
  seal,
  signHandshake,
  toHex,
  tokenIdHash,
} from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";

/**
 * THE DASHBOARD THAT WRITES AND THE CLI THAT READS, IMPORTED UNCHANGED.
 *
 * Reached by relative path, as `secrets.test.ts` reaches the dashboard, because
 * neither `apps/admin` nor the CLI's internals are packages this workspace
 * project depends on. The alternative is re-implementing either half here,
 * which would prove this file agrees with itself.
 */
import { createRevocationKeypair, wrapRevocationKey } from "../apps/admin/src/lib/orgs/revocation-key";
import {
  createProjectDataKey,
  unwrapProjectDataKey,
  wrapProjectDataKey,
} from "../apps/admin/src/lib/secrets/pdk";
import type { EnvironmentKey } from "../apps/admin/src/lib/secrets/pdk";
import { newSecretSlot, sealSecret } from "../apps/admin/src/lib/secrets/seal";
import { decryptSecrets, readRevocation } from "../packages/cli/src/bundle";
import { TokenIdentity } from "../packages/cli/src/config";

export const modules = import.meta.glob("./**/*.ts");

/**
 * THE BUNDLE CONTRACT, CHECKED BY RUNNING BOTH ENDS OF IT.
 *
 * `bundle.getBundle` is written here and read in `packages/cli/src/bundle.ts`,
 * and the two are kept in step by a comment on each side saying "exactly the
 * shape the other returns". A comment is a promise, not a check. Every other
 * test of either side feeds it a bundle that side's own author built, so a
 * field renamed on one side and not the other (`environmentId` to
 * `environmentUid`, `secretId` to `secretUid`, a grant field made optional, a
 * version rendered as a string) passes both suites and fails at a customer's
 * first `sluice run`, as "the bundle did not have the shape this build
 * understands" or, worse, as an AEAD rejection that reads like tampering.
 *
 * So this test produces a bundle with NOTHING hand-built on the server side of
 * the line: the org, the environment and the secret are created through the
 * real mutations with the DASHBOARD'S own wrap and seal; the service token is
 * registered through the real `createServiceToken` and authenticated through
 * the real `/handshake` endpoint; and the bundle is the real `getBundle`'s
 * answer to the credential that handshake issued. That answer is handed,
 * untouched, to the REAL CLI reader, `decryptSecrets`, with the CLI's own
 * `TokenIdentity` parsed from the token string a customer would paste.
 *
 * WHY IT LIVES HERE, in `convex/` beside `bundle.test.ts`, rather than in
 * `packages/cli/test`. Driving the real backend needs `convex-test`, the
 * `_generated` API, the module glob and the edge runtime Convex functions run
 * in, and this workspace project is the one that has all four configured.
 * Putting it in the CLI package would make the CLI's test suite depend on the
 * backend's tree and test harness, which the CLI otherwise does not; putting
 * it here only adds a relative import of two CLI source files, the same
 * direction `secrets.test.ts` already imports the dashboard. It obeys
 * `repo/repo.test.ts`: nothing here reaches the database except through
 * `repo/`, which is how the two seeded rows are written, like every other
 * fixture.
 *
 * WHAT IS NOT REAL, and why that does not weaken the contract. The creator's
 * master unlock key is random bytes rather than an Argon2id derivation, because
 * the contract under test starts after login and `secrets.test.ts` already
 * pays for one real derivation. The user and session rows are seeded through
 * `repo/` for the same reason. The token's grant is wrapped with
 * `pdkAssociatedData` and `seal` from `@sluice/crypto` directly, because the
 * dashboard has no token-issuing code yet; those are the package functions
 * any issuer must call, and nothing here computes associated data by hand.
 */

const SIGNING_KEY =
  "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

beforeEach(() => {
  process.env.JWT_SIGNING_KEY = SIGNING_KEY;
  // Frozen for the reason `bundle.test.ts` gives: the handshake's acceptance
  // window is measured against server time read after the test read its own,
  // and a stopped clock keeps a slow machine from turning that into a flake.
  vi.useFakeTimers();
  vi.setSystemTime(Date.parse("2026-09-18T12:00:00.000Z"));
});

afterEach(() => {
  vi.useRealTimers();
  delete process.env.JWT_SIGNING_KEY;
});

describe("the bundle contract between the backend and the CLI", () => {
  it("decrypts, in the real CLI reader, a secret the real backend serves", async () => {
    const t = convexTest(schema, modules);

    // ---- A signed-in user, seeded through repo/. ---------------------------
    const userUid = newId("usr");
    const sessionToken = "session-for-contract";
    const userId = await t.run(async (ctx) =>
      insertUser(ctx, {
        uid: userUid,
        accountSalt: toHex(randomBytes(16)),
        email: normaliseEmail("founder@example.test"),
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
    const muk = new MasterUnlockKey(randomBytes(32));

    // ---- Org, project and environment, as the dashboard creates them. ------
    const orgUid = newId("org");
    const revocation = createRevocationKeypair();
    const orgId = await t.mutation(api.orgs.createOrg, {
      sessionToken,
      orgUid,
      name: "Acme Rockets",
      slug: "acme-rockets",
      revocationPublicKey: revocation.revocationPublicKey,
      ...(await wrapRevocationKey(muk, revocation.privateKey, {
        orgUid,
        granteeUid: userUid,
      })),
    });
    const projectId = await t.mutation(api.projects.createProject, {
      sessionToken,
      orgId,
      name: "API",
      slug: "api",
    });
    const environmentUid = newId("env");
    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken,
      environmentUid,
      projectId,
      name: "production",
      pdkVersion: 1,
      ...(await wrapProjectDataKey(muk, createProjectDataKey(), {
        environmentUid,
        pdkVersion: 1,
        granteeType: "user",
        granteeId: userUid,
      })),
    });

    // The key as the dashboard holds it: opened from what the server returns.
    const environment = await t.query(api.environments.getEnvironment, {
      sessionToken,
      environmentId,
    });
    const grant = await t.query(api.environments.getMyPdkGrant, {
      sessionToken,
      environmentId,
    });
    const key: EnvironmentKey = {
      pdk: await unwrapProjectDataKey(
        muk,
        { wrappedPDK: grant.wrappedPDK, nonce: grant.nonce },
        {
          environmentUid: environment.uid,
          pdkVersion: grant.pdkVersion,
          granteeType: "user",
          granteeId: userUid,
        },
      ),
      environmentUid: environment.uid,
      pdkVersion: grant.pdkVersion,
    };

    // ---- A secret, sealed by the dashboard's own sealer. -------------------
    const NAME = "DATABASE_URL";
    const VALUE = "postgres://app:hunter2@db.internal:5432/production";
    const slot = newSecretSlot();
    await t.mutation(api.secrets.createSecret, {
      sessionToken,
      environmentId,
      secretUid: slot.secretUid,
      version: slot.version,
      pdkVersion: key.pdkVersion,
      ...(await sealSecret(key, { ...slot, name: NAME, value: VALUE })),
    });

    // ---- A service token, issued and authenticated through the real path. --
    // The grant is bound to the environment's uid, its CURRENT key version and
    // the token id hash, which is the slot `getBundle` will name and the CLI
    // will rebuild.
    const minted = mintToken({ environment: "production" });
    const tokenWrap = await seal(
      minted.unwrapKey,
      key.pdk,
      pdkAssociatedData({
        environmentUid: environment.uid,
        pdkVersion: environment.pdkVersion,
        granteeType: "token",
        granteeId: tokenIdHash({ tokenId: minted.tokenId }),
      }),
    );
    await t.mutation(api.tokens.createServiceToken, {
      sessionToken,
      environmentId,
      tokenId: minted.upload.tokenId,
      publicKey: minted.upload.publicKey,
      wrappedPDK: toHex(tokenWrap.ciphertext),
      pdkNonce: toHex(tokenWrap.nonce),
      pdkVersion: environment.pdkVersion,
    });

    const unixSeconds = Math.floor(Date.now() / 1000);
    const response = await t.fetch("/handshake", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tokenId: minted.upload.tokenId,
        unixSeconds,
        signature: toHex(signHandshake(minted.tokenId, minted.tokenSecret, unixSeconds)),
      }),
    });
    expect(response.status).toBe(200);
    const { token: bundleToken } = (await response.json()) as { token: string };

    // ---- The real bundle, into the real reader. -----------------------------
    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });

    // The identity the CLI builds from the string a customer pastes into
    // `SLUICE_TOKEN`, not one assembled from `minted`'s fields.
    const identity = TokenIdentity.fromToken(minted.token);

    // No notice for a token nobody revoked, read the way the shell reads it:
    // first, without a key, before anything is decrypted.
    expect(readRevocation(bundle)).toBeUndefined();

    const opened = await decryptSecrets(identity, bundle);
    expect(opened.secrets).toEqual({ [NAME]: VALUE });
    expect(opened.epoch).toBe(bundle.epoch);
  });
});
