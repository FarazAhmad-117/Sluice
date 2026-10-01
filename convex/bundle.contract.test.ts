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
  signRevocation,
  toHex,
  tokenIdHash,
} from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";

/**
 * THE DASHBOARD THAT WRITES, THE CLI THAT READS, AND THE CORE THAT DECIDES,
 * IMPORTED UNCHANGED.
 *
 * Reached by relative path, as `secrets.test.ts` reaches the dashboard, because
 * neither `apps/admin`, the CLI's internals, nor the SDK are packages this
 * workspace project depends on. The SDK is imported from its source entry
 * point, which is exactly the module `@sluice/sdk` resolves to for the CLI
 * (`packages/sdk/package.json` maps `.` to `./src/index.ts`). The alternative
 * is re-implementing any of the three here, which would prove this file agrees
 * with itself.
 */
import {
  createRevocationKeypair,
  unwrapRevocationKey,
  wrapRevocationKey,
} from "../apps/admin/src/lib/orgs/revocation-key";
import {
  createProjectDataKey,
  unwrapProjectDataKey,
  wrapProjectDataKey,
} from "../apps/admin/src/lib/secrets/pdk";
import type { EnvironmentKey } from "../apps/admin/src/lib/secrets/pdk";
import { newSecretSlot, sealSecret } from "../apps/admin/src/lib/secrets/seal";
import { decryptSecrets, readRevocation } from "../packages/cli/src/bundle";
import { TokenIdentity } from "../packages/cli/src/config";
import { NO_PERSISTED_FLOOR, SluiceCore } from "../packages/sdk/src/index";

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
 * THE REVOCATION HALF IS THE ONE THAT CANNOT FAIL LOUDLY, which is why it has a
 * case of its own. `readRevocation` reads `revocationNotice` through an untyped
 * cast and answers `undefined` for anything it does not recognise, BY DESIGN:
 * it must never throw on the path to a shutdown. The price is that a server
 * field renamed or reshaped (`revocationNotice` to `notice`, a signature
 * shipped as bytes instead of hex, an epoch as a string) is indistinguishable,
 * to the CLI, from "this token has not been revoked". No type check catches
 * it and no error is raised: every revoked token simply keeps running. The
 * second case below is the only thing that would notice.
 *
 * So this file produces bundles with NOTHING hand-built on the server side of
 * the line: the org, the environment and the secret are created through the
 * real mutations with the DASHBOARD'S own wrap and seal; the service token is
 * registered through the real `createServiceToken` and authenticated through
 * the real `/handshake` endpoint; the revocation is written through the real
 * `revokeServiceToken`, signed with the seed the dashboard unwraps from the
 * real `getMyRevocationGrant`; and every bundle is the real `getBundle`'s
 * answer to the credential that handshake issued. Each answer is handed,
 * untouched, to the REAL CLI reader, with the CLI's own `TokenIdentity`
 * parsed from the token string a customer would paste, and the notice to the
 * REAL `SluiceCore`, constructed the way `packages/cli/src/run.ts` constructs
 * it, which is where the CLI decides to shut down.
 *
 * WHY IT LIVES HERE, in `convex/` beside `bundle.test.ts`, rather than in
 * `packages/cli/test`. Driving the real backend needs `convex-test`, the
 * `_generated` API, the module glob and the edge runtime Convex functions run
 * in, and this workspace project is the one that has all four configured.
 * Putting it in the CLI package would make the CLI's test suite depend on the
 * backend's tree and test harness, which the CLI otherwise does not; putting
 * it here only adds relative imports of CLI and SDK source files, the same
 * direction `secrets.test.ts` already imports the dashboard. It obeys
 * `repo/repo.test.ts`: nothing here reaches the database except through
 * `repo/`, which is how the two seeded rows are written, like every other
 * fixture.
 *
 * WHAT IS NOT REAL, and why that does not weaken the contract. The creator's
 * master unlock key is random bytes rather than an Argon2id derivation, because
 * the contract under test starts after login and `secrets.test.ts` already
 * pays for one real derivation. The user and session rows are seeded through
 * `repo/` for the same reason. The token's grant is wrapped, and the notice
 * signed, with `@sluice/crypto` directly, because the dashboard has no
 * token-issuing or revocation-signing code yet; those are the package
 * functions any issuer or signer must call, and nothing here computes
 * associated data or a signed message by hand.
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

const NAME = "DATABASE_URL";
const VALUE = "postgres://app:hunter2@db.internal:5432/production";

/**
 * One tenant with one secret and one authenticated service token, every row
 * written through the real mutations with the dashboard's own key handling.
 */
async function provision(t: ReturnType<typeof convexTest>) {
  // ---- A signed-in user, seeded through repo/. -----------------------------
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

  // ---- Org, project and environment, as the dashboard creates them. --------
  const orgUid = newId("org");
  const revocation = createRevocationKeypair();
  const orgId: Id<"orgs"> = await t.mutation(api.orgs.createOrg, {
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

  // ---- A secret, sealed by the dashboard's own sealer. ---------------------
  const slot = newSecretSlot();
  await t.mutation(api.secrets.createSecret, {
    sessionToken,
    environmentId,
    secretUid: slot.secretUid,
    version: slot.version,
    pdkVersion: key.pdkVersion,
    ...(await sealSecret(key, { ...slot, name: NAME, value: VALUE })),
  });

  // ---- A service token, issued and authenticated through the real path. ----
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

  return { sessionToken, muk, orgId, orgUid, userUid, minted, bundleToken };
}

describe("the bundle contract between the backend and the CLI", () => {
  it("decrypts, in the real CLI reader, a secret the real backend serves", async () => {
    const t = convexTest(schema, modules);
    const { minted, bundleToken } = await provision(t);

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

  it("delivers a revocation the real CLI reads and the real core shuts down on", async () => {
    const t = convexTest(schema, modules);
    const { sessionToken, muk, orgId, orgUid, userUid, minted, bundleToken } =
      await provision(t);
    const identity = TokenIdentity.fromToken(minted.token);

    // ---- Sign with the seed the dashboard recovers, not the local one. ----
    // `provision` dropped the keypair on purpose. The only seed here is the
    // one that comes back out of the real grant, opened by the dashboard's own
    // unwrap, which is the only seed a real operator would ever sign with.
    const revocationGrant = await t.query(api.orgs.getMyRevocationGrant, {
      sessionToken,
      orgId,
    });
    expect(revocationGrant.orgUid).toBe(orgUid);
    const seed = await unwrapRevocationKey(
      muk,
      { wrappedRevocationKey: revocationGrant.wrappedRevocationKey, nonce: revocationGrant.nonce },
      { orgUid: revocationGrant.orgUid, granteeUid: userUid },
    );
    const org = await t.query(api.orgs.getOrg, { sessionToken, orgId });

    const notice = {
      tokenId: minted.upload.tokenId,
      epoch: 3,
      revokedAt: Date.now(),
      reason: "Laptop stolen.",
    };
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken,
      ...notice,
      signature: toHex(signRevocation(seed, notice)),
    });

    // ---- The SAME credential, the real query, the real reader. ----------
    // A revoked token is still served, because the notice is how it learns.
    const bundle = await t.query(api.bundle.getBundle, { token: bundleToken });
    const parsed = readRevocation(bundle);
    if (parsed === undefined) {
      // The silent failure this case exists for, named: the server sent a
      // notice the CLI could not read, which to the CLI is no notice at all.
      throw new Error("the CLI read no revocation from a revoked token's bundle");
    }
    expect(parsed.notice).toEqual(notice);
    // The notice names THIS process's token, as the CLI identifies itself.
    expect(parsed.notice.tokenId).toBe(identity.tokenIdHex);

    // ---- The decision, made where the CLI makes it. ----------------------
    // Constructed as `run.ts` constructs it: the org key the customer pins
    // (here, the one the server publishes, which `createOrg` stored from the
    // dashboard's keypair) and the token id from the CLI's own identity.
    // `verifyRevocation` runs inside `SluiceCore`; a notice that did not
    // verify would produce a logged rejection and no shutdown.
    const core = new SluiceCore({
      orgRevocationPublicKey: org.revocationPublicKey,
      tokenId: identity.tokenIdHex,
      initialEpochFloor: NO_PERSISTED_FLOOR,
    });
    core.handle({ type: "boot", cache: null, now: Date.now() });
    const decisions = core.handle({
      type: "revocation",
      notice: parsed.notice,
      signature: parsed.signature,
      now: Date.now(),
    });
    expect(decisions).toContainEqual(
      expect.objectContaining({
        type: "shutdown",
        cause: "revocation",
        epoch: notice.epoch,
        signedReason: notice.reason,
      }),
    );

    // And the shutdown is earned by the signature, not granted to any notice:
    // the same delivered notice, under a core pinned to another org's key,
    // must not shut down. Without this the assertion above could pass for a
    // core that never verified anything.
    const stranger = new SluiceCore({
      orgRevocationPublicKey: createRevocationKeypair().revocationPublicKey,
      tokenId: identity.tokenIdHex,
      initialEpochFloor: NO_PERSISTED_FLOOR,
    });
    stranger.handle({ type: "boot", cache: null, now: Date.now() });
    const refused = stranger.handle({
      type: "revocation",
      notice: parsed.notice,
      signature: parsed.signature,
      now: Date.now(),
    });
    expect(refused.some((decision) => decision.type === "shutdown")).toBe(false);
  });
});
