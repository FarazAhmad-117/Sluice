import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import { mintToken, newId, signRevocation, toHex, tokenIdHash } from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import {
  getServiceToken,
  getServiceTokenByIdHash,
  listRevocationsByTokenIdHash,
  listRevocationsByTokenId,
  patchServiceToken,
} from "./repo/tokens";
import {
  getPDKGrant,
  listPDKGrantsByEnvironment,
  patchEnvironment,
} from "./repo/environments";
import { listAuditEventsByActor } from "./repo/audit";
import { insertOrgMember } from "./repo/orgs";
import * as tokensModule from "./tokens";
// The dashboard's mapping of refused writes, imported unchanged by relative
// path as `secrets.test.ts` imports the dashboard. See the re-key test below.
import {
  STALE_ENVIRONMENT_KEY,
  describeWriteFailure,
} from "../apps/admin/src/lib/secrets/write-errors";

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

const NOT_PERMITTED = "Not found, or you do not have access to it.";

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

/**
 * One tenant, built through the real public API, with a REAL organisation
 * revocation keypair. `mintToken` hands back an Ed25519 seed and its public
 * key, which is exactly the pair `signRevocation` and `verifyRevocation` want,
 * so nothing here reaches past `@sluice/crypto` for a curve primitive.
 */
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
  const environmentId = await t.mutation(api.environments.createEnvironment, {
    sessionToken: actor.sessionToken,
    environmentUid: newId("env"),
    projectId,
    name: "production",
    ...WRAP,
  });
  return { keys, orgId, projectId, environmentId };
}

async function issue(
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
  return { minted, serviceTokenId };
}

function notice(tokenId: string, overrides: Record<string, unknown> = {}) {
  return {
    tokenId,
    epoch: 1,
    revokedAt: 1_800_000_000_000,
    reason: "Rotated on schedule.",
    ...overrides,
  } as { tokenId: string; epoch: number; revokedAt: number; reason: string };
}

describe("createServiceToken", () => {
  it("stores the hash from @sluice/crypto and never the plaintext id", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const { minted, serviceTokenId } = await issue(t, alice, environmentId);

    const row = await t.run(async (ctx) => getServiceToken(ctx, serviceTokenId));
    expect(row?.tokenIdHash).toBe(tokenIdHash({ tokenId: minted.tokenId }));
    // The whole point of the column. Nothing on this row is the id itself.
    expect(JSON.stringify(row)).not.toContain(minted.upload.tokenId);
    expect(row?.status).toBe("active");
  });

  it("stores the sealed name and id, the target, and who created it", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const { serviceTokenId } = await issue(t, alice, environmentId);

    const row = await t.run(async (ctx) => getServiceToken(ctx, serviceTokenId));
    expect(row).toMatchObject({
      nameCiphertext: TOKEN_META.nameCiphertext,
      nameNonce: TOKEN_META.nameNonce,
      tokenIdCiphertext: TOKEN_META.tokenIdCiphertext,
      tokenIdNonce: TOKEN_META.tokenIdNonce,
      target: "server",
      // Off the environment, as the grant's version is.
      metaPdkVersion: 1,
      // From the session. There is no argument that could set it.
      createdBy: alice.userId,
    });
  });

  it("refuses sealed metadata of the wrong shape, and writes nothing", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const minted = mintToken({ environment: "production" });
    const good = {
      sessionToken: alice.sessionToken,
      environmentId,
      tokenId: minted.upload.tokenId,
      publicKey: minted.upload.publicKey,
      wrappedPDK: "cc".repeat(48),
      pdkNonce: "0102030405060708090a0b0c",
      pdkVersion: 1,
      ...TOKEN_META,
    };

    for (const [bad, message] of [
      // A sealed 16 byte id is exactly 32 bytes; 31 or 33 is not this id.
      [{ tokenIdCiphertext: "cd".repeat(31) }, undefined],
      [{ tokenIdCiphertext: "cd".repeat(33) }, undefined],
      // An empty name seals to the tag alone.
      [{ nameCiphertext: "ab".repeat(16) }, undefined],
      [{ nameCiphertext: "ab".repeat(64 + 16 + 1) }, "Token names can be up to 64 characters."],
      [{ nameNonce: "0c0b0a09080706050403020" }, undefined],
      [{ tokenIdNonce: "" }, undefined],
      [{ target: "laptop" }, undefined],
    ] as const) {
      const attempt = t.mutation(api.tokens.createServiceToken, { ...good, ...(bad as object) } as typeof good);
      if (message === undefined) await expect(attempt).rejects.toThrow();
      else await expect(attempt).rejects.toThrow(message);
    }
    const left = await t.run(async (ctx) => getServiceTokenByIdHash(ctx, tokenIdHash({ tokenId: minted.tokenId })));
    expect(left).toBeNull();

    // At the limit is accepted.
    await t.mutation(api.tokens.createServiceToken, { ...good, nameCiphertext: "ab".repeat(64 + 16) });
  });

  it("refuses a second token with the same id", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    // `by_token_id_hash` is read with `.unique()` on the handshake path, so a
    // duplicate would not merely be wrong, it would make every handshake for
    // that token THROW and take it offline.
    await expect(
      t.mutation(api.tokens.createServiceToken, {
        sessionToken: alice.sessionToken,
        ...TOKEN_META,
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
        pdkVersion: 1,
      }),
    ).rejects.toThrow("already exists");
  });

  it("refuses a caller who is not a member of the environment's org", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    await tenant(t, mallory, "mallory-co");

    const minted = mintToken({ environment: "production" });
    await expect(
      t.mutation(api.tokens.createServiceToken, {
        sessionToken: mallory.sessionToken,
        ...TOKEN_META,
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
        pdkVersion: 1,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("refuses non-canonical material", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const minted = mintToken({ environment: "production" });

    const good = {
      sessionToken: alice.sessionToken,
      environmentId,
      tokenId: minted.upload.tokenId,
      publicKey: minted.upload.publicKey,
      wrappedPDK: "cc".repeat(48),
      pdkNonce: "0102030405060708090a0b0c",
      pdkVersion: 1,
      ...TOKEN_META,
    };

    for (const bad of [
      { tokenId: minted.upload.tokenId.toUpperCase() },
      { tokenId: "ab".repeat(15) },
      { publicKey: "ab".repeat(31) },
      { pdkNonce: "0102030405060708090a0b" },
      { wrappedPDK: "" },
      { expiresAt: 1.5 },
    ]) {
      await expect(
        t.mutation(api.tokens.createServiceToken, { ...good, ...bad }),
      ).rejects.toThrow();
    }
  });
});

/**
 * ONE HOME FOR A TOKEN'S WRAPPED PROJECT DATA KEY, AND IT IS `pdkGrants`.
 *
 * `serviceTokens` used to carry `wrappedPDK` and `nonce` of its own while
 * `pdkGrants` existed for the same purpose with a `granteeType` of `"token"`
 * already in its union. Two authoritative homes for one blob, with nothing that
 * fails when they disagree, is the defect class that produced the duplicate
 * associated-data definition. These assertions are what stop the column coming
 * back.
 */
describe("a token's wrapped project data key", () => {
  it("lands in pdkGrants and leaves no copy on the service token row", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const { minted, serviceTokenId } = await issue(t, alice, environmentId);

    const row = await t.run(async (ctx) => getServiceToken(ctx, serviceTokenId));
    // Structural, against the stored document rather than against a type. A
    // column added back later fails here before anything can read the wrong
    // one of the two.
    expect(Object.keys(row ?? {})).not.toContain("wrappedPDK");
    expect(Object.keys(row ?? {})).not.toContain("nonce");

    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "token", tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(grant?.wrappedPDK).toBe("cc".repeat(48));
    expect(grant?.nonce).toBe("0102030405060708090a0b0c");
  });

  // The same invariant `createSecret` enforces: the copied org must be the
  // walked org, or nothing is written.
  it("refuses to register a token when the environment's org link is corrupt", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const other = await tenant(t, mallory, "other");
    await t.run(async (ctx) =>
      patchEnvironment(ctx, environmentId, { orgId: other.orgId }),
    );

    const minted = mintToken({ environment: "production" });
    await expect(
      t.mutation(api.tokens.createServiceToken, {
        sessionToken: alice.sessionToken,
        ...TOKEN_META,
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
        pdkVersion: 1,
      }),
    ).rejects.toThrow("This record's organisation link is inconsistent. Nothing was written.");

    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    expect(grants.map((g) => g.granteeType)).toEqual(["user"]);
  });

  // Off the environment row the authorisation walk loaded, on both rows the
  // mutation writes, and not an argument a caller could set.
  it("records the environment's org on the token row and on its grant", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const { orgId, environmentId } = await tenant(t, alice, "acme");
    const other = await tenant(t, mallory, "other");
    const { minted, serviceTokenId } = await issue(t, alice, environmentId);

    const row = await t.run(async (ctx) => getServiceToken(ctx, serviceTokenId));
    expect(row?.orgId).toBe(orgId);
    expect(row?.orgId).not.toBe(other.orgId);

    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "token", tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(grant?.orgId).toBe(orgId);

    const args = JSON.parse(
      (
        tokensModule.createServiceToken as unknown as {
          exportArgs: () => string;
        }
      ).exportArgs(),
    ) as { value: Record<string, unknown> };
    expect(Object.keys(args.value)).not.toContain("orgId");
  });

  /**
   * The grantee id for a token is its `tokenIdHash` and NOT its `serviceTokens`
   * document id, for two reasons that both have to hold.
   *
   * The bundle knows an authenticated token only by its hash, so the hash is
   * what the lookup has. And the CLIENT has to compute the same identifier to
   * build the associated data it wraps under, before the document exists: it
   * mints the token, so it can compute the hash and cannot know the id.
   */
  it("is keyed by tokenIdHash, the one identifier both ends can compute", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const { minted, serviceTokenId } = await issue(t, alice, environmentId);

    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    const forToken = grants.filter((g) => g.granteeType === "token");
    expect(forToken).toHaveLength(1);
    expect(forToken[0]?.granteeId).toBe(tokenIdHash({ tokenId: minted.tokenId }));
    expect(forToken[0]?.granteeId).not.toBe(serviceTokenId);
    expect(JSON.stringify(forToken)).not.toContain(minted.upload.tokenId);
  });

  /**
   * Which project data key version the blob opens is the environment's
   * current one, and the client must STATE the version it wrapped under so the
   * server can check the two agree. A caller cannot make the column say
   * anything else: a mismatch is refused, it is never stored.
   */
  it("records the environment's pdkVersion, which the caller must state exactly", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "token", tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(grant?.pdkVersion).toBe(1);
  });

  /**
   * THE COMPARE-AND-SET. The client wrapped the token's grant under
   * `pdkAssociatedData` naming the key version it opened. If the environment
   * has been re-keyed since, the wrap names a version the grant would not be
   * stored under and the workload would fail at boot with a bare AEAD
   * rejection. Refused, with neither a token row nor a grant written.
   */
  it("refuses a pdkVersion that is not the environment's current one, writing nothing", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    // A re-key happened after the client opened the environment at version 1.
    await t.run(async (ctx) =>
      patchEnvironment(ctx, environmentId, { pdkVersion: 2 }),
    );

    const minted = mintToken({ environment: "production" });
    for (const pdkVersion of [1, 3, 0]) {
      await expect(
        t.mutation(api.tokens.createServiceToken, {
          sessionToken: alice.sessionToken,
          ...TOKEN_META,
          environmentId,
          tokenId: minted.upload.tokenId,
          publicKey: minted.upload.publicKey,
          wrappedPDK: "cc".repeat(48),
          pdkNonce: "0102030405060708090a0b0c",
          pdkVersion,
        }),
      ).rejects.toThrow(
        "This environment's key changed since you opened it. Reload and try again.",
      );
    }

    // The dashboard recognises this exact refusal and offers a reload, so the
    // token form that does not exist yet inherits the mapping the secret forms
    // have. The sentence is not exported from `tokens.ts`, so it is pinned by
    // provoking the real refusal and handing it to the real mapping: if either
    // side rewords it, this fails instead of a future form swallowing it.
    const refusal = await t
      .mutation(api.tokens.createServiceToken, {
        sessionToken: alice.sessionToken,
        ...TOKEN_META,
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
        pdkVersion: 1,
      })
      .then(
        () => null,
        (cause: unknown) => cause,
      );
    expect(describeWriteFailure(refusal)).toEqual({
      message: STALE_ENVIRONMENT_KEY,
      reload: true,
    });

    const hash = tokenIdHash({ tokenId: minted.tokenId });
    expect(
      await t.run(async (ctx) => getServiceTokenByIdHash(ctx, hash)),
    ).toBeNull();
    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    expect(grants.filter((g) => g.granteeType === "token")).toEqual([]);

    // And the current version is accepted, and stored, so the check above is
    // not one that refuses everything.
    await t.mutation(api.tokens.createServiceToken, {
      sessionToken: alice.sessionToken,
      ...TOKEN_META,
      environmentId,
      tokenId: minted.upload.tokenId,
      publicKey: minted.upload.publicKey,
      wrappedPDK: "cc".repeat(48),
      pdkNonce: "0102030405060708090a0b0c",
      pdkVersion: 2,
    });
    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "token", hash),
    );
    expect(grant?.pdkVersion).toBe(2);
  });

  /**
   * The same atomicity argument `createOrg` makes for its revocation grant. A
   * token registered without a grant is a token that can never open a secret,
   * and nothing would error at any point.
   */
  it("is written in the same transaction, so a refused create leaves no grant", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const { environmentId } = await tenant(t, alice, "acme");

    const minted = mintToken({ environment: "production" });
    await expect(
      t.mutation(api.tokens.createServiceToken, {
        sessionToken: mallory.sessionToken,
        ...TOKEN_META,
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
        pdkVersion: 1,
      }),
    ).rejects.toThrow(NOT_PERMITTED);

    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    expect(grants.filter((g) => g.granteeType === "token")).toEqual([]);
  });

  /**
   * MEMBERSHIP AUTHORISED THIS WRITE AND A GRANT IS WHAT MAKES IT MEANINGFUL.
   * BOTH MUST HOLD, and until this test there was only one of them.
   *
   * `requireEnvironment` proves the caller is in the org. It says nothing about
   * whether they hold the project data key, and every SECOND member of an org
   * is in exactly that state today, because nothing wraps an existing key to a
   * new member. Such a member could register a token whose `wrappedPDK` is
   * arbitrary bytes: the row lands, `pdkVersion` is copied off the environment
   * so it claims a real key version, the bundle ships it, the workload boots,
   * and every decrypt fails as a bare AEAD rejection with no indication of
   * which input was wrong -- in production, possibly months later.
   *
   * The server cannot repair it, only refuse it: this deployment has never held
   * the plaintext project data key, so any grant it wrote itself would be a row
   * whose ciphertext is not a key. `secrets.ts` makes the identical check for
   * the identical reason on `createSecret` and `updateSecret`.
   */
  it("refuses a member of the org who holds no key for the environment", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const bob = await seedUser(t, "bob@example.test");
    const { orgId, environmentId } = await tenant(t, alice, "acme");
    // A real member, added the way a second person joins an org. He passes
    // `requireEnvironment` and holds no grant, which is the whole point.
    await t.run(async (ctx) =>
      insertOrgMember(ctx, { orgId, userId: bob.userId, role: "member" }),
    );

    const minted = mintToken({ environment: "production" });
    await expect(
      t.mutation(api.tokens.createServiceToken, {
        sessionToken: bob.sessionToken,
        ...TOKEN_META,
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
        pdkVersion: 1,
      }),
    ).rejects.toThrow("You hold no key for this environment");
  });

  /**
   * THE REFUSAL WRITES NOTHING. A partial create here is worse than the refusal
   * it replaces: a `serviceTokens` row with no grant is a token that
   * authenticates and can open nothing, and an audit trail that records a
   * create which did not happen is an audit trail nobody can trust.
   */
  it("writes no token, no grant and no audit row when the caller holds no key", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const bob = await seedUser(t, "bob@example.test");
    const { orgId, environmentId } = await tenant(t, alice, "acme");
    await t.run(async (ctx) =>
      insertOrgMember(ctx, { orgId, userId: bob.userId, role: "member" }),
    );

    const minted = mintToken({ environment: "production" });
    await expect(
      t.mutation(api.tokens.createServiceToken, {
        sessionToken: bob.sessionToken,
        ...TOKEN_META,
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
        pdkVersion: 1,
      }),
    ).rejects.toThrow();

    // Looked up by the hash, because that is the only identifier the server
    // keeps and the only one the handshake can reach.
    const row = await t.run(async (ctx) =>
      getServiceTokenByIdHash(ctx, tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(row).toBeNull();

    // Alice's own user grant, and nothing else. No token grant was created.
    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    expect(grants.map((g) => g.granteeType)).toEqual(["user"]);

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, bob.userId, 10),
    );
    expect(events).toEqual([]);
  });

  /**
   * The check is on the CALLER'S OWN grant and not on "some grant exists for
   * this environment". Alice holds one and is refused nothing, which is what
   * keeps the guard above from being a guard that refuses everybody.
   */
  it("still admits the member who does hold the key", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const bob = await seedUser(t, "bob@example.test");
    const { orgId, environmentId } = await tenant(t, alice, "acme");
    await t.run(async (ctx) =>
      insertOrgMember(ctx, { orgId, userId: bob.userId, role: "member" }),
    );

    const { minted, serviceTokenId } = await issue(t, alice, environmentId);
    expect(serviceTokenId).toBeDefined();
    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "token", tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(grant).not.toBeNull();
  });
});

describe("revokeServiceToken", () => {
  it("writes both forms of the id and marks the token revoked", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { keys, environmentId } = await tenant(t, alice, "acme");
    const { minted, serviceTokenId } = await issue(t, alice, environmentId);

    const payload = notice(minted.upload.tokenId);
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...payload,
      signature: toHex(signRevocation(keys.authSeed, payload)),
    });

    const hash = tokenIdHash({ tokenId: minted.tokenId });
    const byHash = await t.run(async (ctx) =>
      listRevocationsByTokenIdHash(ctx, hash),
    );
    const byPlaintext = await t.run(async (ctx) =>
      listRevocationsByTokenId(ctx, minted.upload.tokenId),
    );

    // Both indexes must reach the same single row. The plaintext id is what
    // the notice is signed over; the hash is the only handle the bundle has.
    expect(byHash).toHaveLength(1);
    expect(byPlaintext).toHaveLength(1);
    expect(byHash[0]?._id).toBe(byPlaintext[0]?._id);

    const row = await t.run(async (ctx) => getServiceToken(ctx, serviceTokenId));
    expect(row?.status).toBe("revoked");
  });

  // Copied off the token row, so the revocation stays findable by org and
  // attributable to its environment without a walk through the token.
  it("records the token's org and environment on the revocation row", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { keys, orgId, environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    const payload = notice(minted.upload.tokenId);
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...payload,
      signature: toHex(signRevocation(keys.authSeed, payload)),
    });

    const rows = await t.run(async (ctx) =>
      listRevocationsByTokenIdHash(ctx, tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.orgId).toBe(orgId);
    expect(rows[0]?.environmentId).toBe(environmentId);
  });

  // The revocation row is filed under `token.orgId`, which the walk (from
  // `token.environmentId`) never reads. A correctly signed notice still
  // refuses, and the token is left exactly as it was.
  it("refuses to revoke when the token's own org link disagrees with the walk", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const { keys, environmentId } = await tenant(t, alice, "acme");
    const other = await tenant(t, mallory, "other");
    const { minted, serviceTokenId } = await issue(t, alice, environmentId);
    await t.run(async (ctx) =>
      patchServiceToken(ctx, serviceTokenId, { orgId: other.orgId }),
    );

    const payload = notice(minted.upload.tokenId);
    await expect(
      t.mutation(api.tokens.revokeServiceToken, {
        sessionToken: alice.sessionToken,
        ...payload,
        signature: toHex(signRevocation(keys.authSeed, payload)),
      }),
    ).rejects.toThrow("This record's organisation link is inconsistent. Nothing was written.");

    const rows = await t.run(async (ctx) =>
      listRevocationsByTokenIdHash(ctx, tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(rows).toEqual([]);
    const row = await t.run(async (ctx) => getServiceToken(ctx, serviceTokenId));
    expect(row?.status).toBe("active");
  });

  it("refuses a notice this organisation did not sign", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const other = await tenant(t, mallory, "mallory-co");
    const { minted } = await issue(t, alice, environmentId);

    const payload = notice(minted.upload.tokenId);

    // Signed by a different organisation's revocation key. Storing this would
    // mark the token dead in the console while no conforming SDK ever acted on
    // it: a kill switch that reports success and does nothing.
    await expect(
      t.mutation(api.tokens.revokeServiceToken, {
        sessionToken: alice.sessionToken,
        ...payload,
        signature: toHex(signRevocation(other.keys.authSeed, payload)),
      }),
    ).rejects.toThrow("not signed by");

    // And plain garbage.
    await expect(
      t.mutation(api.tokens.revokeServiceToken, {
        sessionToken: alice.sessionToken,
        ...payload,
        signature: "00".repeat(64),
      }),
    ).rejects.toThrow("not signed by");
  });

  it("refuses a notice whose fields were edited after signing", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { keys, environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    const payload = notice(minted.upload.tokenId);
    const signature = toHex(signRevocation(keys.authSeed, payload));

    for (const edit of [
      { epoch: 2 },
      { revokedAt: payload.revokedAt + 1 },
      { reason: "Something else entirely." },
    ]) {
      await expect(
        t.mutation(api.tokens.revokeServiceToken, {
          sessionToken: alice.sessionToken,
          ...payload,
          ...edit,
          signature,
        }),
      ).rejects.toThrow("not signed by");
    }
  });

  it("refuses an epoch at or below one already issued", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { keys, environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    const first = notice(minted.upload.tokenId, { epoch: 4 });
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...first,
      signature: toHex(signRevocation(keys.authSeed, first)),
    });

    // Epochs are globally monotonic per token id and must never reset. A
    // notice at or below one already issued is one an updated SDK will
    // correctly ignore, so storing it would tell an operator a revocation took
    // effect when nothing will act on it.
    for (const epoch of [3, 4]) {
      const replay = notice(minted.upload.tokenId, { epoch });
      await expect(
        t.mutation(api.tokens.revokeServiceToken, {
          sessionToken: alice.sessionToken,
          ...replay,
          signature: toHex(signRevocation(keys.authSeed, replay)),
        }),
      ).rejects.toThrow("already been revoked");
    }

    const higher = notice(minted.upload.tokenId, { epoch: 5 });
    await expect(
      t.mutation(api.tokens.revokeServiceToken, {
        sessionToken: alice.sessionToken,
        ...higher,
        signature: toHex(signRevocation(keys.authSeed, higher)),
      }),
    ).resolves.toBeNull();
  });

  it("refuses an outsider, with the same message as an unknown token id", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const mallory = await seedUser(t, "mallory@example.test");
    const { keys, environmentId } = await tenant(t, alice, "acme");
    await tenant(t, mallory, "mallory-co");
    const { minted } = await issue(t, alice, environmentId);

    const payload = notice(minted.upload.tokenId);
    const signed = {
      ...payload,
      signature: toHex(signRevocation(keys.authSeed, payload)),
    };

    await expect(
      t.mutation(api.tokens.revokeServiceToken, {
        sessionToken: mallory.sessionToken,
        ...signed,
      }),
    ).rejects.toThrow(NOT_PERMITTED);

    // A token id nobody registered gets the identical refusal, so the pair of
    // messages cannot be used to sort candidate ids into registered and not.
    const stranger = mintToken({ environment: "production" });
    const strangerNotice = notice(stranger.upload.tokenId);
    await expect(
      t.mutation(api.tokens.revokeServiceToken, {
        sessionToken: mallory.sessionToken,
        ...strangerNotice,
        signature: toHex(signRevocation(keys.authSeed, strangerNotice)),
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("audits the revocation against the user who signed it", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { keys, environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    const payload = notice(minted.upload.tokenId);
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...payload,
      signature: toHex(signRevocation(keys.authSeed, payload)),
    });

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, alice.userId, 10),
    );
    expect(events.map((event) => event.action)).toContain("token.revoke");
  });

  it("never lets the token row and the revocation disagree about the id", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { keys, environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    const payload = notice(minted.upload.tokenId);
    await t.mutation(api.tokens.revokeServiceToken, {
      sessionToken: alice.sessionToken,
      ...payload,
      signature: toHex(signRevocation(keys.authSeed, payload)),
    });

    // Read the hash off each row rather than recomputing it here, so this
    // compares the two WRITE SITES to each other rather than comparing each of
    // them to a third copy of the construction living in the test.
    const stored = await t.run(async (ctx) =>
      getServiceTokenByIdHash(ctx, tokenIdHash({ tokenId: minted.tokenId })),
    );
    const revocations = await t.run(async (ctx) =>
      listRevocationsByTokenId(ctx, minted.upload.tokenId),
    );
    expect(stored).not.toBeNull();
    expect(revocations[0]?.tokenIdHash).toBe(stored?.tokenIdHash);
  });
});
