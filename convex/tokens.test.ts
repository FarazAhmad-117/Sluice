import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import { mintToken, signRevocation, toHex, tokenIdHash } from "@sluice/crypto";
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
} from "./repo/tokens";
import {
  getPDKGrant,
  listPDKGrantsByEnvironment,
} from "./repo/environments";
import { listAuditEventsByActor } from "./repo/audit";
import { insertOrgMember } from "./repo/orgs";
import * as tokensModule from "./tokens";

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
type Actor = { userId: Id<"users">; sessionToken: string };

const NOT_PERMITTED = "Not found, or you do not have access to it.";

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
 * One tenant, built through the real public API, with a REAL organisation
 * revocation keypair. `mintToken` hands back an Ed25519 seed and its public
 * key, which is exactly the pair `signRevocation` and `verifyRevocation` want,
 * so nothing here reaches past `@sluice/crypto` for a curve primitive.
 */
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
  const environmentId = await t.mutation(api.environments.createEnvironment, {
    sessionToken: actor.sessionToken,
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
    environmentId,
    tokenId: minted.upload.tokenId,
    publicKey: minted.upload.publicKey,
    wrappedPDK: "cc".repeat(48),
    pdkNonce: "0102030405060708090a0b0c",
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
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
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
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
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
   * Which project data key version the blob opens is copied off the environment
   * row, exactly as `secrets.ts` copies it, and is not an argument. A caller
   * that could choose it could label a stale wrap as current.
   */
  it("records the environment's pdkVersion and never one the caller chose", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const { environmentId } = await tenant(t, alice, "acme");
    const { minted } = await issue(t, alice, environmentId);

    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "token", tokenIdHash({ tokenId: minted.tokenId })),
    );
    expect(grant?.pdkVersion).toBe(1);

    const args = JSON.parse(
      (
        tokensModule.createServiceToken as unknown as { exportArgs: () => string }
      ).exportArgs(),
    ) as { value: Record<string, unknown> };
    expect(Object.keys(args.value)).not.toContain("pdkVersion");
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
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
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
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
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
        environmentId,
        tokenId: minted.upload.tokenId,
        publicKey: minted.upload.publicKey,
        wrappedPDK: "cc".repeat(48),
        pdkNonce: "0102030405060708090a0b0c",
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
