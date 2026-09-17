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
import { listAuditEventsByActor } from "./repo/audit";

export const modules = import.meta.glob("./**/*.ts");

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
