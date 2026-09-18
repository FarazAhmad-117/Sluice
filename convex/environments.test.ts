import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import { listAuditEventsByActor } from "./repo/audit";
import {
  getPDKGrant,
  listPDKGrantsByEnvironment,
} from "./repo/environments";
import * as environmentsModule from "./environments";

export const modules = import.meta.glob("./**/*.ts");

type Harness = ReturnType<typeof convexTest>;

/**
 * A seeded person. `userId` is for reading rows back in assertions and is
 * never passed to a handler: no handler takes a user id any more. Acting is
 * `sessionToken` and nothing else.
 */
type Actor = { userId: Id<"users">; sessionToken: string };

/**
 * Seeded through the repo layer, including the session, because the scan in
 * `repo/repo.test.ts` reads test files too. The token is hashed by the same
 * function the server uses, so this fixture cannot drift from the
 * implementation without the suite going red.
 */
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

async function seedOrg(
  t: Harness,
  actor: Actor,
  slug: string,
): Promise<Id<"orgs">> {
  return await t.mutation(api.orgs.createOrg, {
    sessionToken: actor.sessionToken,
    name: "Acme Rockets",
    slug,
    revocationPublicKey: "ab".repeat(32),
    wrappedRevocationKey: "wrapped-revocation-key-blob",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  });
}

const NOT_PERMITTED = "Not found, or you do not have access to it.";

/**
 * A project data key wrapped to the creator, and the nonce it was sealed under.
 * Opaque to the server by design: it is minted in the browser and this
 * deployment has never held the plaintext.
 */
const WRAPPED_PDK = "dd".repeat(48);
const PDK_NONCE = "0a1b2c3d4e5f60718293a4b5";

/** The two arguments every `createEnvironment` call now carries. */
const wrap = { wrappedPDK: WRAPPED_PDK, pdkNonce: PDK_NONCE };

/** One tenant with a project, and a second tenant with a project of its own. */
async function twoTenants(t: Harness) {
  const alice = await seedUser(t, "alice@example.test");
  const mallory = await seedUser(t, "mallory@example.test");
  const orgA = await seedOrg(t, alice, "org-a");
  const orgB = await seedOrg(t, mallory, "org-b");
  const projectA = await t.mutation(api.projects.createProject, {
    sessionToken: alice.sessionToken,
    orgId: orgA,
    name: "API",
    slug: "api",
  });
  const projectB = await t.mutation(api.projects.createProject, {
    sessionToken: mallory.sessionToken,
    orgId: orgB,
    name: "API",
    slug: "api",
  });
  const environmentB = await t.mutation(api.environments.createEnvironment, {
    sessionToken: mallory.sessionToken,
    projectId: projectB,
    name: "production",
    ...wrap,
  });
  return { alice, mallory, orgA, orgB, projectA, projectB, environmentB };
}

// ---------------------------------------------------------------------------
// Authorisation first.
// ---------------------------------------------------------------------------

describe("environments authorisation", () => {
  // The exact question worth asking of this file: an environment id is what
  // every secret hangs off, so creating one under someone else's project is
  // the shortest path to writing into their tenancy.
  it("refuses to create an environment under a project in another org", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectB } = await twoTenants(t);

    await expect(
      t.mutation(api.environments.createEnvironment, {
        sessionToken: alice.sessionToken,
        projectId: projectB,
        name: "staging",
        ...wrap,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("refuses listEnvironments for another org's project", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectB } = await twoTenants(t);

    await expect(
      t.query(api.environments.listEnvironments, {
        sessionToken: alice.sessionToken,
        projectId: projectB,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("refuses getEnvironment for another org's environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, environmentB } = await twoTenants(t);

    await expect(
      t.query(api.environments.getEnvironment, {
        sessionToken: alice.sessionToken,
        environmentId: environmentB,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("writes nothing into the other org when a create is refused", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, projectB } = await twoTenants(t);

    await expect(
      t.mutation(api.environments.createEnvironment, {
        sessionToken: alice.sessionToken,
        projectId: projectB,
        name: "staging",
        ...wrap,
      }),
    ).rejects.toThrow(NOT_PERMITTED);

    const theirs = await t.query(api.environments.listEnvironments, {
      sessionToken: mallory.sessionToken,
      projectId: projectB,
    });
    expect(theirs.map((e) => e.name)).toEqual(["production"]);
  });
});

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

describe("createEnvironment", () => {
  it("initialises pdkVersion at 1 and epoch at 0", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(
      api.environments.createEnvironment,
      {
        sessionToken: alice.sessionToken,
        projectId: projectA,
        name: "production",
        ...wrap,
      },
    );

    expect(
      await t.query(api.environments.getEnvironment, {
        sessionToken: alice.sessionToken,
        environmentId,
      }),
    ).toEqual({
      environmentId,
      projectId: projectA,
      name: "production",
      pdkVersion: 1,
      epoch: 0,
    });
  });

  /**
   * Epochs are globally monotonic per token id and must never reset, so the
   * only safe starting point is one the caller cannot choose. This asserts the
   * validator itself rather than the behaviour: a handler that ignored a
   * supplied epoch today is one refactor away from using it.
   */
  it("does not accept an epoch or a pdkVersion from the caller", () => {
    const args = JSON.parse(
      (
        environmentsModule.createEnvironment as unknown as {
          exportArgs: () => string;
        }
      ).exportArgs(),
    ) as { value: Record<string, unknown> };

    expect(Object.keys(args.value).sort()).toEqual([
      "name",
      "pdkNonce",
      "projectId",
      "sessionToken",
      "wrappedPDK",
    ]);
  });

  it("rejects a duplicate name within one project", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);
    const args = {
      sessionToken: alice.sessionToken,
      projectId: projectA,
      name: "production",
      ...wrap,
    };
    await t.mutation(api.environments.createEnvironment, args);

    await expect(
      t.mutation(api.environments.createEnvironment, args),
    ).rejects.toThrow("An environment with that name already exists in this project.");
  });

  it("allows the same name in a different project", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA, mallory, projectB } = await twoTenants(t);

    await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const theirs = await t.query(api.environments.listEnvironments, {
      sessionToken: mallory.sessionToken,
      projectId: projectB,
    });
    expect(theirs.map((e) => e.name)).toEqual(["production"]);
  });

  /**
   * An environment name is not a label, it is the last segment of the address
   * the SDK resolves a config by, so it obeys the same rule as a slug. The
   * alternative is a name that renders one way, is typed another, and matches
   * neither in an exact-match index.
   */
  it("rejects a name that is not in canonical form", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    for (const name of [
      "Production",
      "prod uction",
      "-prod",
      "prod-",
      "",
      "prod_uction",
      "a".repeat(49),
    ]) {
      await expect(
        t.mutation(api.environments.createEnvironment, {
          sessionToken: alice.sessionToken,
          projectId: projectA,
          name,
          ...wrap,
        }),
      ).rejects.toThrow("name");
    }
  });
});

// ---------------------------------------------------------------------------
// The grant, which is the whole reason an environment can be read at all.
// ---------------------------------------------------------------------------

describe("the creator's project data key grant", () => {
  /**
   * THE ASSERTION THIS FILE EXISTS FOR.
   *
   * `createEnvironment` used to take a project and a name, so no grant was ever
   * written and the project data key could reach nobody. An environment with no
   * grant is an environment whose secrets nobody can ever read, and nothing
   * errors at any point until somebody tries.
   */
  it("is written by the same mutation that creates the environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "user", alice.userId),
    );
    expect(grant?.wrappedPDK).toBe(WRAPPED_PDK);
    expect(grant?.nonce).toBe(PDK_NONCE);
    expect(grant?.granteeType).toBe("user");
    expect(grant?.granteeId).toBe(alice.userId);
  });

  /**
   * Which key version the blob opens comes off the environment the mutation
   * just wrote, not from the caller. The two cannot disagree because one is
   * copied from the other inside one transaction.
   */
  it("records the environment's own pdkVersion", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const environment = await t.query(api.environments.getEnvironment, {
      sessionToken: alice.sessionToken,
      environmentId,
    });
    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "user", alice.userId),
    );
    expect(grant?.pdkVersion).toBe(environment.pdkVersion);
  });

  /** Exactly one, to the creator. Nobody else is granted anything. */
  it("is the only grant on a newly created environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    expect(grants).toHaveLength(1);
    expect(grants[0]?.granteeId).toBe(alice.userId);
    expect(grants[0]?.granteeId).not.toBe(mallory.userId);
  });

  /**
   * Atomicity, asserted rather than asserted about. The refusal happens before
   * either row is written, so there is no environment and no grant, and in
   * particular no environment that exists without one.
   */
  it("leaves neither row behind when the create is refused", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, projectB, environmentB } = await twoTenants(t);

    await expect(
      t.mutation(api.environments.createEnvironment, {
        sessionToken: alice.sessionToken,
        projectId: projectB,
        name: "staging",
        ...wrap,
      }),
    ).rejects.toThrow(NOT_PERMITTED);

    const theirs = await t.query(api.environments.listEnvironments, {
      sessionToken: mallory.sessionToken,
      projectId: projectB,
    });
    expect(theirs.map((e) => e.name)).toEqual(["production"]);

    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentB),
    );
    expect(grants.map((g) => g.granteeId)).toEqual([mallory.userId]);
  });

  /**
   * The nonce is checked by shape and the wrapped key only for a floor, the
   * same split `createOrg` makes and for the same reason: AES-GCM accepts any
   * nonce length and derives its counter block through GHASH when the nonce is
   * not 96 bits, so a wrong-width nonce decrypts happily and silently leaves
   * the construction this package was reviewed under. The wrapped key is an
   * opaque blob whose internals are the client's business, but nothing shorter
   * than the 16 byte GCM tag can be output this product produced.
   */
  it("refuses key material that is not canonical", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    const good = {
      sessionToken: alice.sessionToken,
      projectId: projectA,
      name: "production",
      ...wrap,
    };

    for (const bad of [
      { pdkNonce: "" },
      { pdkNonce: PDK_NONCE.toUpperCase() },
      { pdkNonce: `${PDK_NONCE}00` },
      { pdkNonce: PDK_NONCE.slice(0, -2) },
      { wrappedPDK: "" },
      { wrappedPDK: "ab" },
      { wrappedPDK: WRAPPED_PDK.toUpperCase() },
      { wrappedPDK: `${WRAPPED_PDK}a` },
    ]) {
      await expect(
        t.mutation(api.environments.createEnvironment, { ...good, ...bad }),
      ).rejects.toThrow();
    }

    // And nothing landed while all of that was refused.
    const list = await t.query(api.environments.listEnvironments, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
    });
    expect(list).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Listing, surface, audit
// ---------------------------------------------------------------------------

describe("listEnvironments", () => {
  it("returns every environment in the project, and only those", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);
    for (const name of ["production", "staging"]) {
      await t.mutation(api.environments.createEnvironment, {
        sessionToken: alice.sessionToken,
        projectId: projectA,
        name,
        ...wrap,
      });
    }

    const list = await t.query(api.environments.listEnvironments, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
    });
    expect(list.map((e) => e.name).sort()).toEqual(["production", "staging"]);
  });
});

describe("the environments surface", () => {
  it("exports exactly the functions it is supposed to", () => {
    expect(Object.keys(environmentsModule).sort()).toEqual([
      "createEnvironment",
      "getEnvironment",
      "listEnvironments",
    ]);
  });
});

describe("the audit log", () => {
  it("records the creation against a user id and never an email", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(
      api.environments.createEnvironment,
      {
        sessionToken: alice.sessionToken,
        projectId: projectA,
        name: "production",
        ...wrap,
      },
    );

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, alice.userId, 10),
    );
    const created = events.find((e) => e.action === "environment.create");

    expect(created?.orgId).toBe(orgA);
    expect(created?.actorType).toBe("user");
    expect(created?.actorId).toBe(alice.userId);
    expect(created?.targetId).toBe(environmentId);
    expect(created?.metadata).toBeUndefined();
    expect(JSON.stringify(events)).not.toContain("example.test");
  });
});
