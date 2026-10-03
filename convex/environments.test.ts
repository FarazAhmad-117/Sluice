import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import { newId } from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import { listAuditEventsByActor } from "./repo/audit";
import { insertOrgMember } from "./repo/orgs";
import {
  getEnvironment as getEnvironmentRow,
  getPDKGrant,
  listPDKGrantsByEnvironment,
  patchEnvironment,
} from "./repo/environments";
import * as environmentsModule from "./environments";

export const modules = import.meta.glob("./**/*.ts");

type Harness = ReturnType<typeof convexTest>;

/**
 * A seeded person. `userId` is for reading rows back in assertions and is
 * never passed to a handler: no handler takes a user id any more. Acting is
 * `sessionToken` and nothing else.
 */
type Actor = {
  userId: Id<"users">;
  // The permanent id, for building associated data and for asserting on
  // what a handler returns. Never passed as an argument for the same reason
  // `userId` is not.
  uid: string;
  sessionToken: string;
};

/**
 * Seeded through the repo layer, including the session, because the scan in
 * `repo/repo.test.ts` reads test files too. The token is hashed by the same
 * function the server uses, so this fixture cannot drift from the
 * implementation without the suite going red.
 */
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

async function seedOrg(
  t: Harness,
  actor: Actor,
  slug: string,
): Promise<Id<"orgs">> {
  return await t.mutation(api.orgs.createOrg, {
    sessionToken: actor.sessionToken,
    orgUid: newId("org"),
    name: "Acme Rockets",
    slug,
    revocationPublicKey: "ab".repeat(32),
    wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
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

/**
 * The three key arguments every `createEnvironment` call now carries: the
 * wrap, its nonce, and the key version the client wrapped under, which a new
 * environment must state as 1.
 */
const wrap = { wrappedPDK: WRAPPED_PDK, pdkNonce: PDK_NONCE, pdkVersion: 1 };

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
    environmentUid: newId("env"),
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
        environmentUid: newId("env"),
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
        environmentUid: newId("env"),
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
  it("refuses a project's twenty-first environment, and writes nothing", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);
    const create = (name: string) =>
      t.mutation(api.environments.createEnvironment, {
        sessionToken: alice.sessionToken,
        environmentUid: newId("env"),
        projectId: projectA,
        name,
        ...wrap,
      });
    for (let i = 1; i <= 20; i++) await create(`env-${i}`);
    await expect(create("env-21")).rejects.toThrow("A project can have up to 20 environments.");
    const listed = await t.query(api.environments.listEnvironments, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
    });
    expect(listed).toHaveLength(20);
  });

  it("initialises pdkVersion at 1 and epoch at 0", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    const environmentUid = newId("env");
    const environmentId = await t.mutation(
      api.environments.createEnvironment,
      {
        sessionToken: alice.sessionToken,
        environmentUid,
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
      uid: environmentUid,
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
   *
   * `pdkVersion` IS on the list, and is not a choice: the client states the
   * version it wrapped under so the server can refuse anything but 1. The
   * test below pins that.
   */
  it("does not accept an epoch from the caller", () => {
    const args = JSON.parse(
      (
        environmentsModule.createEnvironment as unknown as {
          exportArgs: () => string;
        }
      ).exportArgs(),
    ) as { value: Record<string, unknown> };

    expect(Object.keys(args.value).sort()).toEqual([
      "environmentUid",
      "name",
      "pdkNonce",
      "pdkVersion",
      "projectId",
      "sessionToken",
      "wrappedPDK",
    ]);
  });

  /**
   * The client wrapped the first grant under `pdkAssociatedData` naming key
   * version 1. A create that states any other version is a client whose wrap
   * names a version this grant will not be stored under, so it is refused and
   * nothing is written: no environment, no grant.
   */
  it("refuses a pdkVersion other than 1 and writes nothing", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    for (const pdkVersion of [0, 2, -1, 1.5, Number.NaN]) {
      await expect(
        t.mutation(api.environments.createEnvironment, {
          sessionToken: alice.sessionToken,
          environmentUid: newId("env"),
          projectId: projectA,
          name: "production",
          ...wrap,
          pdkVersion,
        }),
      ).rejects.toThrow("A new environment's key starts at version 1.");
    }

    expect(
      await t.query(api.environments.listEnvironments, {
        sessionToken: alice.sessionToken,
        projectId: projectA,
      }),
    ).toEqual([]);
  });

  // The uid is what every secret and every grant in this environment binds to
  // on the client, so a malformed one is refused before anything is written.
  describe("rejects an environmentUid that is not a well-formed env id", () => {
    const message = "environmentUid must be a well-formed env id";
    const cases: Array<[string, () => string]> = [
      ["empty", () => ""],
      ["an org id", () => newId("org")],
      ["a user id", () => newId("usr")],
      ["uppercase hex", () => "env_" + "ABCDEF0123456789".repeat(2)],
      ["too long", () => newId("env") + "0"],
      ["trailing newline", () => newId("env") + "\n"],
    ];

    for (const [name, value] of cases) {
      it(name, async () => {
        const t = convexTest(schema, modules);
        const { alice, projectA } = await twoTenants(t);
        await expect(
          t.mutation(api.environments.createEnvironment, {
            sessionToken: alice.sessionToken,
            environmentUid: value(),
            projectId: projectA,
            name: "production",
            ...wrap,
          }),
        ).rejects.toThrow(message);
        expect(
          await t.query(api.environments.listEnvironments, {
            sessionToken: alice.sessionToken,
            projectId: projectA,
          }),
        ).toEqual([]);
      });
    }
  });

  // Client-chosen, so a client can reuse an existing uid on purpose, here
  // another tenant's. Refused, in the same mutation as the insert, and the
  // refusal is the same whichever org owns the existing row.
  it("rejects a duplicate environmentUid, even across orgs", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, projectA, environmentB } = await twoTenants(t);
    const theirs = await t.query(api.environments.getEnvironment, {
      sessionToken: mallory.sessionToken,
      environmentId: environmentB,
    });

    await expect(
      t.mutation(api.environments.createEnvironment, {
        sessionToken: alice.sessionToken,
        environmentUid: theirs.uid,
        projectId: projectA,
        name: "production",
        ...wrap,
      }),
    ).rejects.toThrow("An environment with that id already exists.");
    expect(
      await t.query(api.environments.listEnvironments, {
        sessionToken: alice.sessionToken,
        projectId: projectA,
      }),
    ).toEqual([]);
  });

  // Copied from the org the authorisation walk resolved, never from a caller:
  // there is no orgId argument to take it from.
  it("records the owning org on the environment and on its first grant", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const row = await t.run(async (ctx) => getEnvironmentRow(ctx, environmentId));
    expect(row?.orgId).toBe(orgA);
    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    expect(grants.map((g) => g.orgId)).toEqual([orgA]);
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
    await t.mutation(api.environments.createEnvironment, {
      ...args,
      environmentUid: newId("env"),
    });

    // A fresh uid on the second call, so the only thing that collides is the
    // name and this keeps pinning the name check rather than the uid check.
    await expect(
      t.mutation(api.environments.createEnvironment, {
        ...args,
        environmentUid: newId("env"),
      }),
    ).rejects.toThrow("An environment with that name already exists in this project.");
  });

  it("allows the same name in a different project", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA, mallory, projectB } = await twoTenants(t);

    await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
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
          environmentUid: newId("env"),
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
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "user", alice.uid),
    );
    expect(grant?.wrappedPDK).toBe(WRAPPED_PDK);
    expect(grant?.nonce).toBe(PDK_NONCE);
    expect(grant?.granteeType).toBe("user");
    // The permanent `usr_` uid, not the Convex document id. It is what the
    // client's associated data names, and a string column holding a document
    // id would not be remapped when the org moves cells.
    expect(grant?.granteeId).toBe(alice.uid);
    expect(grant?.granteeId).not.toBe(alice.userId);
  });

  /**
   * Which key version the blob opens comes off the environment the mutation
   * just wrote. The caller states the version it wrapped under, but only so
   * that anything other than 1 can be refused; the stored value is never
   * taken from the argument. The two rows cannot disagree because one is
   * copied from the other inside one transaction.
   */
  it("records the environment's own pdkVersion", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const environment = await t.query(api.environments.getEnvironment, {
      sessionToken: alice.sessionToken,
      environmentId,
    });
    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, environmentId, "user", alice.uid),
    );
    expect(grant?.pdkVersion).toBe(environment.pdkVersion);
  });

  /** Exactly one, to the creator. Nobody else is granted anything. */
  it("is the only grant on a newly created environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const grants = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, environmentId),
    );
    expect(grants).toHaveLength(1);
    expect(grants[0]?.granteeId).toBe(alice.uid);
    expect(grants[0]?.granteeId).not.toBe(mallory.uid);
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
        environmentUid: newId("env"),
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
    expect(grants.map((g) => g.granteeId)).toEqual([mallory.uid]);
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
      environmentUid: newId("env"),
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
        environmentUid: newId("env"),
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

  it("returns each environment's permanent id", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);
    const environmentUid = newId("env");
    await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid,
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    const list = await t.query(api.environments.listEnvironments, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
    });
    expect(list.map((e) => e.uid)).toEqual([environmentUid]);
  });

  // The environment's CURRENT key version, which a client must state back to
  // `createServiceToken` when it wraps a token's grant. Without it in the
  // listing a client has no way to know which version it opened.
  it("returns each environment's current pdkVersion", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);
    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      ...wrap,
    });
    await t.run(async (ctx) =>
      patchEnvironment(ctx, environmentId, { pdkVersion: 3 }),
    );

    const list = await t.query(api.environments.listEnvironments, {
      sessionToken: alice.sessionToken,
      projectId: projectA,
    });
    expect(list.map((e) => e.pdkVersion)).toEqual([3]);
    const one = await t.query(api.environments.getEnvironment, {
      sessionToken: alice.sessionToken,
      environmentId,
    });
    expect(one.pdkVersion).toBe(3);
  });
});

describe("the environments surface", () => {
  it("exports exactly the functions it is supposed to", () => {
    expect(Object.keys(environmentsModule).sort()).toEqual([
      "createEnvironment",
      "getEnvironment",
      "getMyPdkGrant",
      "listEnvironments",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Reading a grant back.
// ---------------------------------------------------------------------------

describe("getMyPdkGrant", () => {
  it("returns the caller's own wrapped key and the version it opens", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    expect(
      await t.query(api.environments.getMyPdkGrant, {
        sessionToken: alice.sessionToken,
        environmentId,
      }),
    ).toEqual({
      environmentId,
      wrappedPDK: WRAPPED_PDK,
      nonce: PDK_NONCE,
      pdkVersion: 1,
    });
  });

  /**
   * THE CROSS-TENANT QUESTION, ASKED OF THE ONE HANDLER THAT RETURNS KEY
   * MATERIAL. It walks environment to project to org to membership through the
   * same chain as every other handler, so a member of one org cannot address
   * another org's environment however the id is obtained.
   */
  it("refuses another org's environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, environmentB } = await twoTenants(t);

    await expect(
      t.query(api.environments.getMyPdkGrant, {
        sessionToken: alice.sessionToken,
        environmentId: environmentB,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  /**
   * A MEMBER OF THE RIGHT ORG WITH NO GRANT GETS THE SHARED REFUSAL.
   *
   * This is the real state the moment a second person joins an org, because
   * nothing wraps an existing key to a new member. It answers with the same
   * string as "no such environment" on purpose: a distinct message would let
   * anyone in the org map exactly which environments each colleague can open,
   * which is a map of who to compromise.
   */
  it("refuses a member of the org who holds no grant", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA, projectA } = await twoTenants(t);
    const bob = await seedUser(t, "bob@example.test");

    const environmentId = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      ...wrap,
    });

    // Seeded through the repository, because there is no invitation flow yet
    // and this is exactly the state one will produce.
    await t.run(async (ctx) =>
      insertOrgMember(ctx, { orgId: orgA, userId: bob.userId, role: "member" }),
    );

    // Bob really is in the org: he can see the environment.
    expect(
      (
        await t.query(api.environments.getEnvironment, {
          sessionToken: bob.sessionToken,
          environmentId,
        })
      ).name,
    ).toBe("production");

    await expect(
      t.query(api.environments.getMyPdkGrant, {
        sessionToken: bob.sessionToken,
        environmentId,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  /**
   * NO GRANTEE ARGUMENT, AND THAT IS THE AUTHORISATION.
   *
   * The only grant anybody can read is their own. A `granteeId` parameter would
   * make this an endpoint for fetching other people's wrapped key material,
   * which is useless to them and is exactly the kind of read that looks
   * harmless in review. `orgs.getMyRevocationGrant` makes the same argument.
   */
  it("takes no grantee argument", () => {
    const args = JSON.parse(
      (
        environmentsModule.getMyPdkGrant as unknown as {
          exportArgs: () => string;
        }
      ).exportArgs(),
    ) as { value: Record<string, unknown> };

    expect(Object.keys(args.value).sort()).toEqual([
      "environmentId",
      "sessionToken",
    ]);
  });

  /** Two people, two environments, and neither sees the other's blob. */
  it("hands each caller only their own grant", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, projectA, projectB, environmentB } =
      await twoTenants(t);

    const environmentA = await t.mutation(api.environments.createEnvironment, {
      sessionToken: alice.sessionToken,
      environmentUid: newId("env"),
      projectId: projectA,
      name: "production",
      wrappedPDK: "ab".repeat(48),
      pdkNonce: PDK_NONCE,
      pdkVersion: 1,
    });
    expect(projectB).toBeDefined();

    const mine = await t.query(api.environments.getMyPdkGrant, {
      sessionToken: alice.sessionToken,
      environmentId: environmentA,
    });
    const theirs = await t.query(api.environments.getMyPdkGrant, {
      sessionToken: mallory.sessionToken,
      environmentId: environmentB,
    });

    expect(mine.wrappedPDK).toBe("ab".repeat(48));
    expect(theirs.wrappedPDK).toBe(WRAPPED_PDK);
    expect(mine.wrappedPDK).not.toBe(theirs.wrappedPDK);
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
        environmentUid: newId("env"),
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
