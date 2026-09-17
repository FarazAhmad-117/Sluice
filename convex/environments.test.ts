import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { listAuditEventsByActor } from "./repo/audit";
import * as environmentsModule from "./environments";

export const modules = import.meta.glob("./**/*.ts");

type Harness = ReturnType<typeof convexTest>;

async function seedUser(t: Harness, email: string): Promise<Id<"users">> {
  return await t.run(async (ctx) =>
    insertUser(ctx, {
      email: normaliseEmail(email),
      authVerifierHash: "hash",
      publicKey: "11".repeat(32),
      verifyKey: "22".repeat(32),
      wrappedPrivateKey: "wrapped-private-key-blob",
      wrappedSigningKey: "wrapped-signing-key-blob",
    }),
  );
}

async function seedOrg(
  t: Harness,
  callerId: Id<"users">,
  slug: string,
): Promise<Id<"orgs">> {
  return await t.mutation(api.orgs.createOrg, {
    callerId,
    name: "Acme Rockets",
    slug,
    revocationPublicKey: "ab".repeat(32),
    wrappedRevocationKey: "wrapped-revocation-key-blob",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  });
}

const NOT_PERMITTED = "Not found, or you do not have access to it.";

/** One tenant with a project, and a second tenant with a project of its own. */
async function twoTenants(t: Harness) {
  const alice = await seedUser(t, "alice@example.test");
  const mallory = await seedUser(t, "mallory@example.test");
  const orgA = await seedOrg(t, alice, "org-a");
  const orgB = await seedOrg(t, mallory, "org-b");
  const projectA = await t.mutation(api.projects.createProject, {
    callerId: alice,
    orgId: orgA,
    name: "API",
    slug: "api",
  });
  const projectB = await t.mutation(api.projects.createProject, {
    callerId: mallory,
    orgId: orgB,
    name: "API",
    slug: "api",
  });
  const environmentB = await t.mutation(api.environments.createEnvironment, {
    callerId: mallory,
    projectId: projectB,
    name: "production",
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
        callerId: alice,
        projectId: projectB,
        name: "staging",
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("refuses listEnvironments for another org's project", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectB } = await twoTenants(t);

    await expect(
      t.query(api.environments.listEnvironments, {
        callerId: alice,
        projectId: projectB,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("refuses getEnvironment for another org's environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, environmentB } = await twoTenants(t);

    await expect(
      t.query(api.environments.getEnvironment, {
        callerId: alice,
        environmentId: environmentB,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("writes nothing into the other org when a create is refused", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, projectB } = await twoTenants(t);

    await expect(
      t.mutation(api.environments.createEnvironment, {
        callerId: alice,
        projectId: projectB,
        name: "staging",
      }),
    ).rejects.toThrow(NOT_PERMITTED);

    const theirs = await t.query(api.environments.listEnvironments, {
      callerId: mallory,
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
      { callerId: alice, projectId: projectA, name: "production" },
    );

    expect(
      await t.query(api.environments.getEnvironment, {
        callerId: alice,
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
      "callerId",
      "name",
      "projectId",
    ]);
  });

  it("rejects a duplicate name within one project", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectA } = await twoTenants(t);
    const args = {
      callerId: alice,
      projectId: projectA,
      name: "production",
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
      callerId: alice,
      projectId: projectA,
      name: "production",
    });

    const theirs = await t.query(api.environments.listEnvironments, {
      callerId: mallory,
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
          callerId: alice,
          projectId: projectA,
          name,
        }),
      ).rejects.toThrow("name");
    }
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
        callerId: alice,
        projectId: projectA,
        name,
      });
    }

    const list = await t.query(api.environments.listEnvironments, {
      callerId: alice,
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
      { callerId: alice, projectId: projectA, name: "production" },
    );

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, alice, 10),
    );
    const created = events.find((e) => e.action === "environment.create");

    expect(created?.orgId).toBe(orgA);
    expect(created?.actorType).toBe("user");
    expect(created?.actorId).toBe(alice);
    expect(created?.targetId).toBe(environmentId);
    expect(created?.metadata).toBeUndefined();
    expect(JSON.stringify(events)).not.toContain("example.test");
  });
});
