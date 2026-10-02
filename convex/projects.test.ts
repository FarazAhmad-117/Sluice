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
import { getEnvironmentByUid } from "./repo/environments";
import { getProject as getProjectRow } from "./repo/projects";
import {
  PROJECT_NEEDS_DEVELOPMENT,
  TOO_MANY_ENVIRONMENTS,
} from "./lib/errors";
import * as projectsModule from "./projects";

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
 * Two organisations, two owners, one project in each. The fixture every
 * cross-tenant test needs, so it is built once.
 */
async function twoOrgs(t: Harness) {
  const alice = await seedUser(t, "alice@example.test");
  const mallory = await seedUser(t, "mallory@example.test");
  const orgA = await seedOrg(t, alice, "org-a");
  const orgB = await seedOrg(t, mallory, "org-b");
  const projectB = await t.mutation(api.projects.createProject, {
    sessionToken: mallory.sessionToken,
    orgId: orgB,
    name: "Secret Weapon",
    slug: "secret-weapon",
  });
  return { alice, mallory, orgA, orgB, projectB };
}

// ---------------------------------------------------------------------------
// Authorisation first.
// ---------------------------------------------------------------------------

describe("projects authorisation", () => {
  it("refuses createProject to a user who is not a member of the org", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgB } = await twoOrgs(t);

    await expect(
      t.mutation(api.projects.createProject, {
        sessionToken: alice.sessionToken,
        orgId: orgB,
        name: "Trojan",
        slug: "trojan",
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("refuses listProjects for an org the caller is not in", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgB } = await twoOrgs(t);

    await expect(
      t.query(api.projects.listProjects, { sessionToken: alice.sessionToken, orgId: orgB }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  // The one that looks like it only reads metadata. A project id carries no
  // organisation with it, so this handler has to walk back to a membership row
  // or it answers for anybody.
  it("refuses getProject for a project in another org", async () => {
    const t = convexTest(schema, modules);
    const { alice, projectB } = await twoOrgs(t);

    await expect(
      t.query(api.projects.getProject, {
        sessionToken: alice.sessionToken,
        projectId: projectB,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("does not leak another org's project through the caller's own listing", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);

    const mine = await t.query(api.projects.listProjects, {
      sessionToken: alice.sessionToken,
      orgId: orgA,
    });
    expect(mine).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

describe("createProject", () => {
  it("creates a project a member can read back", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await seedOrg(t, owner, "acme");

    const projectId = await t.mutation(api.projects.createProject, {
      sessionToken: owner.sessionToken,
      orgId,
      name: "Payments API",
      slug: "payments-api",
    });

    const row = await t.run(async (ctx) => getProjectRow(ctx, projectId));
    expect(
      await t.query(api.projects.getProject, { sessionToken: owner.sessionToken, projectId }),
    ).toEqual({
      projectId,
      orgId,
      name: "Payments API",
      slug: "payments-api",
      // The row's own creation time, so the dashboard can say when a project
      // was made without a column that could disagree with it.
      createdAt: row?._creationTime,
    });
  });

  it("lists each project with its creation time", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await seedOrg(t, owner, "acme");
    const projectId = await t.mutation(api.projects.createProject, {
      sessionToken: owner.sessionToken,
      orgId,
      name: "Payments API",
      slug: "payments-api",
    });

    const row = await t.run(async (ctx) => getProjectRow(ctx, projectId));
    const [listed] = await t.query(api.projects.listProjects, {
      sessionToken: owner.sessionToken,
      orgId,
    });
    expect(typeof listed?.createdAt).toBe("number");
    expect(listed?.createdAt).toBe(row?._creationTime);
  });

  it("rejects a duplicate slug within one org", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await seedOrg(t, owner, "acme");
    const args = {
      sessionToken: owner.sessionToken,
      orgId,
      name: "Payments API",
      slug: "payments-api",
    };
    await t.mutation(api.projects.createProject, args);

    await expect(t.mutation(api.projects.createProject, args)).rejects.toThrow(
      "A project with that slug already exists in this organisation.",
    );
  });

  // The point of `by_org_slug` being composite. Slugs are unique within an
  // org, not globally, or the first customer to take `api` would take it from
  // everyone.
  it("allows the same slug in a different org", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    const bob = await seedUser(t, "bob@example.test");
    const orgA = await seedOrg(t, alice, "org-a");
    const orgB = await seedOrg(t, bob, "org-b");

    await t.mutation(api.projects.createProject, {
      sessionToken: alice.sessionToken,
      orgId: orgA,
      name: "API",
      slug: "api",
    });
    const inB = await t.mutation(api.projects.createProject, {
      sessionToken: bob.sessionToken,
      orgId: orgB,
      name: "API",
      slug: "api",
    });

    expect(inB).toBeTruthy();
    const listA = await t.query(api.projects.listProjects, {
      sessionToken: alice.sessionToken,
      orgId: orgA,
    });
    expect(listA).toHaveLength(1);
  });

  it("rejects a slug that is not in canonical form", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await seedOrg(t, owner, "acme");

    for (const slug of ["Payments", "payments api", "-api", "api-", "", "a".repeat(49)]) {
      await expect(
        t.mutation(api.projects.createProject, {
          sessionToken: owner.sessionToken,
          orgId,
          name: "Payments API",
          slug,
        }),
      ).rejects.toThrow("slug");
    }
  });

  it("rejects a display name that is empty or absurdly long", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await seedOrg(t, owner, "acme");

    for (const name of ["", "  ", "a".repeat(101)]) {
      await expect(
        t.mutation(api.projects.createProject, {
          sessionToken: owner.sessionToken,
          orgId,
          name,
          slug: "payments-api",
        }),
      ).rejects.toThrow("name");
    }
  });
});

// ---------------------------------------------------------------------------
// Listing, surface, audit
// ---------------------------------------------------------------------------

describe("listProjects", () => {
  it("returns every project in the org, and only those", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, orgA, orgB } = await twoOrgs(t);
    await t.mutation(api.projects.createProject, {
      sessionToken: alice.sessionToken,
      orgId: orgA,
      name: "One",
      slug: "one",
    });
    await t.mutation(api.projects.createProject, {
      sessionToken: alice.sessionToken,
      orgId: orgA,
      name: "Two",
      slug: "two",
    });

    const listA = await t.query(api.projects.listProjects, {
      sessionToken: alice.sessionToken,
      orgId: orgA,
    });
    const listB = await t.query(api.projects.listProjects, {
      sessionToken: mallory.sessionToken,
      orgId: orgB,
    });

    expect(listA.map((p) => p.slug).sort()).toEqual(["one", "two"]);
    expect(listB.map((p) => p.slug)).toEqual(["secret-weapon"]);
  });
});

/**
 * A PROJECT AND ITS FIRST ENVIRONMENTS, IN ONE MUTATION.
 *
 * The dashboard creates a project with development always present and any
 * others the person picked. Done as separate calls, a failure part way leaves
 * a project with some environments and not others, and a project with none is
 * a project nothing can be stored in. These pin that it is all or nothing, and
 * that each environment arrives exactly as `createEnvironment` would make it:
 * validated by the same code and holding its creator's key grant.
 */
describe("createProjectWithEnvironments", () => {
  const WRAP = {
    wrappedPDK: "dd".repeat(48),
    pdkNonce: "0a1b2c3d4e5f60718293a4b5",
    pdkVersion: 1,
  } as const;

  function environment(name: string, overrides: Record<string, unknown> = {}) {
    return { environmentUid: newId("env"), name, ...WRAP, ...overrides };
  }

  function args(
    actor: Actor,
    orgId: Id<"orgs">,
    environments: ReturnType<typeof environment>[],
    slug = "api",
  ) {
    return {
      sessionToken: actor.sessionToken,
      orgId,
      name: "API",
      slug,
      environments,
    };
  }

  /** Nothing of the refused call is left behind: no project, no environment. */
  async function expectNothingWritten(
    t: Harness,
    actor: Actor,
    orgId: Id<"orgs">,
    environments: ReturnType<typeof environment>[],
    expectedProjects = 0,
  ) {
    const projects = await t.query(api.projects.listProjects, {
      sessionToken: actor.sessionToken,
      orgId,
    });
    expect(projects).toHaveLength(expectedProjects);
    for (const env of environments) {
      expect(
        await t.run(async (ctx) => getEnvironmentByUid(ctx, env.environmentUid)),
      ).toBeNull();
    }
  }

  const DUPLICATE_NAME =
    "An environment with that name already exists in this project.";
  const DUPLICATE_SLUG =
    "A project with that slug already exists in this organisation.";

  it("creates the project and every environment, each with the creator's grant", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    const envs = [environment("development"), environment("production")];

    const { projectId, environmentIds } = await t.mutation(
      api.projects.createProjectWithEnvironments,
      args(alice, orgA, envs),
    );

    const project = await t.query(api.projects.getProject, {
      sessionToken: alice.sessionToken,
      projectId,
    });
    expect(project).toMatchObject({ orgId: orgA, name: "API", slug: "api" });

    const listed = await t.query(api.environments.listEnvironments, {
      sessionToken: alice.sessionToken,
      projectId,
    });
    expect(listed.map((e) => e.environmentId).sort()).toEqual(
      [...environmentIds].sort(),
    );
    expect(
      listed.map((e) => [e.name, e.uid, e.pdkVersion]).sort(),
    ).toEqual(
      envs.map((e) => [e.name, e.environmentUid, 1]).sort(),
    );

    for (const [i, environmentId] of environmentIds.entries()) {
      const grant = await t.query(api.environments.getMyPdkGrant, {
        sessionToken: alice.sessionToken,
        environmentId,
      });
      expect(grant).toEqual({
        environmentId,
        wrappedPDK: envs[i]!.wrappedPDK,
        nonce: envs[i]!.pdkNonce,
        pdkVersion: 1,
      });
    }
  });

  it("refuses a project with no development environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    const envs = [environment("staging"), environment("production")];

    await expect(
      t.mutation(api.projects.createProjectWithEnvironments, args(alice, orgA, envs)),
    ).rejects.toThrow(PROJECT_NEEDS_DEVELOPMENT);
    await expectNothingWritten(t, alice, orgA, envs);
  });

  it("refuses two environments with one name", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    const envs = [environment("development"), environment("development")];

    await expect(
      t.mutation(api.projects.createProjectWithEnvironments, args(alice, orgA, envs)),
    ).rejects.toThrow(DUPLICATE_NAME);
    await expectNothingWritten(t, alice, orgA, envs);
  });

  it("refuses two environments with one environmentUid", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    const environmentUid = newId("env");
    const envs = [
      environment("development", { environmentUid }),
      environment("production", { environmentUid }),
    ];

    await expect(
      t.mutation(api.projects.createProjectWithEnvironments, args(alice, orgA, envs)),
    ).rejects.toThrow("An environment with that id already exists.");
    await expectNothingWritten(t, alice, orgA, envs);
  });

  it("refuses more than ten environments", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    const envs = [
      environment("development"),
      ...Array.from({ length: 10 }, (_, i) => environment(`env-${i}`)),
    ];

    await expect(
      t.mutation(api.projects.createProjectWithEnvironments, args(alice, orgA, envs)),
    ).rejects.toThrow(TOO_MANY_ENVIRONMENTS);
    await expectNothingWritten(t, alice, orgA, envs);
  });

  it("accepts exactly ten environments", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    const envs = [
      environment("development"),
      ...Array.from({ length: 9 }, (_, i) => environment(`env-${i}`)),
    ];

    const { environmentIds } = await t.mutation(
      api.projects.createProjectWithEnvironments,
      args(alice, orgA, envs),
    );
    expect(environmentIds).toHaveLength(10);
  });

  it("refuses a slug the org already uses, and writes no environment", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    await t.mutation(api.projects.createProject, {
      sessionToken: alice.sessionToken,
      orgId: orgA,
      name: "API",
      slug: "api",
    });
    const envs = [environment("development")];

    await expect(
      t.mutation(api.projects.createProjectWithEnvironments, args(alice, orgA, envs)),
    ).rejects.toThrow(DUPLICATE_SLUG);
    await expectNothingWritten(t, alice, orgA, envs, 1);
  });

  it("leaves no project behind when a later environment is malformed", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgA } = await twoOrgs(t);
    const envs = [
      environment("development"),
      environment("production", { pdkNonce: "00" }),
    ];

    await expect(
      t.mutation(api.projects.createProjectWithEnvironments, args(alice, orgA, envs)),
    ).rejects.toThrow("pdkNonce must be 24 lowercase hex characters.");
    // The project and development were inserted before production's nonce
    // was checked; the transaction rolled both back.
    await expectNothingWritten(t, alice, orgA, envs);
  });

  it("refuses a caller who is not a member of the org", async () => {
    const t = convexTest(schema, modules);
    const { alice, orgB, mallory } = await twoOrgs(t);
    const envs = [environment("development")];

    await expect(
      t.mutation(api.projects.createProjectWithEnvironments, args(alice, orgB, envs)),
    ).rejects.toThrow(NOT_PERMITTED);
    // Mallory's org still holds only the project the fixture made.
    await expectNothingWritten(t, mallory, orgB, envs, 1);
  });
});

describe("the projects surface", () => {
  it("exports exactly the functions it is supposed to", () => {
    expect(Object.keys(projectsModule).sort()).toEqual([
      "createProject",
      "createProjectWithEnvironments",
      "getProject",
      "listProjects",
    ]);
  });
});

describe("the audit log", () => {
  it("records the creation against a user id and never an email", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await seedOrg(t, owner, "acme");
    const projectId = await t.mutation(api.projects.createProject, {
      sessionToken: owner.sessionToken,
      orgId,
      name: "Payments API",
      slug: "payments-api",
    });

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, owner.userId, 10),
    );
    const created = events.find((e) => e.action === "project.create");

    expect(created?.orgId).toBe(orgId);
    expect(created?.actorType).toBe("user");
    expect(created?.actorId).toBe(owner.userId);
    expect(created?.targetId).toBe(projectId);
    expect(created?.metadata).toBeUndefined();
    // The project slug and name are the operator's own words, but they are
    // still not written here, because the field they would go in has no
    // discriminated validator yet and is where a secret name lands by mistake.
    expect(JSON.stringify(events)).not.toContain("payments-api");
    expect(JSON.stringify(events)).not.toContain("example.test");
  });
});
