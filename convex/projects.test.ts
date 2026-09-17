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
import * as projectsModule from "./projects";

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

    expect(
      await t.query(api.projects.getProject, { sessionToken: owner.sessionToken, projectId }),
    ).toEqual({
      projectId,
      orgId,
      name: "Payments API",
      slug: "payments-api",
    });
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

describe("the projects surface", () => {
  it("exports exactly the functions it is supposed to", () => {
    expect(Object.keys(projectsModule).sort()).toEqual([
      "createProject",
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
