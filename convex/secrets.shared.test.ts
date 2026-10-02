import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import { newId } from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import {
  DELETE_SHARED_ROW,
  DUPLICATE_SHARE_UID,
  SHARED_NEEDS_SHARED_ROW,
  SHARED_ROWS_MISMATCH,
} from "./lib/errors";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { listSecretsByEnvironment } from "./repo/secrets";
import { listAuditEventsByActor } from "./repo/audit";
import { patchEnvironment } from "./repo/environments";
import { insertOrgMember } from "./repo/orgs";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";

export const modules = import.meta.glob("./**/*.ts");

/**
 * A SHARED SECRET IS N INDEPENDENTLY SEALED ROWS, ONE PER ENVIRONMENT.
 *
 * Every environment keeps its own project data key, so "set this for all
 * environments" cannot be one ciphertext: it is one row per environment, each
 * sealed by the client under that environment's key and its own `sec_` id,
 * linked by a `shr_` id that is bound into nothing. The server never opens any
 * of them, so the sealed fields below are fixed, valid-shaped hex. What the
 * server DOES own is the shape of the group: exactly one row per environment
 * of the project, all written or none, and these tests pin that.
 */

// Setup helpers, copied from `secrets.test.ts` rather than shared, as every
// test file here keeps its own fixtures.
const WRAP = {
  wrappedPDK: "dd".repeat(48),
  pdkNonce: "0a1b2c3d4e5f60718293a4b5",
  pdkVersion: 1,
} as const;

type Harness = ReturnType<typeof convexTest>;
type Actor = { userId: Id<"users">; uid: string; sessionToken: string };

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
 * Alice owns an org with two projects: `api`, with development, staging and
 * production, and `web`, with development only, which supplies an environment
 * from ANOTHER project of the same org. Mallory owns nothing alice can see.
 */
async function world(t: Harness) {
  const alice = await seedUser(t, "alice@example.test");
  const mallory = await seedUser(t, "mallory@example.test");
  const orgId = await t.mutation(api.orgs.createOrg, {
    sessionToken: alice.sessionToken,
    orgUid: newId("org"),
    name: "Acme Rockets",
    slug: "acme",
    revocationPublicKey: "ab".repeat(32),
    wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  });

  async function project(slug: string, names: string[]) {
    const projectId = await t.mutation(api.projects.createProject, {
      sessionToken: alice.sessionToken,
      orgId,
      name: slug.toUpperCase(),
      slug,
    });
    const environments: Id<"environments">[] = [];
    for (const name of names) {
      environments.push(
        await t.mutation(api.environments.createEnvironment, {
          sessionToken: alice.sessionToken,
          environmentUid: newId("env"),
          projectId,
          name,
          ...WRAP,
        }),
      );
    }
    return { projectId, environments };
  }

  return {
    alice,
    mallory,
    orgId,
    api: await project("api", ["development", "staging", "production"]),
    web: await project("web", ["development"]),
  };
}

const NOT_PERMITTED = "Not found, or you do not have access to it.";
const DUPLICATE_SECRET_UID = "A secret with that id already exists.";
const NO_GRANT =
  "You hold no key for this environment, so nothing you wrote here could ever be read.";
const STALE_PDK_VERSION =
  "This environment's key changed since you opened it. Reload and try again.";

function row(
  environmentId: Id<"environments">,
  overrides: Record<string, unknown> = {},
) {
  return {
    environmentId,
    secretUid: newId("sec"),
    version: 1,
    pdkVersion: 1,
    overridden: false,
    nameCiphertext: "aa".repeat(24),
    nameNonce: "000102030405060708090a0b",
    valueCiphertext: "bb".repeat(40),
    valueNonce: "0b0a090807060504030201ff",
    ...overrides,
  };
}

/** `createSecret`'s arguments for one plain, unshared secret. */
function plainArgs(actor: Actor, environmentId: Id<"environments">) {
  const { overridden: _overridden, ...fields } = row(environmentId);
  return { sessionToken: actor.sessionToken, ...fields };
}

function sharedArgs(
  actor: Actor,
  projectId: Id<"projects">,
  rows: ReturnType<typeof row>[],
  shareUid: string = newId("shr"),
) {
  return { sessionToken: actor.sessionToken, projectId, shareUid, rows };
}

/** Every row in every one of these environments, all history included. */
async function allRows(t: Harness, environments: Id<"environments">[]) {
  const out = [];
  for (const environmentId of environments) {
    out.push(
      ...(await t.run(async (ctx) =>
        listSecretsByEnvironment(ctx, environmentId),
      )),
    );
  }
  return out;
}

describe("createSharedSecret", () => {
  it("writes one row per environment, each carrying the shareUid and its override flag", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const [dev, staging, prod] = w.api.environments as [
      Id<"environments">,
      Id<"environments">,
      Id<"environments">,
    ];
    const shareUid = newId("shr");
    const rows = [row(dev), row(staging), row(prod, { overridden: true })];

    const created = await t.mutation(
      api.secrets.createSharedSecret,
      sharedArgs(w.alice, w.api.projectId, rows, shareUid),
    );

    expect(created.map((c) => [c.environmentId, c.secretUid])).toEqual(
      rows.map((r) => [r.environmentId, r.secretUid]),
    );

    for (const r of rows) {
      const listed = await t.query(api.secrets.listSecrets, {
        sessionToken: w.alice.sessionToken,
        environmentId: r.environmentId,
      });
      expect(listed).toHaveLength(1);
      expect(listed[0]).toMatchObject({
        environmentId: r.environmentId,
        secretUid: r.secretUid,
        version: 1,
        shareUid,
        overridden: r.overridden,
      });
    }

    // One audit event per row, each naming the row it created.
    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, w.alice.userId, 100),
    );
    const creates = events.filter((e) => e.action === "secret.create");
    expect(creates.map((e) => e.targetId).sort()).toEqual(
      created.map((c) => c.secretId).sort(),
    );
  });

  describe("refuses a row set that is not exactly the project's environments, and writes nothing", () => {
    it.each([
      [
        "missing an environment",
        (env: Id<"environments">[], _other: Id<"environments">) => [
          row(env[0]!),
          row(env[1]!),
        ],
      ],
      [
        "with an extra environment from another project",
        (env: Id<"environments">[], other: Id<"environments">) => [
          row(env[0]!),
          row(env[1]!),
          row(env[2]!),
          row(other),
        ],
      ],
      [
        "swapping one environment for another project's",
        (env: Id<"environments">[], other: Id<"environments">) => [
          row(env[0]!),
          row(env[1]!),
          row(other),
        ],
      ],
      [
        "naming one environment twice",
        (env: Id<"environments">[], _other: Id<"environments">) => [
          row(env[0]!),
          row(env[1]!),
          row(env[1]!),
        ],
      ],
    ])("%s", async (_label, build) => {
      const t = convexTest(schema, modules);
      const w = await world(t);
      const rows = build(w.api.environments, w.web.environments[0]!);

      await expect(
        t.mutation(
          api.secrets.createSharedSecret,
          sharedArgs(w.alice, w.api.projectId, rows),
        ),
      ).rejects.toThrow(SHARED_ROWS_MISMATCH);
      expect(
        await allRows(t, [...w.api.environments, ...w.web.environments]),
      ).toEqual([]);
    });
  });

  /**
   * A project with no environments has an empty set, and an empty `rows`
   * matches it exactly. Without its own refusal that call would get as far as
   * the overridden check and be refused for the wrong reason, or, if that
   * check ever moved, write a group of nothing.
   */
  it("refuses an empty row set, even for a project with no environments", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const bare = await t.mutation(api.projects.createProject, {
      sessionToken: w.alice.sessionToken,
      orgId: w.orgId,
      name: "Bare",
      slug: "bare",
    });

    await expect(
      t.mutation(api.secrets.createSharedSecret, sharedArgs(w.alice, bare, [])),
    ).rejects.toThrow(SHARED_ROWS_MISMATCH);
  });

  it("refuses a group in which every environment is overridden", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const rows = w.api.environments.map((e) => row(e, { overridden: true }));

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(w.alice, w.api.projectId, rows),
      ),
    ).rejects.toThrow(SHARED_NEEDS_SHARED_ROW);
    expect(await allRows(t, w.api.environments)).toEqual([]);
  });

  it("refuses a secretUid used twice inside the call", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const [dev, staging, prod] = w.api.environments as Id<"environments">[];
    const secretUid = newId("sec");
    const rows = [
      row(dev!, { secretUid }),
      row(staging!, { secretUid }),
      row(prod!),
    ];

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(w.alice, w.api.projectId, rows),
      ),
    ).rejects.toThrow(DUPLICATE_SECRET_UID);
    expect(await allRows(t, w.api.environments)).toEqual([]);
  });

  it("refuses a secretUid an existing row already carries", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const [dev, staging, prod] = w.api.environments as Id<"environments">[];
    const existing = await t.mutation(
      api.secrets.createSecret,
      plainArgs(w.alice, w.web.environments[0]!),
    );

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(w.alice, w.api.projectId, [
          row(dev!),
          row(staging!, { secretUid: existing.secretUid }),
          row(prod!),
        ]),
      ),
    ).rejects.toThrow(DUPLICATE_SECRET_UID);
    expect(await allRows(t, w.api.environments)).toEqual([]);
  });

  it("refuses a shareUid already in use", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const shareUid = newId("shr");
    await t.mutation(
      api.secrets.createSharedSecret,
      sharedArgs(
        w.alice,
        w.api.projectId,
        w.api.environments.map((e) => row(e)),
        shareUid,
      ),
    );

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(
          w.alice,
          w.api.projectId,
          w.api.environments.map((e) => row(e)),
          shareUid,
        ),
      ),
    ).rejects.toThrow(DUPLICATE_SHARE_UID);
    expect(await allRows(t, w.api.environments)).toHaveLength(3);
  });

  it("refuses a shareUid that is not a well-formed shr id", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(
          w.alice,
          w.api.projectId,
          w.api.environments.map((e) => row(e)),
          newId("sec"),
        ),
      ),
    ).rejects.toThrow("shareUid must be a well-formed shr id");
    expect(await allRows(t, w.api.environments)).toEqual([]);
  });

  it("refuses a row sealed under a key generation that is no longer current", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const [dev, staging, prod] = w.api.environments as Id<"environments">[];
    // Production was re-keyed after the client unwrapped its key.
    await t.run(async (ctx) => patchEnvironment(ctx, prod!, { pdkVersion: 2 }));

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(w.alice, w.api.projectId, [
          row(dev!),
          row(staging!),
          row(prod!),
        ]),
      ),
    ).rejects.toThrow(STALE_PDK_VERSION);
    expect(await allRows(t, w.api.environments)).toEqual([]);
  });

  /**
   * A member with no key for the project's environments would seal under keys
   * nobody holds. The refusal is the grant check's own sentence, not
   * NOT_PERMITTED, which is what proves the fixture really is a member.
   */
  it("refuses a member who holds no key for the environments", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const bob = await seedUser(t, "bob@example.test");
    await t.run(async (ctx) =>
      insertOrgMember(ctx, { orgId: w.orgId, userId: bob.userId, role: "member" }),
    );

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(bob, w.api.projectId, w.api.environments.map((e) => row(e))),
      ),
    ).rejects.toThrow(NO_GRANT);
    expect(await allRows(t, w.api.environments)).toEqual([]);
  });

  it("refuses a caller who is not a member of the org", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    await expect(
      t.mutation(
        api.secrets.createSharedSecret,
        sharedArgs(
          w.mallory,
          w.api.projectId,
          w.api.environments.map((e) => row(e)),
        ),
      ),
    ).rejects.toThrow(NOT_PERMITTED);
    expect(await allRows(t, w.api.environments)).toEqual([]);
  });
});

describe("deleteSharedSecret", () => {
  it("removes every row of the group from every environment's listing", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const shareUid = newId("shr");
    await t.mutation(
      api.secrets.createSharedSecret,
      sharedArgs(
        w.alice,
        w.api.projectId,
        w.api.environments.map((e) => row(e)),
        shareUid,
      ),
    );
    // An unrelated secret in the same environment survives.
    const other = await t.mutation(
      api.secrets.createSecret,
      plainArgs(w.alice, w.api.environments[0]!),
    );

    const result = await t.mutation(api.secrets.deleteSharedSecret, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api.projectId,
      shareUid,
    });
    expect(result).toBeNull();

    for (const environmentId of w.api.environments) {
      const listed = await t.query(api.secrets.listSecrets, {
        sessionToken: w.alice.sessionToken,
        environmentId,
      });
      expect(listed.map((s) => s.secretId)).toEqual(
        environmentId === w.api.environments[0] ? [other.secretId] : [],
      );
    }

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, w.alice.userId, 100),
    );
    expect(events.filter((e) => e.action === "secret.delete")).toHaveLength(3);
  });

  it("refuses a shareUid with no live rows, and one addressed through another project", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const shareUid = newId("shr");
    await t.mutation(
      api.secrets.createSharedSecret,
      sharedArgs(
        w.alice,
        w.api.projectId,
        w.api.environments.map((e) => row(e)),
        shareUid,
      ),
    );

    await expect(
      t.mutation(api.secrets.deleteSharedSecret, {
        sessionToken: w.alice.sessionToken,
        projectId: w.api.projectId,
        shareUid: newId("shr"),
      }),
    ).rejects.toThrow(NOT_PERMITTED);
    await expect(
      t.mutation(api.secrets.deleteSharedSecret, {
        sessionToken: w.alice.sessionToken,
        projectId: w.web.projectId,
        shareUid,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
    await expect(
      t.mutation(api.secrets.deleteSharedSecret, {
        sessionToken: w.mallory.sessionToken,
        projectId: w.api.projectId,
        shareUid,
      }),
    ).rejects.toThrow(NOT_PERMITTED);

    const live = (await allRows(t, w.api.environments)).filter(
      (r) => r.deletedAt === undefined,
    );
    expect(live).toHaveLength(3);
  });
});

/**
 * THE TWO DELETE PATHS AGREE. A delete seals nothing, so neither needs a key
 * grant; and a shared row is deleted with its group or not at all, because a
 * group with a hole in it is labelled "All environments" over an environment
 * that no longer has the value.
 */
describe("deleting shared rows", () => {
  it("lets a member who holds no key delete the group, as deleteSecret would", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const shareUid = newId("shr");
    await t.mutation(
      api.secrets.createSharedSecret,
      sharedArgs(
        w.alice,
        w.api.projectId,
        w.api.environments.map((e) => row(e)),
        shareUid,
      ),
    );
    const bob = await seedUser(t, "bob@example.test");
    await t.run(async (ctx) =>
      insertOrgMember(ctx, { orgId: w.orgId, userId: bob.userId, role: "member" }),
    );

    await t.mutation(api.secrets.deleteSharedSecret, {
      sessionToken: bob.sessionToken,
      projectId: w.api.projectId,
      shareUid,
    });
    const live = (await allRows(t, w.api.environments)).filter(
      (r) => r.deletedAt === undefined,
    );
    expect(live).toEqual([]);
  });

  it("refuses deleteSecret on one row of a group, and deletes nothing", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const created = await t.mutation(
      api.secrets.createSharedSecret,
      sharedArgs(
        w.alice,
        w.api.projectId,
        w.api.environments.map((e) => row(e)),
      ),
    );

    await expect(
      t.mutation(api.secrets.deleteSecret, {
        sessionToken: w.alice.sessionToken,
        secretId: created[0]!.secretId,
      }),
    ).rejects.toThrow(DELETE_SHARED_ROW);
    const live = (await allRows(t, w.api.environments)).filter(
      (r) => r.deletedAt === undefined,
    );
    expect(live).toHaveLength(3);
  });

  it("still lets deleteSecret delete a plain secret", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const plain = await t.mutation(
      api.secrets.createSecret,
      plainArgs(w.alice, w.api.environments[0]!),
    );

    await t.mutation(api.secrets.deleteSecret, {
      sessionToken: w.alice.sessionToken,
      secretId: plain.secretId,
    });
    expect(
      await t.query(api.secrets.listSecrets, {
        sessionToken: w.alice.sessionToken,
        environmentId: w.api.environments[0]!,
      }),
    ).toEqual([]);
  });
});

describe("a shared row's later versions", () => {
  it("keep the shareUid and overridden flag through updateSecret", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const shareUid = newId("shr");
    const [dev, staging, prod] = w.api.environments as Id<"environments">[];
    const created = await t.mutation(
      api.secrets.createSharedSecret,
      sharedArgs(
        w.alice,
        w.api.projectId,
        [row(dev!), row(staging!), row(prod!, { overridden: true })],
        shareUid,
      ),
    );
    const prodRow = created.find((c) => c.environmentId === prod)!;

    const updated = await t.mutation(api.secrets.updateSecret, {
      sessionToken: w.alice.sessionToken,
      secretId: prodRow.secretId,
      version: 2,
      pdkVersion: 1,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "ffffffffffffffffffffffff",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "eeeeeeeeeeeeeeeeeeeeeeee",
    });

    const listed = await t.query(api.secrets.listSecrets, {
      sessionToken: w.alice.sessionToken,
      environmentId: prod!,
    });
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({
      secretId: updated.secretId,
      version: 2,
      shareUid,
      overridden: true,
    });
  });
});
