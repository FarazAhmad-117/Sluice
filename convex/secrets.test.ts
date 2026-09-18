import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import {
  getSecret as getSecretRow,
  insertSecret as insertSecretRow,
} from "./repo/secrets";
import { listAuditEventsByActor } from "./repo/audit";
import * as secretsModule from "./secrets";

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

/**
 * A whole tenant, built through the real public API. `alice` owns `org-a` with
 * two environments in one project, which is what the "cannot be read through
 * another environment's id" tests need, and `mallory` owns a separate org.
 */
async function world(t: Harness) {
  const alice = await seedUser(t, "alice@example.test");
  const mallory = await seedUser(t, "mallory@example.test");

  async function tenant(actor: Actor, slug: string) {
    const orgId = await t.mutation(api.orgs.createOrg, {
      sessionToken: actor.sessionToken,
      name: "Acme Rockets",
      slug,
      revocationPublicKey: "ab".repeat(32),
      wrappedRevocationKey: "wrapped-revocation-key-blob",
      revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
    });
    const projectId = await t.mutation(api.projects.createProject, {
      sessionToken: actor.sessionToken,
      orgId,
      name: "API",
      slug: "api",
    });
    const production = await t.mutation(api.environments.createEnvironment, {
      sessionToken: actor.sessionToken,
      projectId,
      name: "production",
      ...WRAP,
    });
    const staging = await t.mutation(api.environments.createEnvironment, {
      sessionToken: actor.sessionToken,
      projectId,
      name: "staging",
      ...WRAP,
    });
    return { orgId, projectId, production, staging };
  }

  return {
    alice,
    mallory,
    a: await tenant(alice, "org-a"),
    b: await tenant(mallory, "org-b"),
  };
}

const NOT_PERMITTED = "Not found, or you do not have access to it.";

// Ciphertext as the client produces it: `toHex` of an AES-GCM output, which is
// the plaintext plus a 16 byte tag, so never shorter than 32 hex characters.
const NAME_CIPHERTEXT = "aa".repeat(24);
const VALUE_CIPHERTEXT = "bb".repeat(40);
const NAME_NONCE = "000102030405060708090a0b";
const VALUE_NONCE = "0b0a090807060504030201ff";

function secretArgs(
  actor: Actor,
  environmentId: Id<"environments">,
  overrides: Record<string, unknown> = {},
) {
  return {
    sessionToken: actor.sessionToken,
    environmentId,
    nameCiphertext: NAME_CIPHERTEXT,
    nameNonce: NAME_NONCE,
    valueCiphertext: VALUE_CIPHERTEXT,
    valueNonce: VALUE_NONCE,
    ...overrides,
  };
}

/** Every field name mentioned anywhere in an exported validator. */
function fieldNames(json: unknown, out: string[] = []): string[] {
  if (json === null || typeof json !== "object") return out;
  const node = json as { type?: string; value?: unknown; fieldType?: unknown };
  if (node.type === "object" && node.value && typeof node.value === "object") {
    for (const [key, child] of Object.entries(
      node.value as Record<string, unknown>,
    )) {
      out.push(key);
      fieldNames((child as { fieldType?: unknown }).fieldType, out);
    }
    return out;
  }
  for (const child of Object.values(node as Record<string, unknown>)) {
    fieldNames(child, out);
  }
  return out;
}

function validatorFields(name: keyof typeof secretsModule): string[] {
  const fn = secretsModule[name] as unknown as {
    exportArgs: () => string;
    exportReturns: () => string;
  };
  return [
    ...fieldNames(JSON.parse(fn.exportArgs())),
    ...fieldNames(JSON.parse(fn.exportReturns())),
  ];
}

// ---------------------------------------------------------------------------
// Authorisation first, on every path, including the ones that only read.
// ---------------------------------------------------------------------------

describe("secrets authorisation", () => {
  it("refuses every path to a user outside the org", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, b } = await world(t);
    const theirs = await t.mutation(
      api.secrets.createSecret,
      secretArgs(mallory, b.production),
    );

    const attempts: Array<Promise<unknown>> = [
      t.mutation(api.secrets.createSecret, secretArgs(alice, b.production)),
      t.query(api.secrets.listSecrets, {
        sessionToken: alice.sessionToken,
        environmentId: b.production,
      }),
      t.query(api.secrets.getSecret, {
        sessionToken: alice.sessionToken,
        secretId: theirs.secretId,
      }),
      t.query(api.secrets.listSecretVersions, {
        sessionToken: alice.sessionToken,
        secretId: theirs.secretId,
      }),
      t.mutation(api.secrets.updateSecret, {
        sessionToken: alice.sessionToken,
        secretId: theirs.secretId,
        nameCiphertext: NAME_CIPHERTEXT,
        nameNonce: "ffffffffffffffffffffffff",
        valueCiphertext: VALUE_CIPHERTEXT,
        valueNonce: "eeeeeeeeeeeeeeeeeeeeeeee",
      }),
      t.mutation(api.secrets.deleteSecret, {
        sessionToken: alice.sessionToken,
        secretId: theirs.secretId,
      }),
    ];

    for (const attempt of attempts) {
      await expect(attempt).rejects.toThrow(NOT_PERMITTED);
    }
  });

  it("leaves the other tenant's secret exactly as it was", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, b } = await world(t);
    const theirs = await t.mutation(
      api.secrets.createSecret,
      secretArgs(mallory, b.production),
    );

    await expect(
      t.mutation(api.secrets.deleteSecret, {
        sessionToken: alice.sessionToken,
        secretId: theirs.secretId,
      }),
    ).rejects.toThrow(NOT_PERMITTED);

    const still = await t.query(api.secrets.listSecrets, {
      sessionToken: mallory.sessionToken,
      environmentId: b.production,
    });
    expect(still).toHaveLength(1);
    expect(still[0]?.valueCiphertext).toBe(VALUE_CIPHERTEXT);
  });

  // The associated data binds a ciphertext to one environment id. This is the
  // server-side half of that: there is no path by which a row created under
  // one environment is served under another, even inside one org, and no
  // mutation accepts an environment id for a row that already has one.
  it("does not serve a secret through another environment's id", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    await t.mutation(api.secrets.createSecret, secretArgs(alice, a.production));

    const staging = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.staging,
    });
    expect(staging).toEqual([]);
  });

  it("does not let an update move a secret into another environment", () => {
    // `environmentId` is not in `updateSecret`'s arguments at all, so there is
    // nothing to test behaviourally. Asserted against the validator instead,
    // because that is where the property lives.
    const args = JSON.parse(
      (
        secretsModule.updateSecret as unknown as { exportArgs: () => string }
      ).exportArgs(),
    );
    expect(fieldNames(args)).not.toContain("environmentId");
  });
});

// ---------------------------------------------------------------------------
// The server never sees a name or a value.
// ---------------------------------------------------------------------------

describe("the ciphertext-only surface", () => {
  /**
   * Asserted against the exported validators rather than against a convention,
   * because a convention is what an added argument quietly breaks. Every field
   * this file accepts or returns must be on this list, so a `name` argument
   * cannot appear without this test being edited on purpose.
   */
  it("accepts and returns no field that could be a plaintext name or value", () => {
    const ALLOWED = new Set([
      // The credential, which is an argument because a Convex call carries no
      // headers. It is not plaintext of anything and it is never returned.
      "sessionToken",
      "environmentId",
      "secretId",
      "lineageId",
      "version",
      "pdkVersion",
      "nameCiphertext",
      "nameNonce",
      "valueCiphertext",
      "valueNonce",
      "createdAt",
      "supersededAt",
    ]);

    const names = [
      "createSecret",
      "updateSecret",
      "deleteSecret",
      "getSecret",
      "listSecrets",
      "listSecretVersions",
    ] as const;

    // Guard the guard. If `fieldNames` ever stops walking a validator, for
    // example because Convex changes the shape it exports, every assertion
    // below passes against an empty list and this test silently stops being a
    // test. Both an argument and a field nested inside a returned array are
    // named here, because those are the two shapes that have to keep working.
    expect(validatorFields("createSecret")).toEqual(
      expect.arrayContaining([
        "sessionToken",
        "environmentId",
        "nameCiphertext",
        "valueNonce",
        "lineageId",
      ]),
    );
    expect(validatorFields("listSecrets")).toEqual(
      expect.arrayContaining(["environmentId", "valueCiphertext", "version"]),
    );

    for (const name of names) {
      for (const field of validatorFields(name)) {
        expect({ name, field, allowed: ALLOWED.has(field) }).toEqual({
          name,
          field,
          allowed: true,
        });
        // Belt as well as braces: anything whose name suggests a name or a
        // value must say which ciphertext or nonce it is.
        if (/name|value/i.test(field)) {
          expect(field).toMatch(/(Ciphertext|Nonce)$/);
        }
      }
    }
  });

  it("round trips ciphertext unchanged", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);

    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const read = await t.query(api.secrets.getSecret, {
      sessionToken: alice.sessionToken,
      secretId,
    });

    expect(read.nameCiphertext).toBe(NAME_CIPHERTEXT);
    expect(read.nameNonce).toBe(NAME_NONCE);
    expect(read.valueCiphertext).toBe(VALUE_CIPHERTEXT);
    expect(read.valueNonce).toBe(VALUE_NONCE);
    expect(read.environmentId).toBe(a.production);
    expect(read.version).toBe(1);
  });

  /**
   * The pdk version is copied from the environment rather than accepted from
   * the caller. A row claiming a version the environment never had is a row
   * nobody can decrypt, and it stores, lists and syncs perfectly until the day
   * someone needs to read it.
   */
  it("takes pdkVersion from the environment, not from the caller", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const environment = await t.query(api.environments.getEnvironment, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });

    // Not an argument at all, so there is nothing a caller could pass.
    const args = JSON.parse(
      (
        secretsModule.createSecret as unknown as { exportArgs: () => string }
      ).exportArgs(),
    );
    expect(fieldNames(args)).not.toContain("pdkVersion");

    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const read = await t.query(api.secrets.getSecret, {
      sessionToken: alice.sessionToken,
      secretId,
    });
    expect(read.pdkVersion).toBe(environment.pdkVersion);
  });

  it("rejects ciphertext that cannot be an AES-GCM output", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);

    for (const field of ["nameCiphertext", "valueCiphertext"]) {
      for (const bad of ["", "aa", "AA".repeat(24), "zz".repeat(24), "aaa"]) {
        await expect(
          t.mutation(
            api.secrets.createSecret,
            secretArgs(alice, a.production, { [field]: bad }),
          ),
        ).rejects.toThrow(field);
      }
    }
  });

  it("rejects a nonce that is not 12 bytes of canonical hex", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);

    for (const field of ["nameNonce", "valueNonce"]) {
      for (const bad of ["", "00", NAME_NONCE.toUpperCase(), NAME_NONCE + "00"]) {
        await expect(
          t.mutation(
            api.secrets.createSecret,
            secretArgs(alice, a.production, { [field]: bad }),
          ),
        ).rejects.toThrow(field);
      }
    }
  });

  /**
   * Both fields of a row are sealed under the same project data key, so one
   * nonce used for both is nonce reuse under one key, which leaks the XOR of
   * the two plaintexts and the GHASH authentication key. A conforming client
   * cannot do this, because `seal` generates its own nonce; this catches the
   * non-conforming one.
   */
  it("rejects a row that uses one nonce for both fields", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);

    await expect(
      t.mutation(
        api.secrets.createSecret,
        secretArgs(alice, a.production, { valueNonce: NAME_NONCE }),
      ),
    ).rejects.toThrow("nonce");
  });

  it("rejects an update that repeats a nonce already used in the lineage", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    await expect(
      t.mutation(api.secrets.updateSecret, {
        sessionToken: alice.sessionToken,
        secretId,
        nameCiphertext: "cc".repeat(24),
        nameNonce: NAME_NONCE,
        valueCiphertext: "dd".repeat(40),
        valueNonce: "010203040506070809000102",
      }),
    ).rejects.toThrow("nonce");
  });
});

// ---------------------------------------------------------------------------
// Lineage and versioning
// ---------------------------------------------------------------------------

describe("versioning", () => {
  it("gives every new secret its own lineage id", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);

    const one = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const two = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production, {
        nameNonce: "111111111111111111111111",
        valueNonce: "222222222222222222222222",
      }),
    );

    expect(one.lineageId).not.toBe(two.lineageId);
    expect(one.lineageId).toMatch(/^[0-9a-f]{32}$/);
  });

  /**
   * Nothing mints a lineage id but `createSecret`, and no function accepts
   * one. That is the whole answer to "two unrelated secrets share a lineage
   * and their histories merge": the client cannot name a lineage, so it cannot
   * name someone else's.
   */
  it("accepts a lineage id from nobody", () => {
    for (const name of ["createSecret", "updateSecret", "deleteSecret"] as const) {
      const args = JSON.parse(
        (
          secretsModule[name] as unknown as { exportArgs: () => string }
        ).exportArgs(),
      );
      expect(fieldNames(args)).not.toContain("lineageId");
    }
  });

  /**
   * The failure mode the lineage decision exists to prevent, forced into
   * existence by writing the row the public API cannot write. Two unrelated
   * secrets sharing a lineage must be refused loudly, not silently merged into
   * one history where an old value is served as current and a row vanishes
   * from the listing.
   */
  it("refuses loudly if two secrets ever share a lineage", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const original = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    const impostor = await t.run(async (ctx) =>
      insertSecretRow(ctx, {
        environmentId: a.production,
        lineageId: original.lineageId,
        nameCiphertext: "cc".repeat(24),
        nameNonce: "111111111111111111111111",
        valueCiphertext: "dd".repeat(40),
        valueNonce: "222222222222222222222222",
        pdkVersion: 1,
        version: 1,
      }),
    );

    for (const secretId of [original.secretId, impostor]) {
      await expect(
        t.query(api.secrets.getSecret, { sessionToken: alice.sessionToken, secretId }),
      ).rejects.toThrow("This secret's version history is inconsistent.");
    }
  });

  /**
   * The same guard across environments. A lineage that spans two environments
   * would make one environment's history readable through the other, which is
   * precisely what the associated data binding is there to stop, arriving by a
   * different route.
   */
  it("refuses a lineage that spans two environments", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const original = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    await t.run(async (ctx) =>
      insertSecretRow(ctx, {
        environmentId: a.staging,
        lineageId: original.lineageId,
        nameCiphertext: "cc".repeat(24),
        nameNonce: "111111111111111111111111",
        valueCiphertext: "dd".repeat(40),
        valueNonce: "222222222222222222222222",
        pdkVersion: 1,
        version: 2,
        supersededAt: 1,
      }),
    );

    await expect(
      t.query(api.secrets.listSecretVersions, {
        sessionToken: alice.sessionToken,
        secretId: original.secretId,
      }),
    ).rejects.toThrow("This secret's version history is inconsistent.");
  });

  it("creates a new version, keeps the old one readable, and lists only the current one", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    const second = await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    });

    expect(second.lineageId).toBe(first.lineageId);
    expect(second.secretId).not.toBe(first.secretId);

    const old = await t.query(api.secrets.getSecret, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
    });
    expect(old.version).toBe(1);
    expect(old.valueCiphertext).toBe(VALUE_CIPHERTEXT);
    expect(old.supersededAt).toBeTypeOf("number");

    const current = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(current).toHaveLength(1);
    expect(current[0]?.secretId).toBe(second.secretId);
    expect(current[0]?.version).toBe(2);

    const history = await t.query(api.secrets.listSecretVersions, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
    });
    expect(history.map((h) => h.version)).toEqual([1, 2]);
  });

  it("refuses to update a version that is not the current one", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    });

    await expect(
      t.mutation(api.secrets.updateSecret, {
        sessionToken: alice.sessionToken,
        secretId: first.secretId,
        nameCiphertext: "ee".repeat(24),
        nameNonce: "333333333333333333333333",
        valueCiphertext: "ff".repeat(40),
        valueNonce: "444444444444444444444444",
      }),
    ).rejects.toThrow("This version of the secret has already been replaced.");
  });
});

// ---------------------------------------------------------------------------
// Soft delete
// ---------------------------------------------------------------------------

describe("deleteSecret", () => {
  it("sets deletedAt and drops the secret from the default listing", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    await t.mutation(api.secrets.deleteSecret, { sessionToken: alice.sessionToken, secretId });

    const row = await t.run(async (ctx) => getSecretRow(ctx, secretId));
    expect(row?.deletedAt).toBeTypeOf("number");

    expect(
      await t.query(api.secrets.listSecrets, {
        sessionToken: alice.sessionToken,
        environmentId: a.production,
      }),
    ).toEqual([]);
  });

  /**
   * The listing is the path everyone remembers. These are the others: a
   * deleted secret must not come back through its own id, through the id of a
   * version that was current before it, or through its history.
   */
  it("hides the secret from every other path too", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const second = await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    });

    await t.mutation(api.secrets.deleteSecret, {
      sessionToken: alice.sessionToken,
      secretId: second.secretId,
    });

    for (const secretId of [first.secretId, second.secretId]) {
      await expect(
        t.query(api.secrets.getSecret, { sessionToken: alice.sessionToken, secretId }),
      ).rejects.toThrow(NOT_PERMITTED);
      await expect(
        t.query(api.secrets.listSecretVersions, { sessionToken: alice.sessionToken, secretId }),
      ).rejects.toThrow(NOT_PERMITTED);
    }
  });

  it("refuses a second delete and refuses an update after a delete", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    await t.mutation(api.secrets.deleteSecret, { sessionToken: alice.sessionToken, secretId });

    await expect(
      t.mutation(api.secrets.deleteSecret, { sessionToken: alice.sessionToken, secretId }),
    ).rejects.toThrow(NOT_PERMITTED);
    await expect(
      t.mutation(api.secrets.updateSecret, {
        sessionToken: alice.sessionToken,
        secretId,
        nameCiphertext: "cc".repeat(24),
        nameNonce: "111111111111111111111111",
        valueCiphertext: "dd".repeat(40),
        valueNonce: "222222222222222222222222",
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("does not stop a new secret being created afterwards", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    await t.mutation(api.secrets.deleteSecret, { sessionToken: alice.sessionToken, secretId });

    const fresh = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production, {
        nameNonce: "111111111111111111111111",
        valueNonce: "222222222222222222222222",
      }),
    );

    const list = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(list.map((s) => s.secretId)).toEqual([fresh.secretId]);
  });
});

// ---------------------------------------------------------------------------
// Surface and audit
// ---------------------------------------------------------------------------

describe("the secrets surface", () => {
  it("exports exactly the functions it is supposed to", () => {
    expect(Object.keys(secretsModule).sort()).toEqual([
      "createSecret",
      "deleteSecret",
      "getSecret",
      "listSecretVersions",
      "listSecrets",
      "updateSecret",
    ]);
  });
});

describe("the audit log", () => {
  it("records secret writes with ids only, never ciphertext or a nonce", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    await t.mutation(api.secrets.deleteSecret, { sessionToken: alice.sessionToken, secretId });

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, alice.userId, 20),
    );
    const actions = events.map((e) => e.action);
    expect(actions).toContain("secret.create");
    expect(actions).toContain("secret.delete");

    const created = events.find((e) => e.action === "secret.create");
    expect(created?.orgId).toBe(a.orgId);
    expect(created?.actorType).toBe("user");
    expect(created?.actorId).toBe(alice.userId);
    expect(created?.targetId).toBe(secretId);
    expect(created?.metadata).toBeUndefined();

    // Nothing that is, or is derived from, the protected material. The audit
    // table is append only and has no delete, so anything written here is
    // written forever.
    const dump = JSON.stringify(events);
    for (const leak of [
      NAME_CIPHERTEXT,
      VALUE_CIPHERTEXT,
      NAME_NONCE,
      VALUE_NONCE,
      "example.test",
    ]) {
      expect(dump).not.toContain(leak);
    }
  });
});
