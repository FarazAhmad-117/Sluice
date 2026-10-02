import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import {
  deriveMUK,
  fromHex,
  newAccountSalt,
  newId,
  signRevocation,
  toHex,
  verifyRevocation,
} from "@sluice/crypto";
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
  patchSecret,
} from "./repo/secrets";
import { listAuditEventsByActor } from "./repo/audit";
import {
  getRevocationGrant as getRevocationGrantRow,
  insertOrgMember,
} from "./repo/orgs";
import {
  getPDKGrant,
  insertPDKGrant as insertPDKGrantRow,
  listPDKGrantsByEnvironment,
  patchEnvironment,
} from "./repo/environments";
import { getUser as getUserRow } from "./repo/users";
import * as secretsModule from "./secrets";

/**
 * THE DASHBOARD'S OWN MODULES, IMPORTED UNCHANGED, for the end-to-end test at
 * the bottom of this file.
 *
 * They are reached by relative path rather than through a package, because
 * `apps/admin` is an application and not one. The alternative to importing them
 * is re-implementing the client half here, which would prove that this file
 * agrees with itself and nothing about whether the browser agrees with the
 * server. That agreement is the only thing the last test exists to establish.
 */
import {
  createIdentity,
  deriveAuthVerifier,
  identityMatches,
  unwrapIdentity,
} from "../apps/admin/src/lib/auth/identity";
import { normaliseEmail as normaliseWebEmail } from "../apps/admin/src/lib/auth/email";
import {
  RevocationKeyUnwrapError,
  createRevocationKeypair,
  revocationKeyMatches,
  unwrapRevocationKey,
  wrapRevocationKey,
} from "../apps/admin/src/lib/orgs/revocation-key";
import {
  createProjectDataKey,
  unwrapProjectDataKey,
  wrapProjectDataKey,
} from "../apps/admin/src/lib/secrets/pdk";
import type { EnvironmentKey } from "../apps/admin/src/lib/secrets/pdk";
import {
  newSecretSlot,
  nextSecretSlot,
  sealSecret,
} from "../apps/admin/src/lib/secrets/seal";
import {
  SecretOpenError,
  openSecret,
  openSecretName,
  openSecretValue,
} from "../apps/admin/src/lib/secrets/decrypt";
import {
  STALE_ENVIRONMENT_KEY,
  STALE_SECRET_VERSION,
  describeWriteFailure,
} from "../apps/admin/src/lib/secrets/write-errors";

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
      orgUid: newId("org"),
      name: "Acme Rockets",
      slug,
      revocationPublicKey: "ab".repeat(32),
      wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
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
      environmentUid: newId("env"),
      projectId,
      name: "production",
      ...WRAP,
    });
    const staging = await t.mutation(api.environments.createEnvironment, {
      sessionToken: actor.sessionToken,
      environmentUid: newId("env"),
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
    // Minted fresh per call, as the client mints it, so two creates in one
    // test are two secrets rather than a refused duplicate.
    secretUid: newId("sec"),
    // The only version a new secret is sealed under.
    version: 1,
    pdkVersion: 1,
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
        version: 2,
        pdkVersion: 1,
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
// A write from a caller who holds no project data key.
// ---------------------------------------------------------------------------

/**
 * THE HOLE THIS CLOSES, STATED PLAINLY.
 *
 * Membership authorises a write. Holding a grant is what makes the write
 * MEANINGFUL, and until this block the two were never checked together. A
 * member of the org with no row in `pdkGrants` for the environment has no
 * project data key at all, so whatever they seal is sealed under a key NOBODY
 * IN THE SYSTEM HOLDS. Every part of the system then behaves perfectly: the row
 * lands, `pdkVersion` is copied off the environment so it claims a real key
 * version, the listing shows it beside rows that are fine, the bundle ships it,
 * and the failure surfaces as a bare AEAD rejection the first time somebody
 * reads it. That may be in production, months later.
 *
 * It is not a hypothetical state. It is the state EVERY SECOND MEMBER of an org
 * is in today, because nothing wraps an existing project data key to a new
 * member: `createEnvironment` mints exactly one grant, to its creator.
 *
 * The refusal is a DISTINCT message rather than the shared `NOT_PERMITTED`, and
 * that is deliberate. `getMyPdkGrant` uses the shared string because a distinct
 * one there would let a caller map which colleague can open which environment.
 * Here the caller has already passed `requireEnvironment`, so they are a member,
 * and the only fact the message discloses is one about the caller's OWN grant,
 * which they can already establish by calling `getMyPdkGrant` on themselves. In
 * exchange it says something a person can act on, instead of "not found" on an
 * environment they are looking at.
 */
describe("a write from a caller who holds no project data key", () => {
  const NO_GRANT =
    "You hold no key for this environment, so nothing you wrote here could ever be read.";

  /** A member of the org, added the way an invite would add one: no grant. */
  async function memberWithoutGrant(t: Harness, orgId: Id<"orgs">, email: string) {
    const actor = await seedUser(t, email);
    await t.run(async (ctx) =>
      insertOrgMember(ctx, { orgId, userId: actor.userId, role: "member" }),
    );
    return actor;
  }

  it("has a fixture that really is a member and really has no grant", async () => {
    // Guards the guard. If the membership row stopped being written, every
    // assertion below would pass for the wrong reason: the refusal would be
    // NOT_PERMITTED from `requireEnvironment` rather than the grant check.
    const t = convexTest(schema, modules);
    const { a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");

    // A member: a read that needs only membership succeeds.
    const rows = await t.query(api.secrets.listSecrets, {
      sessionToken: bob.sessionToken,
      environmentId: a.production,
    });
    expect(rows).toEqual([]);

    // And no grant.
    const grant = await t.run(async (ctx) =>
      getPDKGrant(ctx, a.production, "user", bob.uid),
    );
    expect(grant).toBeNull();
  });

  it("refuses createSecret", async () => {
    const t = convexTest(schema, modules);
    const { a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");

    await expect(
      t.mutation(api.secrets.createSecret, secretArgs(bob, a.production)),
    ).rejects.toThrow(NO_GRANT);
  });

  it("refuses updateSecret", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");

    // Created by someone who DOES hold a grant, so the row is healthy and the
    // only thing wrong with the update is who is making it.
    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    await expect(
      t.mutation(api.secrets.updateSecret, {
        sessionToken: bob.sessionToken,
        secretId,
        version: 2,
        pdkVersion: 1,
        nameCiphertext: "cc".repeat(24),
        nameNonce: "111111111111111111111111",
        valueCiphertext: "dd".repeat(40),
        valueNonce: "222222222222222222222222",
      }),
    ).rejects.toThrow(NO_GRANT);
  });

  it("writes nothing at all when it refuses", async () => {
    // A refusal that had already inserted the row, or already superseded the
    // previous version, would be worse than no check. Convex mutations are
    // atomic, so this asserts the property rather than the mechanism.
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    await expect(
      t.mutation(api.secrets.createSecret, secretArgs(bob, a.production)),
    ).rejects.toThrow(NO_GRANT);
    await expect(
      t.mutation(api.secrets.updateSecret, {
        sessionToken: bob.sessionToken,
        secretId: first.secretId,
        version: 2,
        pdkVersion: 1,
        nameCiphertext: "cc".repeat(24),
        nameNonce: "111111111111111111111111",
        valueCiphertext: "dd".repeat(40),
        valueNonce: "222222222222222222222222",
      }),
    ).rejects.toThrow(NO_GRANT);

    const live = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(live.map((row) => row.secretId)).toEqual([first.secretId]);
    expect(live[0]?.version).toBe(1);
  });

  /**
   * The grant is checked on the ENVIRONMENT BEING WRITTEN TO, not merely on
   * "some environment". A member who holds a grant on `staging` must not be
   * able to write a `production` row nobody can open, which is the shape this
   * bug would take once grants start being issued selectively.
   */
  it("refuses a caller who holds a grant on a different environment", async () => {
    const t = convexTest(schema, modules);
    const { a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");

    await t.run(async (ctx) =>
      insertPDKGrantRow(ctx, {
        environmentId: a.staging,
        orgId: a.orgId,
        granteeType: "user",
        granteeId: bob.uid,
        wrappedPDK: WRAP.wrappedPDK,
        nonce: WRAP.pdkNonce,
        pdkVersion: 1,
      }),
    );

    await expect(
      t.mutation(api.secrets.createSecret, secretArgs(bob, a.production)),
    ).rejects.toThrow(NO_GRANT);

    // And the same caller, on the environment they DO hold a key for, is fine.
    // Without this the test above would pass against a check that refuses
    // everybody.
    const ok = await t.mutation(api.secrets.createSecret, secretArgs(bob, a.staging));
    expect(ok.version).toBe(1);
  });

  /**
   * A TOKEN'S grant is not a user's. `granteeType` separates two namespaces of
   * opaque strings, and a check that ignored it would accept a `tokenIdHash`
   * that happened to equal a user's uid, and more realistically would be one
   * refactor away from doing so.
   */
  it("does not accept a token grant as a user's", async () => {
    const t = convexTest(schema, modules);
    const { a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");

    await t.run(async (ctx) =>
      insertPDKGrantRow(ctx, {
        environmentId: a.production,
        orgId: a.orgId,
        granteeType: "token",
        granteeId: bob.uid,
        wrappedPDK: WRAP.wrappedPDK,
        nonce: WRAP.pdkNonce,
        pdkVersion: 1,
      }),
    );

    await expect(
      t.mutation(api.secrets.createSecret, secretArgs(bob, a.production)),
    ).rejects.toThrow(NO_GRANT);
  });

  /**
   * A user grant is keyed by the PERMANENT uid. One keyed by the Convex
   * document id is a row from before that rule, or from a writer that forgot
   * it, and it must not authorise anything: the client's associated data names
   * the uid, so a blob filed under the document id is one the lookup and the
   * binding disagree about.
   */
  it("does not accept a user grant keyed by the Convex user id", async () => {
    const t = convexTest(schema, modules);
    const { a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");

    await t.run(async (ctx) =>
      insertPDKGrantRow(ctx, {
        environmentId: a.production,
        orgId: a.orgId,
        granteeType: "user",
        granteeId: bob.userId,
        wrappedPDK: WRAP.wrappedPDK,
        nonce: WRAP.pdkNonce,
        pdkVersion: 1,
      }),
    );

    await expect(
      t.mutation(api.secrets.createSecret, secretArgs(bob, a.production)),
    ).rejects.toThrow(NO_GRANT);
  });

  it("lets a member write as soon as a grant is wrapped to them", async () => {
    const t = convexTest(schema, modules);
    const { a } = await world(t);
    const bob = await memberWithoutGrant(t, a.orgId, "bob@example.test");

    await t.run(async (ctx) =>
      insertPDKGrantRow(ctx, {
        environmentId: a.production,
        orgId: a.orgId,
        granteeType: "user",
        granteeId: bob.uid,
        wrappedPDK: WRAP.wrappedPDK,
        nonce: WRAP.pdkNonce,
        pdkVersion: 1,
      }),
    );

    const created = await t.mutation(
      api.secrets.createSecret,
      secretArgs(bob, a.production),
    );
    expect(created.version).toBe(1);

    const updated = await t.mutation(api.secrets.updateSecret, {
      sessionToken: bob.sessionToken,
      secretId: created.secretId,
      version: 2,
      pdkVersion: 1,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    });
    expect(updated.version).toBe(2);
  });

  /**
   * The check must not become a side channel of its own. Both mutations refuse
   * a non-member with the SHARED string, so "you are not in this org" and "you
   * are in it but hold no key" are told apart only by somebody who is already
   * in the org.
   */
  it("still refuses an outsider with the shared refusal, not this one", async () => {
    const t = convexTest(schema, modules);
    const { mallory, a } = await world(t);

    await expect(
      t.mutation(api.secrets.createSecret, secretArgs(mallory, a.production)),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("does not write a grant of its own on the way past", async () => {
    // A tempting "fix" is to mint the missing grant here. It cannot be done:
    // the server has never held the plaintext project data key and cannot wrap
    // it to anybody. A handler that wrote a grant row would be writing one
    // whose ciphertext is not a key.
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const before = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, a.production),
    );
    await t.mutation(api.secrets.createSecret, secretArgs(alice, a.production));
    const after = await t.run(async (ctx) =>
      listPDKGrantsByEnvironment(ctx, a.production),
    );
    expect(after.length).toBe(before.length);
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
      "secretUid",
      "version",
      "pdkVersion",
      "nameCiphertext",
      "nameNonce",
      "valueCiphertext",
      "valueNonce",
      "createdAt",
      // When the secret last changed: the current row's `_creationTime`,
      // because an update inserts a new row. A timestamp, not a name or a
      // value, and the dashboard shows it per row.
      "updatedAt",
      "supersededAt",
      // Shared-secret grouping metadata. Plaintext on purpose and bound into
      // no associated data: a random `shr_` id and a boolean, neither of which
      // says anything about a name or a value. See `shr_` in
      // `packages/crypto/src/ids.ts`.
      "shareUid",
      "overridden",
      // `createSharedSecret`, `updateSharedSecret` and `deleteSharedSecret`:
      // the project a group spans, and the array of per-environment rows,
      // each of which is made of the fields above.
      "projectId",
      "rows",
    ]);

    const names = [
      "createSecret",
      "createSharedSecret",
      "updateSecret",
      "updateSharedSecret",
      "deleteSecret",
      "deleteSharedSecret",
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
        "secretUid",
      ]),
    );
    expect(validatorFields("listSecrets")).toEqual(
      expect.arrayContaining([
        "environmentId",
        "valueCiphertext",
        "secretUid",
        "version",
      ]),
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
  /**
   * Every secret row carries its org, for the cell-move and quota reads, and
   * it is copied off the environment row (on create) or off the row being
   * replaced (on update), never accepted. The validator assertion is what
   * makes "never from a caller" true rather than merely true today.
   */
  it("records the environment's org on every version, and takes no orgId", async () => {
    const t = convexTest(schema, modules);
    const { alice, a, b } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const second = await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
      version: 2,
      pdkVersion: 1,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "333333333333333333333333",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "444444444444444444444444",
    });

    for (const secretId of [first.secretId, second.secretId]) {
      const row = await t.run(async (ctx) => getSecretRow(ctx, secretId));
      expect(row?.orgId).toBe(a.orgId);
      expect(row?.orgId).not.toBe(b.orgId);
    }

    for (const name of ["createSecret", "updateSecret"] as const) {
      const args = JSON.parse(
        (
          secretsModule[name] as unknown as { exportArgs: () => string }
        ).exportArgs(),
      );
      expect(fieldNames(args)).not.toContain("orgId");
    }
  });

  /**
   * `environments.orgId` is a denormalised copy that the authorisation walk
   * does not read. Corrupted, it would file the new row under an org the
   * caller was never authorised for. The handler compares it with the walked
   * org and refuses, writing nothing.
   */
  it("refuses to write when the environment's org link disagrees with the walk", async () => {
    const t = convexTest(schema, modules);
    const { alice, a, b } = await world(t);
    await t.run(async (ctx) =>
      patchEnvironment(ctx, a.production, { orgId: b.orgId }),
    );

    await expect(
      t.mutation(api.secrets.createSecret, secretArgs(alice, a.production)),
    ).rejects.toThrow("This record's organisation link is inconsistent. Nothing was written.");

    expect(
      await t.query(api.secrets.listSecrets, {
        sessionToken: alice.sessionToken,
        environmentId: a.production,
      }),
    ).toEqual([]);
  });

  // `updateSecret` files the new version under the OLD ROW's `orgId`, which
  // the walk (secret -> environment -> project -> org) never reads.
  it("refuses an update when the secret's own org link disagrees with the walk", async () => {
    const t = convexTest(schema, modules);
    const { alice, a, b } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    await t.run(async (ctx) =>
      patchSecret(ctx, first.secretId, { orgId: b.orgId }),
    );

    await expect(
      t.mutation(api.secrets.updateSecret, {
        sessionToken: alice.sessionToken,
        secretId: first.secretId,
        version: 2,
        pdkVersion: 1,
        nameCiphertext: "cc".repeat(24),
        nameNonce: "555555555555555555555555",
        valueCiphertext: "dd".repeat(40),
        valueNonce: "666666666666666666666666",
      }),
    ).rejects.toThrow("This record's organisation link is inconsistent. Nothing was written.");

    // No new version, and the old one is still current.
    const live = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(live.map((row) => row.secretId)).toEqual([first.secretId]);
    expect(live[0]?.version).toBe(1);
    const row = await t.run(async (ctx) => getSecretRow(ctx, first.secretId));
    expect(row?.supersededAt).toBeUndefined();
  });

  // The caller STATES the generation it sealed under, on both writes, and the
  // stored value is that statement, which must equal the environment's. The
  // refusals are pinned in "the key generation a write was sealed under".
  it("stores the stated pdkVersion, which is the environment's", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const environment = await t.query(api.environments.getEnvironment, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });

    for (const name of ["createSecret", "updateSecret"] as const) {
      const args = JSON.parse(
        (
          secretsModule[name] as unknown as { exportArgs: () => string }
        ).exportArgs(),
      );
      expect(fieldNames(args)).toContain("pdkVersion");
    }

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

  it("rejects an update that repeats a nonce already used in the secret's history", async () => {
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
        version: 2,
        pdkVersion: 1,
        nameCiphertext: "cc".repeat(24),
        nameNonce: NAME_NONCE,
        valueCiphertext: "dd".repeat(40),
        valueNonce: "010203040506070809000102",
      }),
    ).rejects.toThrow("nonce");
  });
});

// ---------------------------------------------------------------------------
// The secret's permanent id, and the version it was sealed under.
// ---------------------------------------------------------------------------

/**
 * The client seals every row under associated data naming the environment's
 * uid, the secret's permanent `sec_` id, the version and the field. The server
 * never computes those bytes. It must store exactly the id and version the
 * client sealed under, hand both back on every read, and refuse a write whose
 * stated version is not the next one, so a stale write fails loudly instead of
 * landing a row that names a slot it does not occupy.
 */
describe("the secret's permanent id", () => {
  /**
   * A secret created in one environment is not part of any shared secret, so
   * it carries neither share field, not even as `undefined`: a dashboard that
   * groups rows by `shareUid` must see "absent" on every plain secret. The
   * shared shape is pinned in `secrets.shared.test.ts`.
   */
  it("lists a plain secret with no shareUid and no overridden field", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    await t.mutation(api.secrets.createSecret, secretArgs(alice, a.production));

    const [row] = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(row).toBeDefined();
    expect(row).not.toHaveProperty("shareUid");
    expect(row).not.toHaveProperty("overridden");
  });

  it("stores the client's secretUid at version 1 and returns both on every read", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const secretUid = newId("sec");

    const created = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production, { secretUid }),
    );
    expect(created.secretUid).toBe(secretUid);
    expect(created.version).toBe(1);

    const row = await t.run(async (ctx) => getSecretRow(ctx, created.secretId));
    expect(row?.secretUid).toBe(secretUid);
    expect(row?.version).toBe(1);

    const got = await t.query(api.secrets.getSecret, {
      sessionToken: alice.sessionToken,
      secretId: created.secretId,
    });
    const listed = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    const history = await t.query(api.secrets.listSecretVersions, {
      sessionToken: alice.sessionToken,
      secretId: created.secretId,
    });
    for (const view of [got, ...listed, ...history]) {
      expect({ secretUid: view.secretUid, version: view.version }).toEqual({
        secretUid,
        version: 1,
      });
    }
  });

  describe("rejects a secretUid that is not a well-formed sec id, and writes nothing", () => {
    const message = "secretUid must be a well-formed sec id";
    const cases: Array<[string, () => string]> = [
      ["empty", () => ""],
      // The shape the server used to mint, before ids were client-minted.
      ["bare 32 hex", () => "ab".repeat(16)],
      ["an env id", () => newId("env")],
      ["a user id", () => newId("usr")],
      ["uppercase hex", () => "sec_" + "ABCDEF0123456789".repeat(2)],
      ["too long", () => newId("sec") + "0"],
      ["trailing newline", () => newId("sec") + "\n"],
    ];

    for (const [name, value] of cases) {
      it(name, async () => {
        const t = convexTest(schema, modules);
        const { alice, a } = await world(t);
        await expect(
          t.mutation(
            api.secrets.createSecret,
            secretArgs(alice, a.production, { secretUid: value() }),
          ),
        ).rejects.toThrow(message);
        expect(
          await t.query(api.secrets.listSecrets, {
            sessionToken: alice.sessionToken,
            environmentId: a.production,
          }),
        ).toEqual([]);
      });
    }
  });

  /**
   * THE REASON THE ID USED TO BE SERVER-MINTED, ANSWERED. A client-chosen id
   * can name an EXISTING secret, and a create that accepted it would add a
   * version to somebody else's history with no compare-and-set having run.
   * Refused, deployment wide: another environment, another org, and a deleted
   * secret all keep their id for ever.
   */
  it("rejects a secretUid any row already carries, wherever it lives", async () => {
    const t = convexTest(schema, modules);
    const { alice, mallory, a, b } = await world(t);
    const DUPLICATE = "A secret with that id already exists.";

    const original = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const fresh = {
      nameNonce: "111111111111111111111111",
      valueNonce: "222222222222222222222222",
    };

    // Same environment, a sibling environment, and another tenant entirely.
    await expect(
      t.mutation(
        api.secrets.createSecret,
        secretArgs(alice, a.production, { secretUid: original.secretUid, ...fresh }),
      ),
    ).rejects.toThrow(DUPLICATE);
    await expect(
      t.mutation(
        api.secrets.createSecret,
        secretArgs(alice, a.staging, { secretUid: original.secretUid, ...fresh }),
      ),
    ).rejects.toThrow(DUPLICATE);
    await expect(
      t.mutation(
        api.secrets.createSecret,
        secretArgs(mallory, b.production, { secretUid: original.secretUid, ...fresh }),
      ),
    ).rejects.toThrow(DUPLICATE);

    // And after the secret is deleted, the id is still taken.
    await t.mutation(api.secrets.deleteSecret, {
      sessionToken: alice.sessionToken,
      secretId: original.secretId,
    });
    await expect(
      t.mutation(
        api.secrets.createSecret,
        secretArgs(alice, a.production, { secretUid: original.secretUid, ...fresh }),
      ),
    ).rejects.toThrow(DUPLICATE);

    // Nothing was written by any of the refusals: the one row is still the
    // only row under that id, and it is still version 1.
    const rows = await t.run(async (ctx) => getSecretRow(ctx, original.secretId));
    expect(rows?.version).toBe(1);
    for (const environmentId of [a.staging]) {
      expect(
        await t.query(api.secrets.listSecrets, {
          sessionToken: alice.sessionToken,
          environmentId,
        }),
      ).toEqual([]);
    }
    expect(
      await t.query(api.secrets.listSecrets, {
        sessionToken: mallory.sessionToken,
        environmentId: b.production,
      }),
    ).toEqual([]);
  });

  it("rejects a create that states any version but 1", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);

    for (const version of [0, 2, -1, 1.5, Number.NaN]) {
      await expect(
        t.mutation(
          api.secrets.createSecret,
          secretArgs(alice, a.production, { version }),
        ),
      ).rejects.toThrow("A new secret starts at version 1.");
    }
    expect(
      await t.query(api.secrets.listSecrets, {
        sessionToken: alice.sessionToken,
        environmentId: a.production,
      }),
    ).toEqual([]);
  });

  /**
   * `createSecret` is the ONLY function that accepts a secretUid. Update and
   * delete resolve it from the row they are handed, so neither can be pointed
   * at another secret's history by an argument.
   */
  it("is accepted by createSecret alone", () => {
    const args = (name: "createSecret" | "updateSecret" | "deleteSecret") =>
      fieldNames(
        JSON.parse(
          (
            secretsModule[name] as unknown as { exportArgs: () => string }
          ).exportArgs(),
        ),
      );
    expect(args("createSecret")).toContain("secretUid");
    expect(args("updateSecret")).not.toContain("secretUid");
    expect(args("deleteSecret")).not.toContain("secretUid");
  });
});

describe("the compare-and-set on update", () => {
  const STALE =
    "This secret changed since you opened it. Reload to see the latest version.";

  function updateArgs(
    actor: Actor,
    secretId: Id<"secrets">,
    version: number,
  ) {
    return {
      sessionToken: actor.sessionToken,
      secretId,
      version,
      pdkVersion: 1,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    };
  }

  it("accepts exactly the current version plus one, keeping the secretUid", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    const second = await t.mutation(
      api.secrets.updateSecret,
      updateArgs(alice, first.secretId, 2),
    );
    expect(second.version).toBe(2);
    expect(second.secretUid).toBe(first.secretUid);

    const row = await t.run(async (ctx) => getSecretRow(ctx, second.secretId));
    expect(row?.secretUid).toBe(first.secretUid);
    expect(row?.version).toBe(2);
  });

  // Equal to the current version (two writers raced from one starting point),
  // a skipped version, and zero. Each refused with the same sentence, and
  // none leaves a new row or a `supersededAt` behind.
  for (const [name, version] of [
    ["the current version (stale)", 1],
    ["two ahead (skipped)", 3],
    ["zero", 0],
    ["negative", -1],
    ["fractional", 1.5],
  ] as const) {
    it(`rejects ${name} and writes nothing`, async () => {
      const t = convexTest(schema, modules);
      const { alice, a } = await world(t);
      const first = await t.mutation(
        api.secrets.createSecret,
        secretArgs(alice, a.production),
      );

      await expect(
        t.mutation(api.secrets.updateSecret, updateArgs(alice, first.secretId, version)),
      ).rejects.toThrow(STALE);

      const live = await t.query(api.secrets.listSecrets, {
        sessionToken: alice.sessionToken,
        environmentId: a.production,
      });
      expect(live.map((row) => [row.secretId, row.version])).toEqual([
        [first.secretId, 1],
      ]);
      const row = await t.run(async (ctx) => getSecretRow(ctx, first.secretId));
      expect(row?.supersededAt).toBeUndefined();
      const history = await t.query(api.secrets.listSecretVersions, {
        sessionToken: alice.sessionToken,
        secretId: first.secretId,
      });
      expect(history).toHaveLength(1);
    });
  }

  /**
   * The race the check exists for, played the way a real loser plays it. Two
   * people open version 2 and both hold `second.secretId`. One saves version
   * 3. The other then saves THEIR version 3, still addressed to the row they
   * opened, which is now superseded. They must be told to reload, not given a
   * different message, and nothing of theirs may land.
   */
  it("tells the loser of a race to reload, and writes nothing of theirs", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const second = await t.mutation(
      api.secrets.updateSecret,
      updateArgs(alice, first.secretId, 2),
    );
    const third = await t.mutation(api.secrets.updateSecret, {
      ...updateArgs(alice, second.secretId, 3),
      nameNonce: "333333333333333333333333",
      valueNonce: "444444444444444444444444",
    });
    expect(third.version).toBe(3);

    await expect(
      t.mutation(api.secrets.updateSecret, {
        ...updateArgs(alice, second.secretId, 3),
        nameNonce: "555555555555555555555555",
        valueNonce: "666666666666666666666666",
      }),
    ).rejects.toThrow(STALE);

    const live = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(live.map((row) => [row.secretId, row.version])).toEqual([
      [third.secretId, 3],
    ]);
    const history = await t.query(api.secrets.listSecretVersions, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
    });
    expect(history.map((row) => row.version)).toEqual([1, 2, 3]);
    // The superseded row the loser named was not touched a second time.
    const opened = await t.run(async (ctx) => getSecretRow(ctx, second.secretId));
    expect(opened?.valueCiphertext).toBe("dd".repeat(40));
    expect(opened?.nameNonce).toBe("111111111111111111111111");
  });

  /**
   * A SMOKE TEST, NOT A CONCURRENCY TEST. convex-test runs mutations one at a
   * time, so `Promise.all` here does not interleave two transactions the way
   * a deployment can; what it does prove is that two updates fired from the
   * same row, whatever order they land in, end with exactly one success,
   * exactly one refusal, and exactly one live row. The real interleaving
   * guarantee is Convex's serialisable OCC, which retries the loser against
   * the winner's write and so reaches the identical refusal.
   */
  it("smoke test: two updates fired together from one row, exactly one lands", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    const results = await Promise.allSettled([
      t.mutation(api.secrets.updateSecret, updateArgs(alice, first.secretId, 2)),
      t.mutation(api.secrets.updateSecret, {
        ...updateArgs(alice, first.secretId, 2),
        nameNonce: "333333333333333333333333",
        valueNonce: "444444444444444444444444",
      }),
    ]);

    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.filter(
      (r): r is PromiseRejectedResult => r.status === "rejected",
    );
    expect(rejected).toHaveLength(1);
    expect(String(rejected[0]?.reason)).toContain(STALE);

    const live = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(live).toHaveLength(1);
    expect(live[0]?.version).toBe(2);
  });
});

/**
 * THE KEY GENERATION THE CLIENT SEALED UNDER, STATED AND CHECKED.
 *
 * The client seals under the project data key it unwrapped, and the version of
 * that key is the grant's `pdkVersion`. If the environment was re-keyed after
 * the unwrap, the ciphertext is under a generation that is no longer current,
 * and a server that stamped the environment's number on it would store a row
 * that never opens. So both writes take `pdkVersion`, refuse a mismatch with
 * the sentence `createServiceToken` uses, and write nothing.
 */
describe("the key generation a write was sealed under", () => {
  const STALE_KEY =
    "This environment's key changed since you opened it. Reload and try again.";

  it("refuses a createSecret whose pdkVersion is not the environment's, writing nothing", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    await t.run(async (ctx) =>
      patchEnvironment(ctx, a.production, { pdkVersion: 2 }),
    );

    for (const pdkVersion of [1, 3, 0]) {
      await expect(
        t.mutation(
          api.secrets.createSecret,
          secretArgs(alice, a.production, { pdkVersion }),
        ),
      ).rejects.toThrow(STALE_KEY);
    }
    expect(
      await t.query(api.secrets.listSecrets, {
        sessionToken: alice.sessionToken,
        environmentId: a.production,
      }),
    ).toEqual([]);

    // The current generation is accepted and stored as stated.
    const ok = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production, { pdkVersion: 2 }),
    );
    const row = await t.run(async (ctx) => getSecretRow(ctx, ok.secretId));
    expect(row?.pdkVersion).toBe(2);
  });

  it("refuses an updateSecret whose pdkVersion is not the environment's, writing nothing", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    // A re-key lands after the client unwrapped generation 1.
    await t.run(async (ctx) =>
      patchEnvironment(ctx, a.production, { pdkVersion: 2 }),
    );

    const update = {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
      version: 2,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    };
    for (const pdkVersion of [1, 3]) {
      await expect(
        t.mutation(api.secrets.updateSecret, { ...update, pdkVersion }),
      ).rejects.toThrow(STALE_KEY);
    }

    const live = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(live.map((row) => [row.secretId, row.version, row.pdkVersion])).toEqual([
      [first.secretId, 1, 1],
    ]);
    const old = await t.run(async (ctx) => getSecretRow(ctx, first.secretId));
    expect(old?.supersededAt).toBeUndefined();

    // Resealed under the current generation, it lands and is stored as such.
    const updated = await t.mutation(api.secrets.updateSecret, {
      ...update,
      pdkVersion: 2,
    });
    const row = await t.run(async (ctx) => getSecretRow(ctx, updated.secretId));
    expect(row?.pdkVersion).toBe(2);
  });

  /**
   * The nonce history is keyed on the generation the NEW row is sealed under.
   * After a re-key, reusing a generation-1 nonce under generation 2 is not
   * reuse under one key and is allowed; reusing it under generation 1 would
   * have been refused.
   */
  it("checks nonce reuse against the stated generation", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    await t.run(async (ctx) =>
      patchEnvironment(ctx, a.production, { pdkVersion: 2 }),
    );

    const reused = await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
      version: 2,
      pdkVersion: 2,
      nameCiphertext: "cc".repeat(24),
      nameNonce: NAME_NONCE,
      valueCiphertext: "dd".repeat(40),
      valueNonce: VALUE_NONCE,
    });
    expect(reused.version).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

describe("versioning", () => {
  /**
   * The failure mode the uniqueness check exists to prevent, forced into
   * existence by writing the row the public API cannot write. Two unrelated
   * secrets sharing a `secretUid` must be refused loudly, not silently merged
   * into one history where an old value is served as current and a row
   * vanishes from the listing.
   */
  it("refuses loudly if two secrets ever share a secretUid", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const original = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    const impostor = await t.run(async (ctx) =>
      insertSecretRow(ctx, {
        environmentId: a.production,
        orgId: a.orgId,
        secretUid: original.secretUid,
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
   * The same guard across environments. One secret's history spanning two
   * environments would make one environment's history readable through the
   * other, which is precisely what the associated data binding is there to
   * stop, arriving by a different route.
   */
  it("refuses a secret whose history spans two environments", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const original = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );

    await t.run(async (ctx) =>
      insertSecretRow(ctx, {
        environmentId: a.staging,
        orgId: a.orgId,
        secretUid: original.secretUid,
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
      version: 2,
      pdkVersion: 1,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    });

    expect(second.secretUid).toBe(first.secretUid);
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

  it("refuses to update or delete through a version that is not the current one", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const first = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId: first.secretId,
      version: 2,
      pdkVersion: 1,
      nameCiphertext: "cc".repeat(24),
      nameNonce: "111111111111111111111111",
      valueCiphertext: "dd".repeat(40),
      valueNonce: "222222222222222222222222",
    });

    await expect(
      t.mutation(api.secrets.updateSecret, {
        sessionToken: alice.sessionToken,
        secretId: first.secretId,
        version: 2,
        pdkVersion: 1,
        nameCiphertext: "ee".repeat(24),
        nameNonce: "333333333333333333333333",
        valueCiphertext: "ff".repeat(40),
        valueNonce: "444444444444444444444444",
      }),
    ).rejects.toThrow(
      "This secret changed since you opened it. Reload to see the latest version.",
    );

    // And a delete through the superseded row gets the same one answer, rather
    // than deleting a value the caller never saw.
    await expect(
      t.mutation(api.secrets.deleteSecret, {
        sessionToken: alice.sessionToken,
        secretId: first.secretId,
      }),
    ).rejects.toThrow(
      "This secret changed since you opened it. Reload to see the latest version.",
    );
    const live = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    expect(live.map((row) => row.version)).toEqual([2]);
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
      version: 2,
      pdkVersion: 1,
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
        version: 2,
        pdkVersion: 1,
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
      "createSharedSecret",
      "deleteSecret",
      "deleteSharedSecret",
      "getSecret",
      "listSecretVersions",
      "listSecrets",
      "updateSecret",
      "updateSharedSecret",
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

// ---------------------------------------------------------------------------
// End to end: a person signs up and reads a secret back in the clear.
// ---------------------------------------------------------------------------

/**
 * THE TEST THAT PROVES THE PRODUCT WORKS, THROUGH BOTH SIDES OF THE WIRE.
 *
 * Every other test in this file drives the server with fixture strings. This
 * one drives it with the DASHBOARD'S OWN CODE: the modules under
 * `apps/admin/src/lib` that the browser runs, imported here unchanged. Nothing
 * below hand-rolls a derivation, a wrap, an associated data or a hex encoding.
 * If the client and the server ever disagree about any of those, this goes red,
 * and it is the only test that can, because agreement between two sides cannot
 * be observed from either side alone.
 *
 * WHAT IT WOULD HAVE CAUGHT, had it existed earlier: an environment created
 * with no grant, so that its secrets were ciphertext under a key no client
 * could obtain, with nothing erroring at any point. And, in the revision before
 * this one, a signup that sent a placeholder salt while deriving the key under
 * another, so that the account could never log in again: the salt below is
 * minted, derived under, and sent, exactly as `auth-flows.ts` does it.
 *
 * EVERY WRAP AND SEAL IS FOR AN EXACT SLOT, and every slot input is minted by
 * the client before the row exists: the org's and the environment's permanent
 * uids, the secret's permanent uid and its version, the key version, and the
 * grantee's permanent `usr_` uid. Steps 3, 6 and 8 mint them; steps 4, 7 and 9
 * read them back from the server and open under them; steps 10 to 12 show the
 * binding refusing a slot the ciphertext was not sealed for, and the server
 * refusing a stale write with the sentence the dashboard shows as written.
 */
describe("end to end", () => {
  // A throwaway pepper. Set on `process.env` directly, because that is what the
  // deployment reads: a test that proved a mock worked would prove nothing.
  const TEST_PEPPER =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

  beforeEach(() => {
    process.env.AUTH_PEPPER = TEST_PEPPER;
  });
  afterEach(() => {
    delete process.env.AUTH_PEPPER;
  });

  /**
   * One real Argon2id derivation at the shipping parameters: 64 MiB, t=3, p=4.
   * That is the cost the product actually pays, and it is why this test carries
   * its own timeout.
   *
   * `deriveMUK` rather than the dashboard's `deriveMasterUnlockKey`, and the
   * difference is a runtime one rather than a cryptographic one: the dashboard
   * wrapper only chooses between a Web Worker, main-thread WASM and the noble
   * backend, all pinned to the same frozen `ARGON2_PARAMS`.
   * `apps/admin/test/argon2-agreement.test.ts` pins those backends to identical
   * bytes, so the key derived here is the key a browser derives.
   */
  it(
    "signs up, creates an org, a project, an environment and a secret, then reads it back decrypted",
    async () => {
      const t = convexTest(schema, modules);

      const email = "founder@example.test";
      const password = "correct horse battery staple";

      // ---- 1. Signup, exactly as `auth-flows.ts` performs it. --------------
      // The salt is RANDOM, minted here, and the key is derived under exactly
      // these bytes. The same bytes, hex encoded, are what the server stores
      // and what `getLoginSalt` hands back at every later login; sending any
      // other value would make this account's key underivable.
      const normalised = normaliseWebEmail(email);
      const accountSalt = newAccountSalt();
      const userUid = newId("usr");
      const muk = await deriveMUK(password, accountSalt);
      const { wrapped, pub } = await createIdentity(muk);
      const authVerifier = deriveAuthVerifier(muk);

      const signedUpUserId = await t.mutation(api.auth.signup, {
        uid: userUid,
        accountSalt: toHex(accountSalt),
        email: normalised,
        authVerifier,
        publicKey: wrapped.publicKey,
        verifyKey: wrapped.verifyKey,
        wrappedPrivateKey: wrapped.wrappedPrivateKey,
        wrappedSigningKey: wrapped.wrappedSigningKey,
      });

      // Only public material and two opaque blobs went over the wire. Asserted
      // rather than assumed, because "the server never sees it" is the whole
      // product and a regression would be invisible.
      const storedUser = await t.run(async (ctx) => getUserRow(ctx, signedUpUserId));
      const userDump = JSON.stringify(storedUser);
      expect(userDump).not.toContain(password);
      expect(userDump).not.toContain(toHex(muk.bytes));

      // ---- 2. Login, from the salt the server hands back. ------------------
      // The salt a later login derives under is `getLoginSalt`'s answer, so it
      // must be byte for byte the salt the key above was derived under, or the
      // account is locked out at its first real login. Compared as bytes
      // rather than re-derived: Argon2id is deterministic, the same salt gives
      // the same key, and a second 64 MiB derivation here would only double
      // this test's run time.
      const loginSalt = await t.query(api.auth.getLoginSalt, { email: normalised });
      expect(toHex(fromHex(loginSalt.accountSalt))).toBe(toHex(accountSalt));

      const session = await t.mutation(api.auth.login, { email: normalised, authVerifier });
      const sessionToken = session.sessionToken;
      const restored = await unwrapIdentity(muk, session);
      expect(identityMatches(restored, pub)).toBe(true);
      expect(session.userId).toBe(signedUpUserId);
      // The permanent uid every grant below is addressed to.
      expect(session.userUid).toBe(userUid);

      // ---- 3. An organisation, whose revocation key is minted HERE. -------
      // This is the product's wedge. The seed below is the only thing that can
      // sign a notice any SDK will honour, it is generated in the client, and
      // this deployment has never held it. The org's permanent uid is minted
      // first, because the wrap is bound to it.
      const orgUid = newId("org");
      const revocationKeypair = createRevocationKeypair();
      const wrappedRevocation = await wrapRevocationKey(muk, revocationKeypair.privateKey, {
        orgUid,
        granteeUid: session.userUid,
      });
      const orgId = await t.mutation(api.orgs.createOrg, {
        sessionToken,
        orgUid,
        name: "Acme Rockets",
        slug: "acme-rockets",
        revocationPublicKey: revocationKeypair.revocationPublicKey,
        ...wrappedRevocation,
      });

      // ---- 4. Open the revocation grant and sign with what comes back. ----
      // From here the test uses `recoveredKey` and never `revocationKeypair
      // .privateKey`. Using the local copy would let a grant that round trips
      // incorrectly pass unnoticed, which is the entire failure this link
      // exists to catch: an org whose kill switch cannot be armed, discovered
      // during the incident it exists for.
      const revocationGrant = await t.query(api.orgs.getMyRevocationGrant, {
        sessionToken,
        orgId,
      });
      expect(revocationGrant.orgUid).toBe(orgUid);
      // The server stores the wrap and the public half; the seed is in neither.
      const grantDump = JSON.stringify(
        await t.run(async (ctx) => getRevocationGrantRow(ctx, orgId, signedUpUserId)),
      );
      expect(grantDump).not.toContain(toHex(revocationKeypair.privateKey));
      expect(grantDump).not.toContain(toHex(muk.bytes));

      // Opened under the org uid the SERVER returned, which the unwrap then
      // authenticates: a grant filed under another org would not open.
      const recoveredKey = await unwrapRevocationKey(
        muk,
        {
          wrappedRevocationKey: revocationGrant.wrappedRevocationKey,
          nonce: revocationGrant.nonce,
        },
        { orgUid: revocationGrant.orgUid, granteeUid: session.userUid },
      );
      expect(toHex(recoveredKey)).toBe(toHex(revocationKeypair.privateKey));

      // The same blob under another org's uid must not open, or the org
      // binding is decoration.
      await expect(
        unwrapRevocationKey(
          muk,
          {
            wrappedRevocationKey: revocationGrant.wrappedRevocationKey,
            nonce: revocationGrant.nonce,
          },
          { orgUid: newId("org"), granteeUid: session.userUid },
        ),
      ).rejects.toThrow(RevocationKeyUnwrapError);

      // The seed and the column the org publishes belong together. The
      // associated data binds the org and the grantee and cannot bind the
      // public key, which is a column the server publishes; this is the check
      // that stands in for it.
      const storedOrg = await t.query(api.orgs.getOrg, { sessionToken, orgId });
      expect(revocationKeyMatches(recoveredKey, storedOrg.revocationPublicKey)).toBe(true);

      // AND IT SIGNS. A notice built the way the SDK will read one, signed by
      // the key that came back out of the database, verified against the public
      // key the SERVER stored rather than the one the client kept.
      const noticeToSign = {
        tokenId: "3f".repeat(16),
        epoch: 1,
        revokedAt: 1_800_000_000_000,
        reason: "Laptop stolen.",
      };
      const signature = signRevocation(recoveredKey, noticeToSign);
      expect(verifyRevocation(storedOrg.revocationPublicKey, noticeToSign, signature)).toBe(true);

      // A different org's key must not verify under this one, or the check
      // above is a check that accepts anything.
      const stranger = createRevocationKeypair();
      expect(
        verifyRevocation(
          storedOrg.revocationPublicKey,
          noticeToSign,
          signRevocation(stranger.privateKey, noticeToSign),
        ),
      ).toBe(false);

      // ---- 5. A project. ---------------------------------------------------
      const projectId = await t.mutation(api.projects.createProject, {
        sessionToken,
        orgId,
        name: "API",
        slug: "api",
      });

      // ---- 6. An environment, whose project data key is minted HERE. -------
      // The server has never held the plaintext of this key and cannot: it
      // arrives wrapped, under associated data this deployment computes
      // nowhere, bound to the environment uid and key version minted here.
      const environmentUid = newId("env");
      const pdk = createProjectDataKey();
      const wrappedPdk = await wrapProjectDataKey(muk, pdk, {
        environmentUid,
        pdkVersion: 1,
        granteeType: "user",
        granteeId: session.userUid,
      });
      const environmentId = await t.mutation(api.environments.createEnvironment, {
        sessionToken,
        environmentUid,
        projectId,
        name: "production",
        ...wrappedPdk,
        pdkVersion: 1,
      });

      // ---- 7. Fetch the environment and the grant back, and open it. ------
      // Exactly as `use-project-data-key.ts` does: the uid from the
      // ENVIRONMENT, the version from the GRANT, the grantee from the session.
      // From this line on the test uses `key`, built from what the server
      // returned, NOT `pdk` or `environmentUid`. Using the local copies would
      // let a round trip that came back wrong pass unnoticed, which is exactly
      // the failure this whole chain exists to catch.
      const environment = await t.query(api.environments.getEnvironment, {
        sessionToken,
        environmentId,
      });
      expect(environment.uid).toBe(environmentUid);
      const grant = await t.query(api.environments.getMyPdkGrant, {
        sessionToken,
        environmentId,
      });
      expect(grant.environmentId).toBe(environmentId);
      expect(grant.pdkVersion).toBe(1);

      const openedPdk = await unwrapProjectDataKey(
        muk,
        { wrappedPDK: grant.wrappedPDK, nonce: grant.nonce },
        {
          environmentUid: environment.uid,
          pdkVersion: grant.pdkVersion,
          granteeType: "user",
          granteeId: session.userUid,
        },
      );
      expect(toHex(openedPdk)).toBe(toHex(pdk));
      const key: EnvironmentKey = {
        pdk: openedPdk,
        environmentUid: environment.uid,
        pdkVersion: grant.pdkVersion,
      };

      // ---- 8. Seal a secret for a fresh slot and write it. ----------------
      const NAME = "DATABASE_URL";
      const VALUE = "postgres://app:hunter2@db.internal:5432/production";

      const slot = newSecretSlot();
      const sealed = await sealSecret(key, { ...slot, name: NAME, value: VALUE });
      const created = await t.mutation(api.secrets.createSecret, {
        sessionToken,
        environmentId,
        secretUid: slot.secretUid,
        version: slot.version,
        pdkVersion: key.pdkVersion,
        ...sealed,
      });
      expect(created.secretUid).toBe(slot.secretUid);

      // The row the server stored contains neither the name nor the value.
      const storedRow = await t.run(async (ctx) => getSecretRow(ctx, created.secretId));
      const rowDump = JSON.stringify(storedRow);
      expect(rowDump).not.toContain(NAME);
      expect(rowDump).not.toContain(VALUE);
      expect(rowDump).not.toContain(toHex(openedPdk));

      // ---- 9. List it and open it, which is what the dashboard does. -------
      const listed = await t.query(api.secrets.listSecrets, { sessionToken, environmentId });
      expect(listed).toHaveLength(1);

      const row = listed[0];
      if (row === undefined) throw new Error("the listing returned no row");
      expect(row.secretUid).toBe(slot.secretUid);
      expect(row.version).toBe(1);
      const opened = await openSecret(key, row);
      expect(opened.name).toBe(NAME);
      expect(opened.value).toBe(VALUE);

      // ---- 10. And the slot binding actually binds. ------------------------
      // The same key, the same ciphertext, one part of the slot changed. Each
      // must fail, or that part of the binding is decoration. The environment
      // is a real second environment's uid, read back from the server.
      const stagingUid = newId("env");
      const otherEnvironmentId = await t.mutation(api.environments.createEnvironment, {
        sessionToken,
        environmentUid: stagingUid,
        projectId,
        name: "staging",
        ...(await wrapProjectDataKey(muk, createProjectDataKey(), {
          environmentUid: stagingUid,
          pdkVersion: 1,
          granteeType: "user",
          granteeId: session.userUid,
        })),
        pdkVersion: 1,
      });
      const otherEnvironment = await t.query(api.environments.getEnvironment, {
        sessionToken,
        environmentId: otherEnvironmentId,
      });
      await expect(
        openSecret({ ...key, environmentUid: otherEnvironment.uid }, row),
      ).rejects.toThrow(SecretOpenError);
      await expect(openSecret(key, { ...row, secretUid: newId("sec") })).rejects.toThrow(
        SecretOpenError,
      );
      await expect(
        openSecretName(key, {
          ...row,
          nameCiphertext: row.valueCiphertext,
          nameNonce: row.valueNonce,
        }),
      ).rejects.toThrow(SecretOpenError);

      // ---- 11. An update, through the same path, reads back updated. ------
      // The slot for the next version, built from the row as the server
      // returned it: same permanent uid, version plus one.
      const NEW_VALUE = "postgres://app:hunter3@db.internal:5432/production";
      const nextSlot = nextSecretSlot(row);
      const resealed = await sealSecret(key, { ...nextSlot, name: NAME, value: NEW_VALUE });
      const updated = await t.mutation(api.secrets.updateSecret, {
        sessionToken,
        secretId: created.secretId,
        version: nextSlot.version,
        pdkVersion: key.pdkVersion,
        ...resealed,
      });
      expect(updated.secretUid).toBe(slot.secretUid);

      const after = await t.query(api.secrets.listSecrets, { sessionToken, environmentId });
      const currentRow = after[0];
      if (currentRow === undefined) throw new Error("the listing returned no row");
      expect(currentRow.version).toBe(2);
      expect(currentRow.secretUid).toBe(slot.secretUid);
      expect((await openSecret(key, currentRow)).value).toBe(NEW_VALUE);
      // Version 1's ciphertext presented as version 2 does not open as current.
      await expect(
        openSecretValue(key, {
          ...currentRow,
          valueCiphertext: row.valueCiphertext,
          valueNonce: row.valueNonce,
        }),
      ).rejects.toThrow(SecretOpenError);

      // ---- 12. A stale write is refused, and the dashboard says so. -------
      // A second tab that opened version 1 and seals "version 2" now loses the
      // race. The server refuses it with its own sentence, and the dashboard's
      // mapping shows that sentence unchanged with a reload control. This is
      // the assertion that pins the exact text `write-errors.ts` matches on.
      const staleSealed = await sealSecret(key, { ...nextSlot, name: NAME, value: "lost race" });
      const refusal = await t
        .mutation(api.secrets.updateSecret, {
          sessionToken,
          secretId: created.secretId,
          version: nextSlot.version,
          pdkVersion: key.pdkVersion,
          ...staleSealed,
        })
        .then(
          () => null,
          (cause: unknown) => cause,
        );
      expect(describeWriteFailure(refusal)).toEqual({
        message: STALE_SECRET_VERSION,
        reload: true,
      });

      // And a write stating a key generation the environment is not at, as a
      // tab would after somebody else re-keyed the environment under it.
      const freshSlot = newSecretSlot();
      const wrongKeyVersion = await t
        .mutation(api.secrets.createSecret, {
          sessionToken,
          environmentId,
          secretUid: freshSlot.secretUid,
          version: freshSlot.version,
          pdkVersion: key.pdkVersion + 1,
          ...(await sealSecret(key, { ...freshSlot, name: "X", value: "y" })),
        })
        .then(
          () => null,
          (cause: unknown) => cause,
        );
      expect(describeWriteFailure(wrongKeyVersion)).toEqual({
        message: STALE_ENVIRONMENT_KEY,
        reload: true,
      });
    },
    // One Argon2id derivation at 64 MiB inside the edge-runtime VM. The
    // default five seconds is not enough, and a flake here would be read as a
    // real failure.
    120_000,
  );
});

// ---------------------------------------------------------------------------
// When a secret last changed.
// ---------------------------------------------------------------------------

describe("updatedAt", () => {
  /**
   * An update inserts a new row, so the current row's creation time IS the
   * moment the secret last changed. The dashboard shows it per row; nothing
   * about it is a name or a value.
   */
  it("is the current row's creation time, and moves forward on an update", async () => {
    const t = convexTest(schema, modules);
    const { alice, a } = await world(t);
    const { secretId } = await t.mutation(
      api.secrets.createSecret,
      secretArgs(alice, a.production),
    );
    const [before] = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    const created = await t.run(async (ctx) => getSecretRow(ctx, secretId));
    expect(before?.updatedAt).toBe(created?._creationTime);

    const updated = await t.mutation(api.secrets.updateSecret, {
      sessionToken: alice.sessionToken,
      secretId,
      version: 2,
      pdkVersion: 1,
      nameCiphertext: NAME_CIPHERTEXT,
      nameNonce: "c0c1c2c3c4c5c6c7c8c9cacb",
      valueCiphertext: VALUE_CIPHERTEXT,
      valueNonce: "cbcac9c8c7c6c5c4c3c2c1c0",
    });
    const [after] = await t.query(api.secrets.listSecrets, {
      sessionToken: alice.sessionToken,
      environmentId: a.production,
    });
    const replacement = await t.run(async (ctx) =>
      getSecretRow(ctx, updated.secretId),
    );
    expect(after?.secretId).toBe(updated.secretId);
    expect(after?.updatedAt).toBe(replacement?._creationTime);
    expect(after?.updatedAt).toBeGreaterThanOrEqual(
      before?.updatedAt ?? Number.POSITIVE_INFINITY,
    );
  });
});
