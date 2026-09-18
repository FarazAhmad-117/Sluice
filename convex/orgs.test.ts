import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import { getOrgMember, getRevocationGrant } from "./repo/orgs";
import { listAuditEventsByActor } from "./repo/audit";
import * as orgsModule from "./orgs";

export const modules = import.meta.glob("./**/*.ts");

type Harness = ReturnType<typeof convexTest>;

/**
 * A seeded person, and the only way this suite can act as one.
 *
 * `userId` is here for the assertions that read rows back, never for a call:
 * no handler takes a user id any more. Acting is `sessionToken` and nothing
 * else.
 */
export type Actor = { userId: Id<"users">; sessionToken: string };

/**
 * Seeded through the repo layer rather than through `signup` and `login`,
 * because these tests are about the hierarchy and a pepper is not their
 * business. The enumeration test in `repo/repo.test.ts` scans this file too,
 * so seeding straight through the database handle on the context is
 * unavailable on purpose, and the phrase for doing so cannot even be written
 * here.
 *
 * The token is derived from the email so a failure names a readable value, and
 * it is hashed by the same function the server uses, so the fixture cannot
 * drift from the implementation without this suite going red.
 */
export async function seedUser(t: Harness, email: string): Promise<Actor> {
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

const REVOCATION_PUBLIC_KEY = "ab".repeat(32);
// 12 bytes in lowercase hex, which is what `toHex(seal().nonce)` produces.
const NONCE = "0f1e2d3c4b5a69788796a5b4";

function orgArgs(actor: Actor, overrides: Record<string, unknown> = {}) {
  return {
    sessionToken: actor.sessionToken,
    name: "Acme Rockets",
    slug: "acme-rockets",
    revocationPublicKey: REVOCATION_PUBLIC_KEY,
    wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
    revocationKeyNonce: NONCE,
    ...overrides,
  };
}

/**
 * The failure every authorisation path shares. It is one string on purpose: a
 * caller must not be able to tell "this org does not exist" from "this org
 * exists and is not yours", because the second answer confirms the existence
 * of another tenant's row one guess at a time.
 */
const NOT_PERMITTED = "Not found, or you do not have access to it.";

/**
 * The other refusal, for a caller who is nobody rather than a caller who is
 * somebody without access. Kept as a literal here rather than imported, so
 * that changing the constant in `lib/authz.ts` has to be a deliberate edit to
 * the tests as well.
 */
const NOT_AUTHENTICATED = "Your session is not valid. Sign in again.";

/**
 * A well formed id for the same table that no row has. Derived from a real one
 * so it carries the table tag Convex's id validator checks, which is the only
 * way to get past the validator and reach the handler at all.
 */
function absentIdLike<T extends string>(id: T): T {
  const digits = "0123456789";
  const flipped = id
    .split("")
    .map((c) => (digits.includes(c) ? (c === "9" ? "0" : "9") : c))
    .join("");
  return flipped as T;
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    throw new Error("expected the call to fail, but it resolved");
  } catch (error) {
    return error;
  }
}

// ---------------------------------------------------------------------------
// Authorisation first. These are written before the happy path because they
// are the tests that get forgotten once the happy path works.
// ---------------------------------------------------------------------------

describe("orgs authorisation", () => {
  it("refuses getOrg to a user who is not a member", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const outsider = await seedUser(t, "outsider@example.test");
    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(owner));

    await expect(
      t.query(api.orgs.getOrg, { sessionToken: outsider.sessionToken, orgId }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("refuses getMyRevocationGrant to a user who is not a member", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const outsider = await seedUser(t, "outsider@example.test");
    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(owner));

    await expect(
      t.query(api.orgs.getMyRevocationGrant, { sessionToken: outsider.sessionToken, orgId }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  /**
   * THIS TEST CHANGED MEANING, AND THE OLD MEANING IS GONE ON PURPOSE.
   *
   * It used to read "refuses createOrg to a caller id that is well formed but
   * not a user", and it passed a forged `callerId` built with `absentIdLike`.
   * That test cannot be written any more, because `createOrg` no longer has a
   * caller id to forge: identity comes from the session row. It is not being
   * quietly dropped, it is being replaced by the question that now matters,
   * which is whether an unrecognised CREDENTIAL is refused. The refusal is
   * `NOT_AUTHENTICATED` rather than `NOT_PERMITTED`, because the caller is not
   * anybody at all rather than somebody without access.
   *
   * `session.test.ts` covers the other three ways a credential can fail, and
   * `unauthenticated.test.ts` covers every function rather than just this one.
   */
  it("refuses createOrg to a token that was never issued", async () => {
    const t = convexTest(schema, modules);
    const real = await seedUser(t, "real@example.test");

    await expect(
      t.mutation(
        api.orgs.createOrg,
        orgArgs(
          { userId: real.userId, sessionToken: "ff".repeat(32) },
          { slug: "other" },
        ),
      ),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  /**
   * Convex ids carry their table and `v.id(...)` checks it, so an id crafted
   * from another table cannot reach a handler at all. The property is
   * unchanged; only the argument it can be demonstrated on has moved, because
   * there is no longer a `v.id("users")` anywhere in the public surface. It is
   * shown here on `getOrg`, which means the handlers below are defending
   * against a wrong-row-same-table attack and nothing weirder.
   */
  it("refuses an id belonging to another table before the handler runs", async () => {
    const t = convexTest(schema, modules);
    const real = await seedUser(t, "real@example.test");

    await expect(
      t.query(api.orgs.getOrg, {
        sessionToken: real.sessionToken,
        orgId: real.userId as unknown as Id<"orgs">,
      }),
    ).rejects.toThrow('Expected ID for table "orgs"');
  });

  /**
   * The id that no row has, kept because it is the only way to prove the
   * handler refuses rather than the validator. `absentIdLike` exists for it.
   */
  it("refuses an org id that is well formed but has no row", async () => {
    const t = convexTest(schema, modules);
    const real = await seedUser(t, "real@example.test");
    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(real));

    await expect(
      t.query(api.orgs.getOrg, {
        sessionToken: real.sessionToken,
        orgId: absentIdLike(orgId),
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  it("tells a member of one org nothing about another org", async () => {
    const t = convexTest(schema, modules);
    const a = await seedUser(t, "a@example.test");
    const b = await seedUser(t, "b@example.test");
    await t.mutation(api.orgs.createOrg, orgArgs(a, { slug: "org-a" }));
    const orgB = await t.mutation(api.orgs.createOrg, orgArgs(b, { slug: "org-b" }));

    const refused = await failure(
      t.query(api.orgs.getOrg, { sessionToken: a.sessionToken, orgId: orgB }),
    );
    expect((refused as { data?: unknown }).data).toBe(NOT_PERMITTED);
  });

  it("returns only the caller's own orgs from listMyOrgs", async () => {
    const t = convexTest(schema, modules);
    const a = await seedUser(t, "a@example.test");
    const b = await seedUser(t, "b@example.test");
    await t.mutation(api.orgs.createOrg, orgArgs(a, { slug: "org-a" }));
    await t.mutation(api.orgs.createOrg, orgArgs(b, { slug: "org-b" }));

    const mine = await t.query(api.orgs.listMyOrgs, { sessionToken: a.sessionToken });
    expect(mine.map((o) => o.slug)).toEqual(["org-a"]);
  });
});

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

describe("createOrg", () => {
  it("creates the org, the owner membership and the revocation grant in one mutation", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");

    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(owner));

    const member = await t.run(async (ctx) => getOrgMember(ctx, orgId, owner.userId));
    expect(member?.role).toBe("owner");

    // The whole wedge. An org with no grant is an org nobody can ever sign a
    // revocation notice for, and nothing later in the product would notice
    // until the moment it mattered most.
    const grant = await t.run(async (ctx) =>
      getRevocationGrant(ctx, orgId, owner.userId),
    );
    expect(grant?.wrappedRevocationKey).toBe("7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264");
    expect(grant?.nonce).toBe(NONCE);
  });

  // BE HONEST ABOUT WHAT THIS PROVES. Every check in `createOrg` runs before
  // the first insert, so this would also pass against an implementation that
  // simply never got as far as writing anything. It is not evidence of
  // rollback; Convex's transaction is. What it does pin is that rejected grant
  // material cannot leave a half-built org behind, which is the state that
  // would be invisible until a revocation was needed.
  it("leaves no org at all when the grant material is rejected", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");

    await expect(
      t.mutation(
        api.orgs.createOrg,
        orgArgs(owner, { wrappedRevocationKey: "" }),
      ),
    ).rejects.toThrow();

    expect(await t.query(api.orgs.listMyOrgs, { sessionToken: owner.sessionToken })).toEqual([]);
  });

  it("rejects a duplicate slug", async () => {
    const t = convexTest(schema, modules);
    const a = await seedUser(t, "a@example.test");
    const b = await seedUser(t, "b@example.test");
    await t.mutation(api.orgs.createOrg, orgArgs(a));

    await expect(
      t.mutation(api.orgs.createOrg, orgArgs(b)),
    ).rejects.toThrow("An organisation with that slug already exists.");
  });

  it("rejects a slug that is not in canonical form", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");

    for (const slug of [
      "Acme",
      "acme rockets",
      "-acme",
      "acme-",
      "acme--rockets",
      "acme_rockets",
      "",
      "a".repeat(49),
      "acmé",
      "ACME",
    ]) {
      await expect(
        t.mutation(api.orgs.createOrg, orgArgs(owner, { slug })),
      ).rejects.toThrow("slug");
    }
  });

  // Uppercase is rejected rather than folded, so there is exactly one spelling
  // of a slug in the table and the uniqueness check cannot be sidestepped by
  // changing case.
  it("does not fold case to make a duplicate slug look new", async () => {
    const t = convexTest(schema, modules);
    const a = await seedUser(t, "a@example.test");
    await t.mutation(api.orgs.createOrg, orgArgs(a));

    await expect(
      t.mutation(api.orgs.createOrg, orgArgs(a, { slug: "ACME-ROCKETS" })),
    ).rejects.toThrow("slug");
  });

  it("rejects a revocation public key that is not 64 lowercase hex characters", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");

    for (const key of [
      "",
      "AB".repeat(32),
      "ab".repeat(31),
      "0x" + "ab".repeat(32),
      "zz".repeat(32),
    ]) {
      await expect(
        t.mutation(
          api.orgs.createOrg,
          orgArgs(owner, { revocationPublicKey: key }),
        ),
      ).rejects.toThrow("revocationPublicKey");
    }
  });

  it("rejects a revocation key nonce that is not 24 lowercase hex characters", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");

    for (const nonce of ["", "abc", NONCE.toUpperCase(), NONCE + "00"]) {
      await expect(
        t.mutation(
          api.orgs.createOrg,
          orgArgs(owner, { revocationKeyNonce: nonce }),
        ),
      ).rejects.toThrow("revocationKeyNonce");
    }
  });

  it("rejects a display name that is empty or absurdly long", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");

    for (const name of ["", "   ", "a".repeat(101)]) {
      await expect(
        t.mutation(api.orgs.createOrg, orgArgs(owner, { name })),
      ).rejects.toThrow("name");
    }
  });

  // Truncation is how a 101 character name becomes a 100 character name that
  // nobody typed. Reject instead.
  it("does not silently truncate a long display name", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const name = "a".repeat(100);

    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(owner, { name }));
    const org = await t.query(api.orgs.getOrg, { sessionToken: owner.sessionToken, orgId });
    expect(org.name).toBe(name);
  });
});

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

describe("getOrg", () => {
  it("returns public material and the caller's role, and no wrapped key", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(owner));

    const org = await t.query(api.orgs.getOrg, { sessionToken: owner.sessionToken, orgId });

    expect(org).toEqual({
      orgId,
      name: "Acme Rockets",
      slug: "acme-rockets",
      revocationPublicKey: REVOCATION_PUBLIC_KEY,
      role: "owner",
    });
  });
});

describe("getMyRevocationGrant", () => {
  it("returns the caller's own wrapped revocation key", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(owner));

    const grant = await t.query(api.orgs.getMyRevocationGrant, {
      sessionToken: owner.sessionToken,
      orgId,
    });

    expect(grant).toEqual({
      wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
      nonce: NONCE,
      revocationPublicKey: REVOCATION_PUBLIC_KEY,
    });
  });
});

// ---------------------------------------------------------------------------
// The public surface
// ---------------------------------------------------------------------------

describe("the orgs surface", () => {
  /**
   * The real answer to "can an org exist without a revocation grant" is that
   * `createOrg` is the only function that inserts one, and it writes the grant
   * in the same transaction. Nothing in the language enforces that, so this
   * pins the surface: a second way to create an org cannot be added without
   * editing this list, which puts it in the diff where someone will ask.
   *
   * The same idea as the pinned export list in `packages/crypto`.
   */
  it("exports exactly the functions it is supposed to", () => {
    expect(Object.keys(orgsModule).sort()).toEqual([
      "createOrg",
      "getMyRevocationGrant",
      "getOrg",
      "listMyOrgs",
    ]);
  });
});

// ---------------------------------------------------------------------------
// The audit log
// ---------------------------------------------------------------------------

describe("the audit log", () => {
  // `actorId` is indexed and this table has no delete. An email written here
  // is plaintext PII that can never be removed, so the actor is a user id.
  it("records the creation against a user id and never an email", async () => {
    const t = convexTest(schema, modules);
    const owner = await seedUser(t, "owner@example.test");
    const orgId = await t.mutation(api.orgs.createOrg, orgArgs(owner));

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, owner.userId, 10),
    );

    expect(events).toHaveLength(1);
    const event = events[0];
    expect(event?.orgId).toBe(orgId);
    expect(event?.actorType).toBe("user");
    expect(event?.actorId).toBe(owner.userId);
    expect(event?.action).toBe("org.create");
    expect(event?.targetId).toBe(orgId);
    expect(event?.metadata).toBeUndefined();
    expect(JSON.stringify(events)).not.toContain("example.test");
  });
});

/**
 * The bar the fixtures were hiding.
 *
 * Until 2026-09-18 this field accepted any non-empty string, so `"x"` was a
 * legal wrap for an org's revocation signing key. Every fixture in `convex/`
 * passed an opaque placeholder that was not hex, which is exactly why the
 * missing check went unnoticed: the suite had normalised the malformed shape.
 * These cases exist so a future relaxation fails here rather than in an
 * incident.
 */
describe("the wrapped revocation key must look like a wrap", () => {
  it("refuses a non-hex blob, which is what every fixture used to pass", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    await expect(
      t.mutation(api.orgs.createOrg, {
        sessionToken: alice.sessionToken,
        name: "Acme Rockets",
        slug: "acme-rockets",
        revocationPublicKey: "33".repeat(32),
        wrappedRevocationKey: "wrapped-revocation-key-blob",
        revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
      }),
    ).rejects.toThrow(/wrappedRevocationKey/);
  });

  it("refuses a blob shorter than an AES-GCM tag", async () => {
    const t = convexTest(schema, modules);
    const alice = await seedUser(t, "alice@example.test");
    await expect(
      t.mutation(api.orgs.createOrg, {
        sessionToken: alice.sessionToken,
        name: "Acme Rockets",
        slug: "acme-rockets",
        // 15 bytes. A GCM ciphertext is never shorter than its 16 byte tag,
        // so this cannot be output this product produced.
        revocationPublicKey: "33".repeat(32),
        wrappedRevocationKey: "ab".repeat(15),
        revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
      }),
    ).rejects.toThrow(/wrappedRevocationKey/);
  });
});
