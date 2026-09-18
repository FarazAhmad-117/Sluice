import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import { mintToken, signRevocation, toHex } from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { listAuditEventsByActor } from "./repo/audit";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import * as orgsModule from "./orgs";
import * as projectsModule from "./projects";
import * as environmentsModule from "./environments";
import * as secretsModule from "./secrets";
import * as tokensModule from "./tokens";

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
 * THE TEST NONE OF THE AUTHORISATION SUITES CAN EXPRESS.
 *
 * `orgs.test.ts`, `projects.test.ts`, `environments.test.ts` and
 * `secrets.test.ts` all prove that a caller who IS somebody, and who is not a
 * member, is refused. Not one of them could prove anything about a caller who
 * is NOBODY, because until sessions existed there was no such thing: identity
 * was an argument, so every caller was whoever they said they were.
 *
 * This file asks the other question, of every single public function rather
 * than of a sample, and of all four ways a credential can be bad: never
 * issued, expired, logged out, and absent.
 *
 * It is written against an ENUMERATION of the exported surface rather than a
 * hand written list of calls, because a hand written list is a list somebody
 * adds a handler without. The enumeration is cross checked against
 * `CALLS` below, so a new public function fails this suite until someone has
 * written down how to call it, and that failure is the point.
 */

const NOT_AUTHENTICATED = "Your session is not valid. Sign in again.";

/**
 * `bundle` is deliberately absent, and that absence is a decision rather than
 * an oversight.
 *
 * Every module here authenticates a PERSON, through `sessionArg` and the
 * `sessions` table. The bundle subscription authenticates a MACHINE, through
 * the short-lived token the handshake issues, and it takes no session at all:
 * a service token has no user and must never be given one. Listing it here
 * would fail the structural assertion below for the right reason and then
 * tempt somebody to fix it by giving the bundle a `sessionToken` argument,
 * which would be exactly backwards. `bundle.test.ts` asks the equivalent
 * question of the credential the bundle actually takes.
 */
const SURFACE = {
  orgs: orgsModule,
  projects: projectsModule,
  environments: environmentsModule,
  secrets: secretsModule,
  tokens: tokensModule,
} as const;

type Registered = {
  isQuery?: boolean;
  isMutation?: boolean;
  exportArgs: () => string;
};

/** Every exported function, as `module.name`, discovered rather than listed. */
function exportedFunctions(): string[] {
  const out: string[] = [];
  for (const [namespace, mod] of Object.entries(SURFACE)) {
    for (const name of Object.keys(mod)) out.push(`${namespace}.${name}`);
  }
  return out.sort();
}

function registered(path: string): Registered {
  const [namespace, name] = path.split(".") as [keyof typeof SURFACE, string];
  return (SURFACE[namespace] as unknown as Record<string, Registered>)[
    name
  ] as Registered;
}

function argNames(path: string): string[] {
  const parsed = JSON.parse(registered(path).exportArgs()) as {
    value: Record<string, unknown>;
  };
  return Object.keys(parsed.value);
}

function reference(path: string): unknown {
  const [namespace, name] = path.split(".") as [keyof typeof SURFACE, string];
  return (api as unknown as Record<string, Record<string, unknown>>)[namespace]?.[
    name
  ];
}

// ---------------------------------------------------------------------------
// A world, and one valid call for every function in it.
// ---------------------------------------------------------------------------

type Actor = { userId: Id<"users">; sessionToken: string };

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

const NAME_CIPHERTEXT = "aa".repeat(24);
const VALUE_CIPHERTEXT = "bb".repeat(40);
const NAME_NONCE = "000102030405060708090a0b";
const VALUE_NONCE = "0b0a090807060504030201ff";

interface World {
  alice: Actor;
  orgId: Id<"orgs">;
  projectId: Id<"projects">;
  environmentId: Id<"environments">;
  secretId: Id<"secrets">;
  /** A registered service token, and the signed notice that revokes it. */
  revoke: {
    tokenId: string;
    epoch: number;
    revokedAt: number;
    reason: string;
    signature: string;
  };
  /** A minted but unregistered token, so `createServiceToken` has one to take. */
  spare: { tokenId: string; publicKey: string };
}

/**
 * Built through the real public API, so every id below is one the handlers
 * would accept. That matters more here than anywhere else in the suite: if the
 * arguments were junk, every call would fail for a reason that has nothing to
 * do with the credential and this whole file would pass against a backend with
 * no session layer at all.
 */
async function world(t: Harness): Promise<World> {
  const alice = await seedUser(t, "alice@example.test");
  // A REAL organisation revocation keypair, built out of the crypto package's
  // own public surface: `mintToken` hands back an Ed25519 seed and its public
  // key, which is exactly the pair `signRevocation` wants. The placeholder
  // that used to be here was fine while nothing verified it, and stopped being
  // fine the moment `revokeServiceToken` started checking the signature.
  const orgKeys = mintToken({ environment: "revocation" });
  const orgId = await t.mutation(api.orgs.createOrg, {
    sessionToken: alice.sessionToken,
    name: "Acme Rockets",
    slug: "acme-rockets",
    revocationPublicKey: orgKeys.upload.publicKey,
    wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  });
  const projectId = await t.mutation(api.projects.createProject, {
    sessionToken: alice.sessionToken,
    orgId,
    name: "API",
    slug: "api",
  });
  const environmentId = await t.mutation(api.environments.createEnvironment, {
    sessionToken: alice.sessionToken,
    projectId,
    name: "production",
    ...WRAP,
  });
  const { secretId } = await t.mutation(api.secrets.createSecret, {
    sessionToken: alice.sessionToken,
    environmentId,
    nameCiphertext: NAME_CIPHERTEXT,
    nameNonce: NAME_NONCE,
    valueCiphertext: VALUE_CIPHERTEXT,
    valueNonce: VALUE_NONCE,
  });
  const victim = mintToken({ environment: "production" });
  await t.mutation(api.tokens.createServiceToken, {
    sessionToken: alice.sessionToken,
    environmentId,
    tokenId: victim.upload.tokenId,
    publicKey: victim.upload.publicKey,
    wrappedPDK: "cc".repeat(48),
    pdkNonce: "0102030405060708090a0b0c",
  });
  const notice = {
    tokenId: victim.upload.tokenId,
    epoch: 1,
    revokedAt: Date.now(),
    reason: "Rotated on schedule.",
  };

  const spare = mintToken({ environment: "production" });

  return {
    alice,
    orgId,
    projectId,
    environmentId,
    secretId,
    revoke: {
      ...notice,
      signature: toHex(signRevocation(orgKeys.authSeed, notice)),
    },
    spare: {
      tokenId: spare.upload.tokenId,
      publicKey: spare.upload.publicKey,
    },
  };
}

/**
 * How to call each function so that it SUCCEEDS for the session in `w`. The
 * key set is asserted against the discovered surface below, which is what
 * makes forgetting to add one here impossible rather than merely unlikely.
 */
const CALLS: Record<
  string,
  (w: World, sessionToken: string) => Record<string, unknown>
> = {
  "orgs.createOrg": (_w, sessionToken) => ({
    sessionToken,
    name: "Second Org",
    // A slug the world fixture has not used, so the valid call below is not
    // refused for being a duplicate.
    slug: "second-org",
    revocationPublicKey: "cd".repeat(32),
    wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
    revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
  }),
  "orgs.getOrg": (w, sessionToken) => ({ sessionToken, orgId: w.orgId }),
  "orgs.listMyOrgs": (_w, sessionToken) => ({ sessionToken }),
  "orgs.getMyRevocationGrant": (w, sessionToken) => ({
    sessionToken,
    orgId: w.orgId,
  }),
  "projects.createProject": (w, sessionToken) => ({
    sessionToken,
    orgId: w.orgId,
    name: "Billing",
    slug: "billing",
  }),
  "projects.getProject": (w, sessionToken) => ({
    sessionToken,
    projectId: w.projectId,
  }),
  "projects.listProjects": (w, sessionToken) => ({
    sessionToken,
    orgId: w.orgId,
  }),
  "environments.createEnvironment": (w, sessionToken) => ({
    sessionToken,
    projectId: w.projectId,
    name: "staging",
    ...WRAP,
  }),
  "environments.getEnvironment": (w, sessionToken) => ({
    sessionToken,
    environmentId: w.environmentId,
  }),
  "environments.getMyPdkGrant": (w, sessionToken) => ({
    sessionToken,
    environmentId: w.environmentId,
  }),
  "environments.listEnvironments": (w, sessionToken) => ({
    sessionToken,
    projectId: w.projectId,
  }),
  // These nonces are deliberately distinct from NAME_NONCE and VALUE_NONCE,
  // which `world()` has already spent seeding a secret. Reusing them made the
  // live-session case fail, and the failure was correct: both fields of a row
  // are sealed under one project data key, so a repeated nonce under that key
  // leaks the XOR of the two plaintexts and the GHASH authentication key. The
  // implementation refused, which is the behaviour these tests want preserved.
  // A fixture must not be able to force a nonce collision just by being lazy.
  "secrets.createSecret": (w, sessionToken) => ({
    sessionToken,
    environmentId: w.environmentId,
    nameCiphertext: NAME_CIPHERTEXT,
    nameNonce: "101112131415161718191a1b",
    valueCiphertext: VALUE_CIPHERTEXT,
    valueNonce: "1b1a191817161514131211ff",
  }),
  "secrets.updateSecret": (w, sessionToken) => ({
    sessionToken,
    secretId: w.secretId,
    nameCiphertext: NAME_CIPHERTEXT,
    nameNonce: "202122232425262728292a2b",
    valueCiphertext: "cc".repeat(40),
    valueNonce: "2b2a292827262524232221ff",
  }),
  "secrets.deleteSecret": (w, sessionToken) => ({
    sessionToken,
    secretId: w.secretId,
  }),
  "secrets.getSecret": (w, sessionToken) => ({
    sessionToken,
    secretId: w.secretId,
  }),
  "secrets.listSecrets": (w, sessionToken) => ({
    sessionToken,
    environmentId: w.environmentId,
  }),
  "secrets.listSecretVersions": (w, sessionToken) => ({
    sessionToken,
    secretId: w.secretId,
  }),
  "tokens.createServiceToken": (w, sessionToken) => ({
    sessionToken,
    environmentId: w.environmentId,
    tokenId: w.spare.tokenId,
    publicKey: w.spare.publicKey,
    wrappedPDK: "dd".repeat(48),
    pdkNonce: "1112131415161718191a1b1c",
  }),
  "tokens.revokeServiceToken": (w, sessionToken) => ({
    sessionToken,
    ...w.revoke,
  }),
};

async function call(
  t: Harness,
  path: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const fn = registered(path);
  const ref = reference(path);
  // Dispatched on the registered kind rather than on a list, so a function
  // that changes from a query to a mutation stays covered.
  const invoke = (
    fn.isQuery === true ? t.query : t.mutation
  ) as (r: unknown, a: unknown) => Promise<unknown>;
  return await invoke(ref, args);
}

const FUNCTIONS = exportedFunctions();

// ---------------------------------------------------------------------------
// Guard the guard, before anything relies on the enumeration.
// ---------------------------------------------------------------------------

describe("the enumeration this file is built on", () => {
  it("finds every public function in the hierarchy", () => {
    // Nineteen, written as a number as well as a list, so that an enumeration
    // which silently starts returning nothing cannot make every assertion
    // below pass vacuously.
    expect(FUNCTIONS.length).toBe(19);
    expect(FUNCTIONS).toEqual([
      "environments.createEnvironment",
      "environments.getEnvironment",
      "environments.getMyPdkGrant",
      "environments.listEnvironments",
      "orgs.createOrg",
      "orgs.getMyRevocationGrant",
      "orgs.getOrg",
      "orgs.listMyOrgs",
      "projects.createProject",
      "projects.getProject",
      "projects.listProjects",
      "secrets.createSecret",
      "secrets.deleteSecret",
      "secrets.getSecret",
      // listSecretVersions sorts before listSecrets, because the enumeration
      // sorts by code point and "V" (0x56) precedes "s" (0x73). Written in
      // human alphabetical order this list fails with a diff showing two
      // identical-looking strings, which is a slow ten minutes to read.
      "secrets.listSecretVersions",
      "secrets.listSecrets",
      "secrets.updateSecret",
      "tokens.createServiceToken",
      "tokens.revokeServiceToken",
    ]);
  });

  it("knows how to call every function it found", () => {
    // A new handler is not covered by this suite until it appears here, and
    // this is the assertion that says so out loud instead of leaving a gap.
    expect(Object.keys(CALLS).sort()).toEqual(FUNCTIONS);
  });

  /**
   * The structural half of the property, independent of any call. A handler
   * cannot be authenticated if it does not take the credential, and a handler
   * must never take a user id: that was the whole defect.
   */
  it("gives every function a sessionToken argument and none a user id", () => {
    for (const path of FUNCTIONS) {
      const names = argNames(path);
      expect(names, path).toContain("sessionToken");
      expect(names, path).not.toContain("callerId");
      expect(names, path).not.toContain("userId");
      expect(names, path).not.toContain("actorId");
      expect(names, path).not.toContain("granteeId");
    }
  });
});

// ---------------------------------------------------------------------------
// The four ways a credential can be bad.
// ---------------------------------------------------------------------------

describe("every query and every mutation refuses an unauthenticated caller", () => {
  it.each(FUNCTIONS)("%s refuses a token that was never issued", async (path) => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    await expect(
      call(t, path, CALLS[path]!(w, "ff".repeat(32))),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  it.each(FUNCTIONS)("%s refuses an absent token", async (path) => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    await expect(call(t, path, CALLS[path]!(w, ""))).rejects.toThrow(
      NOT_AUTHENTICATED,
    );
  });

  it.each(FUNCTIONS)("%s refuses an expired session", async (path) => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    const stale = "expired-session-token";
    await t.run(async (ctx) =>
      insertSession(ctx, {
        userId: w.alice.userId,
        tokenHash: hashSessionToken(stale),
        createdAt: Date.now() - SESSION_LIFETIME_MS - 1,
        expiresAt: Date.now() - 1,
      }),
    );

    await expect(call(t, path, CALLS[path]!(w, stale))).rejects.toThrow(
      NOT_AUTHENTICATED,
    );
  });

  it.each(FUNCTIONS)("%s refuses a session that logged out", async (path) => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    // The same credential the world was built with, so this cannot pass by
    // accident: it worked a moment ago, for these very arguments.
    await t.mutation(api.auth.logout, {
      sessionToken: w.alice.sessionToken,
    });

    await expect(
      call(t, path, CALLS[path]!(w, w.alice.sessionToken)),
    ).rejects.toThrow(NOT_AUTHENTICATED);
  });

  /**
   * THE ASSERTION THAT KEEPS THE FOUR ABOVE HONEST.
   *
   * Every one of them would also pass if the arguments were malformed, or the
   * fixture ids were wrong, or the function simply threw for an unrelated
   * reason. This proves the only difference between refused and accepted is
   * the credential.
   */
  it.each(FUNCTIONS)("%s accepts the same call with a live session", async (path) => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    await expect(
      call(t, path, CALLS[path]!(w, w.alice.sessionToken)),
    ).resolves.not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Where the token must never end up.
// ---------------------------------------------------------------------------

describe("the session token does not leak", () => {
  it("is absent from every refusal, for every function", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const token = "a-very-distinctive-token-value";

    for (const path of FUNCTIONS) {
      let message = "";
      try {
        await call(t, path, CALLS[path]!(w, token));
      } catch (error) {
        message = JSON.stringify({
          message: (error as Error).message,
          data: (error as { data?: unknown }).data,
        });
      }
      expect(message, path).not.toBe("");
      expect(message, path).not.toContain(token);
    }
  });

  it("is absent from an error raised after authentication succeeds", async () => {
    // The refusals above never get past `requireSession`, so on their own they
    // would not notice a handler that interpolated the token into a VALIDATION
    // message further down. This one authenticates and then fails on the slug.
    const t = convexTest(schema, modules);
    const w = await world(t);

    let message = "";
    try {
      await t.mutation(api.orgs.createOrg, {
        sessionToken: w.alice.sessionToken,
        name: "Bad Slug",
        slug: "Not A Slug",
        revocationPublicKey: "cd".repeat(32),
        wrappedRevocationKey: "7b3f1c9a5e8d2046b1f7c3a9e5d80264b7f1c3a9e5d80264",
        revocationKeyNonce: "0f1e2d3c4b5a69788796a5b4",
      });
    } catch (error) {
      message = JSON.stringify({
        message: (error as Error).message,
        data: (error as { data?: unknown }).data,
      });
    }
    expect(message).toContain("slug");
    expect(message).not.toContain(w.alice.sessionToken);
  });

  it("is absent from the audit log", async () => {
    // `auditLog` has no delete and indexes its actor, so anything written
    // there is permanent and queryable. A credential in an append-only table
    // is a credential that cannot be withdrawn.
    const t = convexTest(schema, modules);
    const w = await world(t);
    await t.mutation(api.secrets.deleteSecret, {
      sessionToken: w.alice.sessionToken,
      secretId: w.secretId,
    });

    const events = await t.run(async (ctx) =>
      listAuditEventsByActor(ctx, w.alice.userId, 100),
    );
    expect(events.length).toBeGreaterThan(0);
    expect(JSON.stringify(events)).not.toContain(w.alice.sessionToken);
    expect(JSON.stringify(events)).not.toContain("session");
  });
});

// ---------------------------------------------------------------------------
// One session cannot be redirected at another user.
// ---------------------------------------------------------------------------

describe("a session acts only as its own user", () => {
  /**
   * The attack the old `callerId` made trivial, attempted the only way that is
   * left: present your own valid credential and add the victim's id to the
   * arguments anyway. Convex validates arguments against the declared
   * validator and rejects unknown fields, so this cannot even reach a handler,
   * and the handler would ignore it if it did because it reads no such field.
   */
  it("ignores a caller id smuggled in beside a valid token", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    const mallory = await seedUser(t, "mallory@example.test");

    await expect(
      t.query(api.orgs.getOrg, {
        sessionToken: mallory.sessionToken,
        orgId: w.orgId,
        callerId: w.alice.userId,
      } as never),
    ).rejects.toThrow();

    await expect(
      t.query(api.orgs.listMyOrgs, {
        sessionToken: mallory.sessionToken,
        userId: w.alice.userId,
      } as never),
    ).rejects.toThrow();
  });

  it("returns mallory's own empty world for mallory's own token", async () => {
    const t = convexTest(schema, modules);
    await world(t);
    const mallory = await seedUser(t, "mallory@example.test");

    expect(
      await t.query(api.orgs.listMyOrgs, {
        sessionToken: mallory.sessionToken,
      }),
    ).toEqual([]);
  });
});
