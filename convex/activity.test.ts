import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { convexTest } from "convex-test";
import { newId } from "@sluice/crypto";
import schema from "./schema";
import { api } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { normaliseEmail } from "./lib/email";
import { insertUser } from "./repo/users";
import { insertSession } from "./repo/sessions";
import { insertOrgMember } from "./repo/orgs";
import { insertAuditEvent } from "./repo/audit";
import { SESSION_LIFETIME_MS, hashSessionToken } from "./lib/session";
import * as activityModule from "./activity";

export const modules = import.meta.glob("./**/*.ts");

type Harness = ReturnType<typeof convexTest>;

type Actor = {
  userId: Id<"users">;
  sessionToken: string;
};

const NOT_PERMITTED = "Not found, or you do not have access to it.";

const WRAP = {
  wrappedPDK: "dd".repeat(48),
  pdkNonce: "0a1b2c3d4e5f60718293a4b5",
  pdkVersion: 1,
} as const;

const NAME_CIPHERTEXT = "aa".repeat(24);
const VALUE_CIPHERTEXT = "bb".repeat(40);

/**
 * A stopped clock that this file moves by hand, one second per write, so
 * "newest first" is a property of the timestamps and not of how quickly a
 * machine under load got from one line to the next.
 */
const START = Date.parse("2026-10-02T09:00:00.000Z");

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(START);
});

afterEach(() => {
  vi.useRealTimers();
});

function tick(): void {
  vi.setSystemTime(Date.now() + 1000);
}

async function seedUser(t: Harness, email: string): Promise<Actor> {
  const sessionToken = `session-for-${email}`;
  const userId = await t.run(async (ctx) =>
    insertUser(ctx, {
      uid: newId("usr"),
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
      expiresAt: Date.now() + SESSION_LIFETIME_MS * 10,
    }),
  );
  return { userId, sessionToken };
}

let nonceCounter = 0;
/** A fresh 12 byte nonce pair per call, so no fixture repeats one. */
function nonces(): { nameNonce: string; valueNonce: string } {
  nonceCounter += 1;
  const n = nonceCounter.toString(16).padStart(8, "0");
  return {
    nameNonce: `aaaa${n}000000000000`,
    valueNonce: `bbbb${n}000000000000`,
  };
}

async function createOrg(t: Harness, actor: Actor, slug: string) {
  tick();
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

async function createProject(
  t: Harness,
  actor: Actor,
  orgId: Id<"orgs">,
  slug: string,
) {
  tick();
  return await t.mutation(api.projects.createProject, {
    sessionToken: actor.sessionToken,
    orgId,
    name: slug,
    slug,
  });
}

async function createEnvironment(
  t: Harness,
  actor: Actor,
  projectId: Id<"projects">,
  name: string,
) {
  tick();
  return await t.mutation(api.environments.createEnvironment, {
    sessionToken: actor.sessionToken,
    environmentUid: newId("env"),
    projectId,
    name,
    ...WRAP,
  });
}

async function createSecret(
  t: Harness,
  actor: Actor,
  environmentId: Id<"environments">,
) {
  tick();
  return await t.mutation(api.secrets.createSecret, {
    sessionToken: actor.sessionToken,
    environmentId,
    secretUid: newId("sec"),
    version: 1,
    pdkVersion: 1,
    nameCiphertext: NAME_CIPHERTEXT,
    valueCiphertext: VALUE_CIPHERTEXT,
    ...nonces(),
  });
}

/**
 * Alice's org holds two projects, `api` and `web`, and a second member, Bob.
 * Mallory has an org of her own with a project of her own. Every write moves
 * the clock, so the order of events is the order of these lines.
 */
async function world(t: Harness) {
  const alice = await seedUser(t, "alice@example.test");
  const bob = await seedUser(t, "bob@example.test");
  const mallory = await seedUser(t, "mallory@example.test");

  const orgA = await createOrg(t, alice, "org-a");
  await t.run(async (ctx) =>
    insertOrgMember(ctx, { orgId: orgA, userId: bob.userId, role: "member" }),
  );
  const api_ = await createProject(t, alice, orgA, "api");
  const production = await createEnvironment(t, alice, api_, "production");
  const web = await createProject(t, alice, orgA, "web");
  const webDev = await createEnvironment(t, alice, web, "development");
  const { secretId: webSecret } = await createSecret(t, alice, webDev);
  const { secretId: apiSecret } = await createSecret(t, alice, production);
  tick();
  const updated = await t.mutation(api.secrets.updateSecret, {
    sessionToken: alice.sessionToken,
    secretId: apiSecret,
    version: 2,
    pdkVersion: 1,
    nameCiphertext: NAME_CIPHERTEXT,
    valueCiphertext: VALUE_CIPHERTEXT,
    ...nonces(),
  });
  // Bob can create an environment, which mints his own grant on it.
  const staging = await createEnvironment(t, bob, api_, "staging");

  const orgB = await createOrg(t, mallory, "org-b");
  const theirs = await createProject(t, mallory, orgB, "api");
  const theirEnv = await createEnvironment(t, mallory, theirs, "production");
  await createSecret(t, mallory, theirEnv);

  return {
    alice,
    bob,
    mallory,
    orgA,
    orgB,
    api: api_,
    production,
    staging,
    web,
    webDev,
    webSecret,
    apiSecret,
    apiSecretV2: updated.secretId,
    theirs,
  };
}

describe("listProjectActivity", () => {
  it("returns this project's events, newest first, and nothing else", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    const events = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api,
    });

    expect(
      events.map((e) => [e.action, e.targetKind, e.targetId, e.environmentId]),
    ).toEqual([
      ["environment.create", "environment", w.staging, w.staging],
      ["secret.update", "secret", w.apiSecretV2, w.production],
      ["secret.create", "secret", w.apiSecret, w.production],
      ["environment.create", "environment", w.production, w.production],
      ["project.create", "project", w.api, null],
    ]);
    for (let i = 1; i < events.length; i += 1) {
      expect(events[i - 1]!.at).toBeGreaterThan(events[i]!.at);
    }
  });

  it("names the actor, and says when it is the caller", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    const asAlice = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api,
    });
    expect(asAlice[0]).toMatchObject({
      action: "environment.create",
      actorIsYou: false,
      actorEmail: "bob@example.test",
    });
    expect(asAlice[1]).toMatchObject({
      actorIsYou: true,
      actorEmail: "alice@example.test",
    });

    const asBob = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.bob.sessionToken,
      projectId: w.api,
    });
    expect(asBob[0]?.actorIsYou).toBe(true);
    expect(asBob[1]?.actorIsYou).toBe(false);
  });

  it("returns ids and timestamps only, never ciphertext or a nonce", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    const events = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api,
    });
    for (const event of events) {
      expect(Object.keys(event).sort()).toEqual([
        "action",
        "actorEmail",
        "actorIsYou",
        "at",
        "environmentId",
        "targetId",
        "targetKind",
      ]);
    }
    const body = JSON.stringify(events);
    expect(body).not.toContain(NAME_CIPHERTEXT);
    expect(body).not.toContain(VALUE_CIPHERTEXT);
  });

  it("honours the limit, defaults to 30 and refuses more than 100", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    for (let i = 0; i < 32; i += 1) await createSecret(t, w.alice, w.production);

    const all = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api,
    });
    expect(all).toHaveLength(30);

    const two = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api,
      limit: 2,
    });
    expect(two).toEqual(all.slice(0, 2));

    const hundred = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api,
      limit: 100,
    });
    // 32 creates plus the five events of the world.
    expect(hundred).toHaveLength(37);

    for (const limit of [0, -1, 1.5, 101]) {
      await expect(
        t.query(api.activity.listProjectActivity, {
          sessionToken: w.alice.sessionToken,
          projectId: w.api,
          limit,
        }),
      ).rejects.toThrow("limit must be a whole number from 1 to 100.");
    }
  });

  it("refuses a caller who is not a member of the project's org", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    await expect(
      t.query(api.activity.listProjectActivity, {
        sessionToken: w.mallory.sessionToken,
        projectId: w.api,
      }),
    ).rejects.toThrow(NOT_PERMITTED);
  });

  /**
   * The org boundary is the index range, not a filter. An event filed under
   * another org that NAMES one of this project's rows -- which no handler
   * writes, so it is forged here through the repo layer -- still does not
   * appear, because it is never read.
   */
  it("never shows another org's events, even one naming this project's rows", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);
    tick();
    await t.run(async (ctx) =>
      insertAuditEvent(ctx, {
        orgId: w.orgB,
        actorType: "user",
        actorId: w.mallory.userId,
        action: "secret.update",
        targetId: w.apiSecretV2,
        ts: Date.now(),
      }),
    );

    const events = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.api,
    });
    expect(events).toHaveLength(5);
    expect(JSON.stringify(events)).not.toContain("mallory");

    const theirs = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.mallory.sessionToken,
      projectId: w.theirs,
    });
    expect(theirs.map((e) => e.action)).toEqual([
      "secret.create",
      "environment.create",
      "project.create",
    ]);
    // Her own forged event names a secret outside her project, so it is not
    // hers to see either.
    expect(JSON.stringify(theirs)).not.toContain(w.apiSecretV2);
  });

  it("does not show the org's other project, or the org itself", async () => {
    const t = convexTest(schema, modules);
    const w = await world(t);

    const web = await t.query(api.activity.listProjectActivity, {
      sessionToken: w.alice.sessionToken,
      projectId: w.web,
    });
    expect(web.map((e) => [e.action, e.targetId])).toEqual([
      ["secret.create", w.webSecret],
      ["environment.create", w.webDev],
      ["project.create", w.web],
    ]);
  });
});

describe("the activity surface", () => {
  it("exports exactly the functions it is supposed to", () => {
    expect(Object.keys(activityModule).sort()).toEqual(["listProjectActivity"]);
  });
});
