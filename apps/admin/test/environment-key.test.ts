import { describe, expect, it } from "vitest";
import { ConvexError } from "convex/values";
import { getFunctionName } from "convex/server";
import { MasterUnlockKey, newId, toHex } from "@sluice/crypto";
import type { Id } from "@convex/_generated/dataModel";
import { createProjectDataKey, wrapProjectDataKey } from "../src/lib/secrets/pdk";
import { loadEnvironmentKey } from "../src/lib/secrets/environment-key";
import type { KeyQueryClient } from "../src/lib/secrets/environment-key";

/**
 * ONE ENVIRONMENT'S KEY, LOADED WITH THE CHECKS THE DASHBOARD HAS ALWAYS MADE.
 *
 * The loader was lifted out of `useProjectDataKey` so that a whole project's
 * keys can be loaded with the same steps. These tests pin that its answers
 * did not change on the way out: a re-key in progress, a server whose answers
 * disagree, a refusal, and a grant that does not open are each reported as
 * the same state they always were.
 */

function fixedKey(fill = 7): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(fill));
}

const ENVIRONMENT_ID = "env-doc-1" as Id<"environments">;
const ENVIRONMENT_UID = newId("env");
const USER_UID = newId("usr");

interface Fixture {
  environment?: Partial<{ environmentId: string; uid: string; pdkVersion: number }>;
  grant?: Partial<{ environmentId: string; pdkVersion: number; wrappedPDK: string }>;
  refuse?: string;
}

async function fakeClient(muk: MasterUnlockKey, fixture: Fixture = {}) {
  const pdk = createProjectDataKey();
  const wrapped = await wrapProjectDataKey(muk, pdk, {
    environmentUid: ENVIRONMENT_UID,
    pdkVersion: 1,
    granteeType: "user",
    granteeId: USER_UID,
  });
  const query = async (reference: unknown) => {
    const name = getFunctionName(reference as never);
    if (fixture.refuse !== undefined) throw new ConvexError(fixture.refuse);
    if (name === "environments:getEnvironment") {
      return {
        environmentId: ENVIRONMENT_ID,
        uid: ENVIRONMENT_UID,
        projectId: "p",
        name: "development",
        pdkVersion: 1,
        epoch: 0,
        ...fixture.environment,
      };
    }
    if (name === "environments:getMyPdkGrant") {
      return {
        environmentId: ENVIRONMENT_ID,
        wrappedPDK: wrapped.wrappedPDK,
        nonce: wrapped.pdkNonce,
        pdkVersion: 1,
        ...fixture.grant,
      };
    }
    throw new Error(`unexpected query ${name}`);
  };
  return { client: { query } as unknown as KeyQueryClient, pdk };
}

function request(muk: MasterUnlockKey, listedEnvironmentUid: string | null = ENVIRONMENT_UID) {
  return {
    sessionToken: "token",
    environmentId: ENVIRONMENT_ID,
    listedEnvironmentUid,
    userUid: USER_UID,
    muk,
  };
}

describe("loadEnvironmentKey", () => {
  it("opens the grant and carries the environment's uid and version with the key", async () => {
    const muk = fixedKey();
    const { client, pdk } = await fakeClient(muk);
    const state = await loadEnvironmentKey(client, request(muk));
    expect(state.status).toBe("ready");
    if (state.status !== "ready") return;
    expect(toHex(state.key.pdk)).toBe(toHex(pdk));
    expect(state.key.environmentUid).toBe(ENVIRONMENT_UID);
    expect(state.key.pdkVersion).toBe(1);
  });

  it("reports a grant at another key version than the environment as rekeying", async () => {
    const muk = fixedKey();
    const { client } = await fakeClient(muk, { environment: { pdkVersion: 2 } });
    expect(await loadEnvironmentKey(client, request(muk))).toEqual({
      status: "rekeying",
      message: "This environment is being re-keyed. Reload the page in a moment to try again.",
    });
  });

  it("fails without opening anything when the server's answers disagree", async () => {
    const muk = fixedKey();
    for (const fixture of [
      { environment: { environmentId: "other" } },
      { grant: { environmentId: "other" } },
    ]) {
      const { client } = await fakeClient(muk, fixture);
      const state = await loadEnvironmentKey(client, request(muk));
      expect(state.status).toBe("failed");
    }
    const { client } = await fakeClient(muk);
    const state = await loadEnvironmentKey(client, request(muk, newId("env")));
    expect(state.status).toBe("failed");
  });

  it("carries the server's refusal through as its own sentence", async () => {
    const muk = fixedKey();
    const { client } = await fakeClient(muk, { refuse: "You do not have access to this." });
    expect(await loadEnvironmentKey(client, request(muk))).toEqual({
      status: "refused",
      message: "You do not have access to this.",
    });
  });

  it("fails when the grant does not open under this master unlock key", async () => {
    const { client } = await fakeClient(fixedKey(1));
    const state = await loadEnvironmentKey(client, request(fixedKey(2)));
    expect(state).toEqual({
      status: "failed",
      message: "The project data key for this environment could not be opened.",
    });
  });
});
