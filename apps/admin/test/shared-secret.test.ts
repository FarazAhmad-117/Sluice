import { describe, expect, it } from "vitest";
import { newId } from "@sluice/crypto";
import { createProjectDataKey } from "../src/lib/secrets/pdk";
import type { EnvironmentKey } from "../src/lib/secrets/pdk";
import { SecretOpenError, openSecret } from "../src/lib/secrets/decrypt";
import { sealSharedSecret } from "../src/lib/secrets/shared";
import type { SharedSecretEnvironment } from "../src/lib/secrets/shared";

/**
 * ONE SECRET, SEALED INTO EVERY ENVIRONMENT OF A PROJECT.
 *
 * A shared secret is N independently sealed rows, one per environment, each
 * under that environment's own key and bound to that environment's uid. The
 * assertion that matters is the one a server cannot check: each row opens with
 * ITS environment's key and with no other.
 */

function environmentKey(): EnvironmentKey {
  return { pdk: createProjectDataKey(), environmentUid: newId("env"), pdkVersion: 1 };
}

function threeEnvironments(): SharedSecretEnvironment[] {
  return [
    { environmentId: "env-doc-dev", key: environmentKey() },
    { environmentId: "env-doc-prod", key: environmentKey() },
    { environmentId: "env-doc-stg", key: environmentKey() },
  ];
}

describe("sealSharedSecret", () => {
  it("seals one row per environment under one share id with distinct secret ids", async () => {
    const environments = threeEnvironments();
    const payload = await sealSharedSecret({ name: "API_URL", value: "https://x", environments });

    expect(payload.shareUid).toMatch(/^shr_[0-9a-f]{32}$/);
    expect(payload.rows.map((row) => row.environmentId)).toEqual(
      environments.map((environment) => environment.environmentId),
    );
    expect(new Set(payload.rows.map((row) => row.secretUid)).size).toBe(3);
    for (const row of payload.rows) {
      expect(row.secretUid).toMatch(/^sec_[0-9a-f]{32}$/);
      expect(row.version).toBe(1);
      expect(row.pdkVersion).toBe(1);
      expect(row.overridden).toBe(false);
    }
  });

  it("states each environment's own key version", async () => {
    const environments = threeEnvironments();
    environments[1] = { ...environments[1]!, key: { ...environments[1]!.key, pdkVersion: 3 } };
    const payload = await sealSharedSecret({ name: "N", value: "v", environments });
    expect(payload.rows.map((row) => row.pdkVersion)).toEqual([1, 3, 1]);
  });

  it("opens each row with its environment's key, to the override where one is given", async () => {
    const environments = threeEnvironments();
    environments[1] = { ...environments[1]!, override: "prod-only" };
    const payload = await sealSharedSecret({ name: "API_URL", value: "shared", environments });

    const expected = ["shared", "prod-only", "shared"];
    for (const [index, row] of payload.rows.entries()) {
      const opened = await openSecret(environments[index]!.key, row);
      expect(opened.name).toBe("API_URL");
      expect(opened.value).toBe(expected[index]);
    }
    expect(payload.rows.map((row) => row.overridden)).toEqual([false, true, false]);
  });

  it("treats an empty override as an override, not as the shared value", async () => {
    const environments = threeEnvironments();
    environments[2] = { ...environments[2]!, override: "" };
    const payload = await sealSharedSecret({ name: "N", value: "shared", environments });
    expect(payload.rows[2]!.overridden).toBe(true);
    expect((await openSecret(environments[2]!.key, payload.rows[2]!)).value).toBe("");
  });

  it("does not open a row with another environment's key", async () => {
    const environments = threeEnvironments();
    const payload = await sealSharedSecret({ name: "N", value: "v", environments });
    await expect(openSecret(environments[1]!.key, payload.rows[0]!)).rejects.toThrow(
      SecretOpenError,
    );
    // Same key bytes, another environment's uid: the binding, not the key, refuses it.
    await expect(
      openSecret(
        { ...environments[0]!.key, environmentUid: environments[1]!.key.environmentUid },
        payload.rows[0]!,
      ),
    ).rejects.toThrow(SecretOpenError);
  });

  it("mints a new share id every time", async () => {
    const environments = threeEnvironments();
    const first = await sealSharedSecret({ name: "N", value: "v", environments });
    const second = await sealSharedSecret({ name: "N", value: "v", environments });
    expect(second.shareUid).not.toBe(first.shareUid);
  });

  it("refuses no environments", async () => {
    await expect(sealSharedSecret({ name: "N", value: "v", environments: [] })).rejects.toThrow(
      /at least one environment/,
    );
  });

  it("refuses every environment overriding the shared value", async () => {
    const environments = threeEnvironments().map((environment) => ({
      ...environment,
      override: "own",
    }));
    await expect(sealSharedSecret({ name: "N", value: "v", environments })).rejects.toThrow(
      /shared value/,
    );
  });

  it("refuses one environment listed twice", async () => {
    const environments = threeEnvironments();
    await expect(
      sealSharedSecret({ name: "N", value: "v", environments: [...environments, environments[0]!] }),
    ).rejects.toThrow(/more than once/);
  });
});
