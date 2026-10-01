import { describe, expect, it } from "vitest";
import { MasterUnlockKey, newId, toHex } from "@sluice/crypto";
import { MAX_SLUG_LENGTH, isSlug } from "../src/lib/naming";
import { PdkUnwrapError, unwrapProjectDataKey } from "../src/lib/secrets/pdk";
import {
  OPTIONAL_ENVIRONMENTS,
  environmentNames,
  sealProjectEnvironments,
  slugFromName,
} from "../src/lib/projects/create-project";

/**
 * A NEW PROJECT'S ENVIRONMENTS, SEALED IN ONE STEP.
 *
 * Every environment gets its own key, wrapped to its creator for its own
 * freshly minted `env_` uid. The assertions that matter are the ones a server
 * cannot check: each wrap opens for its own environment and for no other.
 */

/** A deterministic stand-in for a real derivation. Not a real key. */
function fixedKey(fill = 7): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(fill));
}

const USER_UID = newId("usr");

describe("slugFromName", () => {
  it("lowercases and joins words with single hyphens", () => {
    expect(slugFromName("Storefront API!")).toBe("storefront-api");
    expect(slugFromName("  web__2   api ")).toBe("web-2-api");
  });

  it("is empty when nothing usable remains", () => {
    expect(slugFromName("")).toBe("");
    expect(slugFromName("!!! ??? ---")).toBe("");
    expect(slugFromName("café")).toBe("caf");
  });

  it("caps long input without leaving a trailing hyphen", () => {
    const long = slugFromName("a".repeat(MAX_SLUG_LENGTH - 1) + " bcdef");
    expect(long.length).toBeLessThanOrEqual(MAX_SLUG_LENGTH);
    expect(long.endsWith("-")).toBe(false);
    expect(isSlug(long)).toBe(true);
    expect(slugFromName("x".repeat(200))).toHaveLength(MAX_SLUG_LENGTH);
  });

  it("produces only slugs the server accepts", () => {
    for (const name of ["Acme Rockets", "API v2.1", "-lead-", "Ünïcode Näme"]) {
      const slug = slugFromName(name);
      expect({ name, ok: slug === "" || isSlug(slug) }).toEqual({ name, ok: true });
    }
  });
});

describe("environmentNames", () => {
  it("always starts with development", () => {
    expect(environmentNames([])).toEqual(["development"]);
  });

  it("orders and dedupes the optional environments", () => {
    expect(environmentNames(["staging", "production", "staging"])).toEqual([
      "development",
      "production",
      "staging",
    ]);
    expect(OPTIONAL_ENVIRONMENTS).toEqual(["production", "staging"]);
  });
});

describe("sealProjectEnvironments", () => {
  it("wraps one fresh key per environment, each opening for its own uid only", async () => {
    const muk = fixedKey();
    const names = ["development", "production"];
    const { payload, keys } = await sealProjectEnvironments(muk, USER_UID, names);

    expect(payload.map((row) => row.name)).toEqual(names);
    expect(keys).toHaveLength(2);
    expect(new Set(payload.map((row) => row.environmentUid)).size).toBe(2);
    expect(toHex(keys[0]!.pdk)).not.toBe(toHex(keys[1]!.pdk));

    for (const [index, row] of payload.entries()) {
      const key = keys[index]!;
      expect(row.environmentUid).toMatch(/^env_[0-9a-f]{32}$/);
      expect(row.pdkVersion).toBe(1);
      expect(key.environmentUid).toBe(row.environmentUid);
      expect(key.pdkVersion).toBe(1);

      const opened = await unwrapProjectDataKey(
        muk,
        { wrappedPDK: row.wrappedPDK, nonce: row.pdkNonce },
        {
          environmentUid: row.environmentUid,
          pdkVersion: 1,
          granteeType: "user",
          granteeId: USER_UID,
        },
      );
      expect(toHex(opened)).toBe(toHex(key.pdk));
    }

    // A grant moved onto the other environment's uid must not open there.
    const [development, production] = payload;
    await expect(
      unwrapProjectDataKey(
        muk,
        { wrappedPDK: development!.wrappedPDK, nonce: development!.pdkNonce },
        {
          environmentUid: production!.environmentUid,
          pdkVersion: 1,
          granteeType: "user",
          granteeId: USER_UID,
        },
      ),
    ).rejects.toBeInstanceOf(PdkUnwrapError);
  });

  it("does not open under another account's master unlock key", async () => {
    const { payload } = await sealProjectEnvironments(fixedKey(1), USER_UID, ["development"]);
    const row = payload[0]!;
    await expect(
      unwrapProjectDataKey(
        fixedKey(2),
        { wrappedPDK: row.wrappedPDK, nonce: row.pdkNonce },
        {
          environmentUid: row.environmentUid,
          pdkVersion: 1,
          granteeType: "user",
          granteeId: USER_UID,
        },
      ),
    ).rejects.toBeInstanceOf(PdkUnwrapError);
  });
});
