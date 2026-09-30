import { describe, expect, it } from "vitest";
import { assertId, newId } from "../src/ids";

describe("newId", () => {
  it.each(["org", "usr", "env"] as const)("mints a %s id in the one canonical shape", (kind) => {
    expect(newId(kind)).toMatch(new RegExp(`^${kind}_[0-9a-f]{32}$`));
  });

  it("never repeats across a large sample", () => {
    const seen = new Set(Array.from({ length: 10_000 }, () => newId("env")));
    expect(seen.size).toBe(10_000);
  });
});

describe("assertId", () => {
  it("returns a well-formed id unchanged", () => {
    const id = "env_000102030405060708090a0b0c0d0e0f";
    expect(assertId("env", "environmentUid", id)).toBe(id);
  });

  /**
   * THE REASON THE PREFIX EXISTS. A user id passed where an environment id is
   * expected must fail at the call, not produce well-formed associated data
   * for the wrong thing.
   */
  it("rejects an id of another kind", () => {
    expect(() =>
      assertId("env", "environmentUid", "usr_101112131415161718191a1b1c1d1e1f"),
    ).toThrow("environmentUid must be an env id");
  });

  /**
   * THE REASON THIS PHASE EXISTS. A Convex document id is deployment-local and
   * changes when an org moves cells. It must never reach an encryption binding.
   */
  it("rejects a Convex document id", () => {
    expect(() => assertId("env", "environmentUid", "k17dn9q2x4m8p3v6b0zc5t7wgh")).toThrow();
  });

  it.each([
    ["uppercase hex", "env_000102030405060708090A0B0C0D0E0F"],
    ["short", "env_0001020304050607"],
    ["long", "env_000102030405060708090a0b0c0d0e0f00"],
    ["empty", ""],
    ["no separator", "env000102030405060708090a0b0c0d0e0f"],
    ["trailing newline", "env_000102030405060708090a0b0c0d0e0f\n"],
  ])("rejects %s", (_label, value) => {
    expect(() => assertId("env", "environmentUid", value)).toThrow();
  });

  it("rejects a non-string without echoing it", () => {
    expect(() => assertId("env", "environmentUid", 42 as unknown as string)).toThrow(
      "environmentUid must be an env id",
    );
  });
});
