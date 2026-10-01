import { describe, expect, it } from "vitest";
import { assertId, newId, type IdKind } from "../src/ids";

describe("newId", () => {
  it.each(["org", "usr", "env"] as const)("mints a %s id in the one canonical shape", (kind) => {
    const id = newId(kind);
    expect(id).toMatch(new RegExp(`^${kind}_[0-9a-f]{32}$`));
    // Minting and validation must agree: whatever newId hands out, assertId
    // accepts unchanged.
    expect(assertId(kind, "id", id)).toBe(id);
  });

  it("never repeats across a large sample", () => {
    const seen = new Set(Array.from({ length: 10_000 }, () => newId("env")));
    expect(seen.size).toBe(10_000);
  });

  it("refuses to mint for an unknown kind", () => {
    expect(() => newId("foo" as IdKind)).toThrow(/^kind must be org, usr or env$/);
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
  it("rejects an id of another kind, without echoing it", () => {
    const call = () =>
      assertId("env", "environmentUid", "usr_101112131415161718191a1b1c1d1e1f");
    expect(call).toThrow(/^environmentUid must be a well-formed env id$/);
    try {
      call();
    } catch (e) {
      expect(String((e as Error).message)).not.toContain("usr_1011");
    }
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
    ["prefixed Convex id", "env_k17dn9q2x4m8p3v6b0zc5t7wgh000000"],
  ])("rejects %s", (_label, value) => {
    expect(() => assertId("env", "environmentUid", value)).toThrow();
  });

  it("rejects a non-string without echoing it", () => {
    expect(() => assertId("env", "environmentUid", 42 as unknown as string)).toThrow(
      /^environmentUid must be a well-formed env id$/,
    );
  });

  it("rejects an unknown kind", () => {
    expect(() => assertId("foo" as IdKind, "x", "foo_" + "0".repeat(32))).toThrow(
      /^kind must be org, usr or env$/,
    );
  });
});
