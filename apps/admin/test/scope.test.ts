import { describe, expect, it } from "vitest";
import {
  countScopes,
  missingFromShare,
  scopeLabel,
  scopeOf,
} from "../src/lib/secrets/scope";

/**
 * A SECRET'S SCOPE, READ OFF ITS ROW.
 *
 * `shareUid` and `overridden` are plaintext metadata the server hands back and
 * bound into no ciphertext, so these labels say how the server grouped a row,
 * not anything a decrypt proved. That is why the mapping is this small and this
 * literal: it must never guess.
 */
describe("scopeOf", () => {
  it("is only when the row carries no share id", () => {
    expect(scopeOf({})).toBe("only");
    // A stray flag without a share id is still a one-environment secret.
    expect(scopeOf({ overridden: true })).toBe("only");
  });

  it("is shared when the row carries a share id and is not overridden", () => {
    expect(scopeOf({ shareUid: "shr_x" })).toBe("shared");
    expect(scopeOf({ shareUid: "shr_x", overridden: false })).toBe("shared");
  });

  it("is overridden when the row carries a share id and the flag", () => {
    expect(scopeOf({ shareUid: "shr_x", overridden: true })).toBe("overridden");
  });
});

describe("scopeOf with group coverage", () => {
  it("is partial for a shared or overridden row whose group misses an environment", () => {
    expect(scopeOf({ shareUid: "shr_x" }, false)).toBe("partial");
    expect(scopeOf({ shareUid: "shr_x", overridden: true }, false)).toBe("partial");
  });

  it("keeps the row's own scope when the group covers every environment", () => {
    expect(scopeOf({ shareUid: "shr_x" }, true)).toBe("shared");
    expect(scopeOf({ shareUid: "shr_x", overridden: true }, true)).toBe("overridden");
  });

  it("never makes a one-environment row partial", () => {
    expect(scopeOf({}, false)).toBe("only");
  });
});

describe("missingFromShare", () => {
  const listings = [
    { environmentName: "development", rows: [{ shareUid: "shr_a" }, { shareUid: "shr_b" }, {}] },
    { environmentName: "production", rows: [{ shareUid: "shr_a", overridden: true }] },
    { environmentName: "staging", rows: [{ shareUid: "shr_a" }, {}] },
  ];

  it("is empty when every environment has a live row of the group", () => {
    expect(missingFromShare("shr_a", listings)).toEqual([]);
  });

  it("names every environment without a row of the group, in listing order", () => {
    expect(missingFromShare("shr_b", listings)).toEqual(["production", "staging"]);
  });

  it("counts an environment that could not be listed as missing, because nothing confirms it", () => {
    expect(
      missingFromShare("shr_a", [...listings, { environmentName: "qa", rows: null }]),
    ).toEqual(["qa"]);
  });
});

describe("scopeLabel", () => {
  it("names the environments a partial group is missing in", () => {
    expect(scopeLabel("partial", "development", ["staging"])).toBe("Shared, missing in staging");
    expect(scopeLabel("partial", "development", ["production", "staging"])).toBe(
      "Shared, missing in production and staging",
    );
    expect(scopeLabel("partial", "development", ["a", "b", "c"])).toBe(
      "Shared, missing in a, b and c",
    );
  });

  it("names every scope", () => {
    expect(scopeLabel("shared", "production")).toBe("All environments");
    expect(scopeLabel("overridden", "production")).toBe("Overridden in production");
    expect(scopeLabel("only", "development")).toBe("Only development");
  });
});

describe("countScopes", () => {
  it("is all zero for no rows", () => {
    expect(countScopes([])).toEqual({ all: 0, shared: 0, overridden: 0, only: 0, partial: 0 });
  });

  it("counts each scope and the total", () => {
    const rows = [
      {},
      {},
      { shareUid: "shr_a" },
      { shareUid: "shr_b", overridden: false },
      { shareUid: "shr_c", overridden: true },
    ];
    expect(countScopes(rows)).toEqual({ all: 5, shared: 2, overridden: 1, only: 2, partial: 0 });
  });

  it("counts rows of a group that misses an environment as partial", () => {
    const rows = [{ shareUid: "shr_a" }, { shareUid: "shr_b", overridden: true }, {}];
    const covers = (row: { shareUid?: string }) => row.shareUid !== "shr_b";
    expect(countScopes(rows, covers)).toEqual({ all: 3, shared: 1, overridden: 0, only: 1, partial: 1 });
  });
});
