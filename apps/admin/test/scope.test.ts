import { describe, expect, it } from "vitest";
import { countScopes, scopeLabel, scopeOf } from "../src/lib/secrets/scope";

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

describe("scopeLabel", () => {
  it("names every scope", () => {
    expect(scopeLabel("shared", "production")).toBe("All environments");
    expect(scopeLabel("overridden", "production")).toBe("Overridden in production");
    expect(scopeLabel("only", "development")).toBe("Only development");
  });
});

describe("countScopes", () => {
  it("is all zero for no rows", () => {
    expect(countScopes([])).toEqual({ all: 0, shared: 0, overridden: 0, only: 0 });
  });

  it("counts each scope and the total", () => {
    const rows = [
      {},
      {},
      { shareUid: "shr_a" },
      { shareUid: "shr_b", overridden: false },
      { shareUid: "shr_c", overridden: true },
    ];
    expect(countScopes(rows)).toEqual({ all: 5, shared: 2, overridden: 1, only: 2 });
  });
});
