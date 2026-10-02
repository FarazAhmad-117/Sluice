import { describe, expect, it } from "vitest";
import { rank, score } from "../src/lib/search/rank";

const labels = (items: { label: string }[]) => items.map((item) => item.label);

describe("score", () => {
  it("orders exact, prefix, word start, substring", () => {
    expect(score("redis", "redis")).toBe(0);
    expect(score("red", "REDIS_URL")).toBe(1);
    expect(score("url", "DATABASE_URL")).toBe(2);
    expect(score("db", "prod-db")).toBe(2);
    expect(score("base", "DATABASE_URL")).toBe(3);
    expect(score("zzz", "DATABASE_URL")).toBeNull();
  });

  it("ignores case and surrounding space", () => {
    expect(score("  Redis ", "redis_url")).toBe(1);
  });

  it("finds a word start at a case change", () => {
    expect(score("api", "storefrontApi")).toBe(2);
  });
});

describe("rank", () => {
  const items = [
    { label: "DATABASE_URL" },
    { label: "REDIS_URL" },
    { label: "URL_PREFIX" },
    { label: "SENTRY_DSN" },
    { label: "Secrets", keywords: ["keys", "values"] },
  ];

  it("puts a prefix above a substring", () => {
    expect(labels(rank(items, "url"))).toEqual(["URL_PREFIX", "DATABASE_URL", "REDIS_URL"]);
  });

  it("keeps the given order among equals, and for an empty query", () => {
    expect(labels(rank(items, ""))).toEqual(labels(items));
    expect(labels(rank(items, "s"))[0]).toBe("SENTRY_DSN");
  });

  it("matches keywords just below the label", () => {
    expect(labels(rank(items, "keys"))).toEqual(["Secrets"]);
    // Both a prefix: the label's beats the keyword's.
    expect(labels(rank([{ label: "Secrets", keywords: ["keys"] }, { label: "Keystore" }], "key"))).toEqual([
      "Keystore",
      "Secrets",
    ]);
  });

  it("drops what does not match", () => {
    expect(rank(items, "nothing")).toEqual([]);
  });
});
