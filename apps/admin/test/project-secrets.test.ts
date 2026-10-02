import { describe, expect, it } from "vitest";
import {
  environmentsWithName,
  labelRows,
  pickEnvironment,
} from "../src/lib/secrets/project-secrets";

const dev = { environmentId: "e-dev", name: "development" };
const prod = { environmentId: "e-prod", name: "production" };
const stg = { environmentId: "e-stg", name: "staging" };

describe("pickEnvironment", () => {
  const environments = [prod, dev, stg];

  it("is the environment named in the address when it exists", () => {
    expect(pickEnvironment(environments, "staging")).toBe(stg);
  });

  it("falls back to development, then to the first", () => {
    expect(pickEnvironment(environments, null)).toBe(dev);
    expect(pickEnvironment(environments, "nope")).toBe(dev);
    expect(pickEnvironment([prod, stg], null)).toBe(prod);
    expect(pickEnvironment([], null)).toBeNull();
  });
});

describe("labelRows", () => {
  const listings = [
    {
      environmentId: "e-dev",
      environmentName: "development",
      rows: [
        { secretId: "d1", shareUid: "shr_all" },
        { secretId: "d2", shareUid: "shr_two" },
        { secretId: "d3" },
        { secretId: "d4" },
      ],
    },
    {
      environmentId: "e-prod",
      environmentName: "production",
      rows: [
        { secretId: "p1", shareUid: "shr_all", overridden: true },
        { secretId: "p2", shareUid: "shr_two" },
      ],
    },
    {
      environmentId: "e-stg",
      environmentName: "staging",
      rows: [{ secretId: "s1", shareUid: "shr_all" }],
    },
  ];
  const names = new Map([
    ["d1", "B_SHARED"],
    ["d2", "A_TWO"],
    ["d3", "C_ONLY"],
  ]);

  it("labels a row from its group's coverage and sorts by name, sealed rows last", () => {
    const rows = labelRows(listings[0]!, listings, names);
    expect(rows.map((row) => [row.secret.secretId, row.name, row.scope, row.missingIn])).toEqual([
      ["d2", "A_TWO", "partial", ["staging"]],
      ["d1", "B_SHARED", "shared", []],
      ["d3", "C_ONLY", "only", []],
      ["d4", undefined, "only", []],
    ]);
  });

  it("keeps an override's label when its group covers everything", () => {
    const rows = labelRows(listings[1]!, listings, new Map());
    expect(rows.find((row) => row.secret.secretId === "p1")?.scope).toBe("overridden");
  });
});

describe("environmentsWithName", () => {
  it("names every environment that already has a live secret with this name", () => {
    const namesByEnvironment = new Map([
      ["e-dev", new Map([["d1", "API_URL"]])],
      ["e-prod", new Map([["p1", "OTHER"]])],
      ["e-stg", new Map([["s1", "API_URL"]])],
    ]);
    expect(environmentsWithName("API_URL", [dev, prod, stg], namesByEnvironment)).toEqual([
      "development",
      "staging",
    ]);
    expect(environmentsWithName("NEW", [dev, prod, stg], namesByEnvironment)).toEqual([]);
  });
});
