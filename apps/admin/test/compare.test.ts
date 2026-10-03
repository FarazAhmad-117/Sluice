import { describe, expect, it } from "vitest";
import { buildMatrix, rowFor } from "../src/lib/secrets/compare";

type Row = { secretId: string; shareUid?: string; overridden?: boolean };

const listings = (prodRows: Row[] | null = [
  { secretId: "p1", shareUid: "shr_log", overridden: true },
  { secretId: "p2" },
]) => [
  {
    environmentId: "dev",
    environmentName: "development",
    rows: [
      { secretId: "d1" },
      { secretId: "d2", shareUid: "shr_log", overridden: false },
      { secretId: "d3" },
    ] as Row[],
  },
  { environmentId: "prod", environmentName: "production", rows: prodRows },
];

const names = new Map<string, ReadonlyMap<string, string>>([
  ["dev", new Map([["d1", "REDIS_URL"], ["d2", "LOG_LEVEL"], ["d3", "DATABASE_URL"]])],
  ["prod", new Map([["p1", "LOG_LEVEL"], ["p2", "DATABASE_URL"]])],
]);

describe("buildMatrix", () => {
  it("groups rows across environments by opened name, sorted by key", () => {
    const matrix = buildMatrix(listings(), names);
    expect(matrix.rows.map((row) => row.name)).toEqual(["DATABASE_URL", "LOG_LEVEL", "REDIS_URL"]);
  });

  it("classifies each cell: set here, shared value, own value, missing", () => {
    const matrix = buildMatrix(listings(), names);
    const kinds = (name: string) => rowFor(matrix, name)!.cells.map((cell) => cell.kind);
    // Set separately in both: the same key to a person.
    expect(kinds("DATABASE_URL")).toEqual(["set", "set"]);
    expect(kinds("LOG_LEVEL")).toEqual(["shared", "own"]);
    expect(kinds("REDIS_URL")).toEqual(["set", "missing"]);
    expect(rowFor(matrix, "LOG_LEVEL")!.cells[1]!.secret?.secretId).toBe("p1");
  });

  it("counts missing and own values per environment", () => {
    const matrix = buildMatrix(listings(), names);
    expect(matrix.missing.get("prod")).toBe(1);
    expect(matrix.missing.get("dev")).toBe(0);
    expect(matrix.own.get("prod")).toBe(1);
  });

  it("shows a partial shared group as missing where it has no row", () => {
    const matrix = buildMatrix(listings([{ secretId: "p2" }]), names);
    expect(rowFor(matrix, "LOG_LEVEL")!.cells.map((cell) => cell.kind)).toEqual(["shared", "missing"]);
  });

  it("never says missing for an environment that failed to list", () => {
    const matrix = buildMatrix(listings(null), names);
    expect(rowFor(matrix, "REDIS_URL")!.cells[1]!.kind).toBe("unknown");
    expect(matrix.uncertain).toEqual(["production"]);
    expect(matrix.missing.get("prod")).toBe(0);
  });

  it("never says missing where a name did not open, and counts the sealed row", () => {
    const partial = new Map(names);
    partial.set("prod", new Map([["p1", "LOG_LEVEL"]]));
    const matrix = buildMatrix(listings(), partial);
    expect(matrix.sealed).toBe(1);
    expect(rowFor(matrix, "DATABASE_URL")!.cells[1]!.kind).toBe("unknown");
    expect(rowFor(matrix, "LOG_LEVEL")!.cells[1]!.kind).toBe("own");
  });

  it("treats an environment with no names open as unknown throughout", () => {
    const matrix = buildMatrix(listings(), new Map([["dev", names.get("dev")!]]));
    expect(matrix.rows.every((row) => row.cells[1]!.kind === "unknown")).toBe(true);
  });
});
