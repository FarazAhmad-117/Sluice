import { describe, expect, it } from "vitest";
import { newId } from "@sluice/crypto";
import { buildMatrix } from "../src/lib/secrets/compare";
import { linkForRow, rowForRef, secretLink, secretRef } from "../src/lib/secrets/links";

type Row = { secretId: string; secretUid: string; shareUid?: string; overridden?: boolean };

const shareUid = newId("shr");
const rows: Record<string, Row[]> = {
  dev: [
    { secretId: "d1", secretUid: newId("sec") },
    { secretId: "d2", secretUid: newId("sec"), shareUid, overridden: false },
  ],
  prod: [{ secretId: "p1", secretUid: newId("sec"), shareUid, overridden: true }],
};
const names = new Map<string, ReadonlyMap<string, string>>([
  ["dev", new Map([["d1", "STRIPE_SECRET_KEY"], ["d2", "DATABASE_URL"]])],
  ["prod", new Map([["p1", "DATABASE_URL"]])],
]);
const matrix = buildMatrix(
  [
    { environmentId: "dev", environmentName: "development", rows: rows.dev! },
    { environmentId: "prod", environmentName: "production", rows: rows.prod! },
  ],
  names,
);

describe("secret links", () => {
  it("carries the share id for a shared secret and the row's own id otherwise", () => {
    expect(secretRef(rows.dev![1]!)).toBe(shareUid);
    expect(secretRef(rows.dev![0]!)).toBe(rows.dev![0]!.secretUid);
  });

  it("never puts a secret's name in a link", () => {
    for (const row of matrix.rows) {
      const link = linkForRow("storefront-api", row);
      expect(link).not.toContain(row.name);
      expect(decodeURIComponent(link)).not.toContain(row.name);
      for (const name of ["STRIPE", "DATABASE", "SECRET_KEY"]) expect(decodeURIComponent(link)).not.toContain(name);
    }
    expect(secretLink("p", "development", rows.dev![0]!)).toMatch(/\?env=development&secret=sec_[0-9a-f]{32}$/);
  });

  it("resolves a link back to its key in the browser, from any environment's row", () => {
    expect(rowForRef(matrix, shareUid)?.name).toBe("DATABASE_URL");
    expect(rowForRef(matrix, rows.dev![0]!.secretUid)?.name).toBe("STRIPE_SECRET_KEY");
    expect(rowForRef(matrix, newId("sec"))).toBeUndefined();
    expect(rowForRef(matrix, null)).toBeUndefined();
  });
});
