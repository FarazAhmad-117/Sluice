import { describe, expect, it } from "vitest";
import { checklist, environmentStats } from "../src/lib/projects/overview";

type Row = { secretId: string; shareUid?: string; overridden?: boolean };

const dev: Row[] = [
  { secretId: "d1" },
  { secretId: "d2" },
  { secretId: "d3", shareUid: "shr_a", overridden: false },
  { secretId: "d4", shareUid: "shr_b", overridden: false },
];
const prod: Row[] = [
  { secretId: "p1", shareUid: "shr_a", overridden: true },
  { secretId: "p2", shareUid: "shr_b", overridden: false },
  { secretId: "p3" },
];
const names = new Map<string, ReadonlyMap<string, string>>([
  ["dev", new Map([["d1", "DATABASE_URL"], ["d2", "REDIS_URL"], ["d3", "SENTRY_DSN"], ["d4", "LOG_LEVEL"]])],
  ["prod", new Map([["p1", "SENTRY_DSN"], ["p2", "LOG_LEVEL"], ["p3", "STRIPE_KEY"]])],
]);

describe("environmentStats", () => {
  it("counts shared, own and only-here rows per environment", () => {
    const [d, p] = environmentStats(
      [
        { environmentId: "dev", environmentName: "development", rows: dev },
        { environmentId: "prod", environmentName: "production", rows: prod },
      ],
      names,
    );
    expect(d).toMatchObject({ secrets: 4, shared: 2, own: 0, only: 2, missingVsDevelopment: undefined });
    expect(p).toMatchObject({ secrets: 3, shared: 1, own: 1, only: 1, missingVsDevelopment: 2 });
  });

  it("refuses to compare by name when a name is not open", () => {
    const partial = new Map(names);
    partial.set("prod", new Map([["p1", "SENTRY_DSN"]]));
    const [, p] = environmentStats(
      [
        { environmentId: "dev", environmentName: "development", rows: dev },
        { environmentId: "prod", environmentName: "production", rows: prod },
      ],
      partial,
    );
    expect(p!.missingVsDevelopment).toBeNull();
    expect(p!.secrets).toBe(3);
  });

  it("gives no counts for a listing that failed", () => {
    const [, p] = environmentStats(
      [
        { environmentId: "dev", environmentName: "development", rows: dev },
        { environmentId: "prod", environmentName: "production", rows: null },
      ],
      names,
    );
    expect(p).toMatchObject({ secrets: null, shared: null, own: null, only: null, missingVsDevelopment: null });
  });

  it("has no 'missing vs development' without a development environment", () => {
    const [p] = environmentStats([{ environmentId: "prod", environmentName: "production", rows: prod }], names);
    expect(p!.missingVsDevelopment).toBeUndefined();
  });
});

describe("checklist", () => {
  it("is one of four done for a project with no secrets", () => {
    const list = checklist({ secretCount: 0, ranLocally: false, connections: [] });
    expect([...list.done]).toEqual(["create"]);
    expect(list.total).toBe(4);
  });
  it("counts secrets only once they are known", () => {
    expect(checklist({ secretCount: undefined, ranLocally: false, connections: [] }).done.has("secrets")).toBe(false);
    expect(checklist({ secretCount: 3, ranLocally: false, connections: [] }).done.has("secrets")).toBe(true);
  });
  it("takes the person's word for running locally", () => {
    const list = checklist({ secretCount: 3, ranLocally: true, connections: [] });
    expect(list.done.size).toBe(3);
    expect(list.done.has("production")).toBe(false);
  });
  it("marks running done once a development token has connected, whatever the person said", () => {
    const list = checklist({
      secretCount: 3,
      ranLocally: false,
      connections: [{ environmentName: "development", connected: true }],
    });
    expect(list.done.has("run")).toBe(true);
    expect(list.done.has("production")).toBe(false);
  });
  it("marks production done once a token outside development has connected, not merely been made", () => {
    const made = checklist({
      secretCount: 3,
      ranLocally: false,
      connections: [{ environmentName: "production", connected: false }],
    });
    expect(made.done.has("production")).toBe(false);
    const connected = checklist({
      secretCount: 3,
      ranLocally: false,
      connections: [{ environmentName: "staging", connected: true }],
    });
    expect(connected.done.has("production")).toBe(true);
  });
});
