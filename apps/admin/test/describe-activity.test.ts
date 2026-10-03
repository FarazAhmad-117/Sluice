import { describe, expect, it } from "vitest";
import { describeActivity, groupByDay } from "../src/lib/activity/describe";
import type { ActivityEvent, DescribeContext } from "../src/lib/activity/describe";

const context: DescribeContext = {
  secretNames: new Map([
    ["s-dev-log", "LOG_LEVEL"],
    ["s-prod-log", "LOG_LEVEL"],
    ["s-dev-db", "DATABASE_URL"],
  ]),
  environmentNames: new Map([
    ["dev", "development"],
    ["prod", "production"],
  ]),
  environmentCount: 2,
  projectName: "storefront-api",
  selfEmail: "faraz@example.com",
};

function event(overrides: Partial<ActivityEvent>): ActivityEvent {
  return {
    at: 1_000_000,
    action: "secret.create",
    actorIsYou: true,
    actorEmail: "faraz@example.com",
    targetKind: "secret",
    targetId: "s-dev-db",
    environmentId: "dev",
    ...overrides,
  };
}

const sentences = (events: ActivityEvent[]) => describeActivity(events, context).map((line) => line.sentence);

describe("describeActivity", () => {
  it("names a secret from the rows this browser opened", () => {
    expect(sentences([event({})])).toEqual(["You added DATABASE_URL to development"]);
  });

  it("calls a secret that is no longer listed 'a secret'", () => {
    expect(sentences([event({ action: "secret.delete", targetId: "gone" })])).toEqual([
      "You deleted a secret from development",
    ]);
  });

  it("collapses one shared write into one line for all environments", () => {
    const lines = sentences([
      event({ targetId: "s-prod-log", environmentId: "prod", at: 1_000_500 }),
      event({ targetId: "s-dev-log", environmentId: "dev", at: 1_000_000 }),
    ]);
    expect(lines).toEqual(["You added LOG_LEVEL to all environments"]);
  });

  it("collapses an update and a delete the same way", () => {
    expect(
      sentences([
        event({ action: "secret.update", targetId: "s-prod-log", environmentId: "prod" }),
        event({ action: "secret.update", targetId: "s-dev-log", environmentId: "dev" }),
      ]),
    ).toEqual(["You changed LOG_LEVEL in all environments"]);
  });

  it("never merges events it cannot name, which could be different secrets", () => {
    expect(
      sentences([
        event({ action: "secret.delete", targetId: "x1", environmentId: "prod" }),
        event({ action: "secret.delete", targetId: "x2", environmentId: "dev" }),
      ]),
    ).toEqual(["You deleted a secret from production", "You deleted a secret from development"]);
    // Nor a named event with an unnamed one.
    expect(
      sentences([
        event({ targetId: "s-prod-log", environmentId: "prod" }),
        event({ targetId: "gone", environmentId: "dev" }),
      ]),
    ).toHaveLength(2);
  });

  it("does not collapse events more than two seconds apart, by different people, or in one environment", () => {
    expect(
      sentences([
        event({ targetId: "s-prod-log", environmentId: "prod", at: 1_005_000 }),
        event({ targetId: "s-dev-log", environmentId: "dev", at: 1_000_000 }),
      ]),
    ).toHaveLength(2);
    expect(
      sentences([
        event({ targetId: "s-prod-log", environmentId: "prod", actorIsYou: false, actorEmail: "sam@example.com" }),
        event({ targetId: "s-dev-log", environmentId: "dev" }),
      ]),
    ).toEqual(["sam@example.com added LOG_LEVEL to production", "You added LOG_LEVEL to development"]);
    expect(
      sentences([event({ targetId: "s-dev-log" }), event({ targetId: "s-dev-db" })]),
    ).toHaveLength(2);
  });

  it("describes environments and the project", () => {
    expect(
      sentences([
        event({ action: "environment.create", targetKind: "environment", targetId: "prod", environmentId: "prod" }),
        event({ action: "project.create", targetKind: "project", targetId: "p", environmentId: null }),
      ]),
    ).toEqual(["You created production", "You created storefront-api"]);
  });

  it("uses the actor's email, or 'Someone' when the server gives none", () => {
    const [mine, theirs, token] = describeActivity(
      [
        event({}),
        event({ actorIsYou: false, actorEmail: "sam@example.com", at: 900_000 }),
        event({ actorIsYou: false, actorEmail: null, at: 800_000 }),
      ],
      context,
    );
    expect(mine!.initial).toBe("F");
    expect(theirs!.sentence.startsWith("sam@example.com ")).toBe(true);
    expect(theirs!.initial).toBe("S");
    expect(token!.sentence.startsWith("Someone ")).toBe(true);
    expect(token!.initial).toBe("?");
  });
});

describe("groupByDay", () => {
  it("labels today, yesterday, then dates, keeping order", () => {
    const now = new Date(2026, 9, 3, 12).getTime();
    const line = (at: number) => ({ id: String(at), at, sentence: "", initial: "Y" });
    const days = groupByDay(
      [
        line(new Date(2026, 9, 3, 11).getTime()),
        line(new Date(2026, 9, 3, 9).getTime()),
        line(new Date(2026, 9, 2, 22).getTime()),
        line(new Date(2026, 8, 28, 10).getTime()),
      ],
      now,
    );
    expect(days.map((day) => [day.label, day.lines.length])).toEqual([
      ["Today", 2],
      ["Yesterday", 1],
      ["Sep 28, 2026", 1],
    ]);
  });
});
