import { describe, expect, it } from "vitest";
import {
  countProjectSecrets,
  filterProjects,
  secretsLabel,
} from "../src/lib/projects/project-overview";

describe("countProjectSecrets", () => {
  it("is zero for no environments and for empty ones", () => {
    expect(countProjectSecrets([])).toBe(0);
    expect(countProjectSecrets([[], []])).toBe(0);
  });

  it("counts a shared secret once across every environment", () => {
    const dev = [{ shareUid: "shr_a" }, {}, { shareUid: "shr_b" }];
    const prod = [{ shareUid: "shr_a" }, { shareUid: "shr_b" }, {}, {}];
    // shr_a, shr_b, one dev-only and two prod-only.
    expect(countProjectSecrets([dev, prod])).toBe(5);
  });

  it("counts a shared secret present in one environment only once too", () => {
    expect(countProjectSecrets([[{ shareUid: "shr_a" }], []])).toBe(1);
  });
});

describe("secretsLabel", () => {
  it("is singular for one", () => {
    expect(secretsLabel(0)).toBe("0 secrets");
    expect(secretsLabel(1)).toBe("1 secret");
    expect(secretsLabel(18)).toBe("18 secrets");
  });
});

describe("filterProjects", () => {
  const projects = [
    { name: "Storefront API", slug: "storefront-api" },
    { name: "billing", slug: "billing-service" },
  ];

  it("keeps everything for an empty or blank query", () => {
    expect(filterProjects(projects, "")).toEqual(projects);
    expect(filterProjects(projects, "   ")).toEqual(projects);
  });

  it("matches the name or the slug, ignoring case", () => {
    expect(filterProjects(projects, "STORE")).toEqual([projects[0]]);
    expect(filterProjects(projects, "service")).toEqual([projects[1]]);
    expect(filterProjects(projects, "nothing")).toEqual([]);
  });
});
