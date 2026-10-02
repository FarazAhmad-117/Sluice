import { describe, expect, it } from "vitest";
import { pickOrg } from "../src/lib/orgs/pick-org";

describe("pickOrg", () => {
  const orgs = [{ orgId: "a" }, { orgId: "b" }];

  it("is null with no orgs", () => {
    expect(pickOrg([], "a")).toBeNull();
  });

  it("is the remembered org while it is still listed", () => {
    expect(pickOrg(orgs, "b")).toBe(orgs[1]);
  });

  it("falls back to the first org for a missing or stale id", () => {
    expect(pickOrg(orgs, null)).toBe(orgs[0]);
    expect(pickOrg(orgs, "gone")).toBe(orgs[0]);
  });
});
