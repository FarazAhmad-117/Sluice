import { describe, expect, it } from "vitest";
import { normaliseEmail } from "../src/email";

describe("normaliseEmail", () => {
  it("trims and lowercases without locale rules", () => {
    expect(normaliseEmail("  Ada@Example.COM ")).toBe("ada@example.com");
    expect(normaliseEmail("I@x.io")).toBe("i@x.io"); // never a Turkish dotless i
  });
  it.each(["", "a", "a@b@c", "a b@c.d", `${"a".repeat(250)}@b.io`])("rejects %j", (value) => {
    expect(() => normaliseEmail(value)).toThrow();
  });
});
