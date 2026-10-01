import { describe, expect, it } from "vitest";
import { EmailFormatError, normaliseEmail } from "../src/email";

function reasonFor(value: string): string | undefined {
  try {
    normaliseEmail(value);
  } catch (error) {
    if (error instanceof EmailFormatError) return error.reason;
    throw error;
  }
  return undefined;
}

describe("normaliseEmail", () => {
  it("trims and lowercases without locale rules", () => {
    expect(normaliseEmail("  Ada@Example.COM ")).toBe("ada@example.com");
    expect(normaliseEmail("I@x.io")).toBe("i@x.io"); // never a Turkish dotless i
  });
  it("accepts an address of exactly 254 characters, the RFC 5321 cap", () => {
    const address = "a".repeat(249) + "@b.io";
    expect(address).toHaveLength(254);
    expect(normaliseEmail(address)).toBe(address);
  });
  it.each(["", "a", "a@b@c", "a b@c.d", `${"a".repeat(250)}@b.io`])("rejects %j", (value) => {
    expect(() => normaliseEmail(value)).toThrow();
  });
  it("says which rule failed", () => {
    expect(reasonFor("")).toBe("length");
    expect(reasonFor("a b@c.d")).toBe("shape");
  });
});
