import { describe, expect, it } from "vitest";
import { listOf } from "../src/lib/list-of";

describe("listOf", () => {
  it("joins names for a sentence", () => {
    expect(listOf([])).toBe("");
    expect(listOf(["development"])).toBe("development");
    expect(listOf(["development", "production"])).toBe("development and production");
    expect(listOf(["development", "staging", "production"])).toBe(
      "development, staging and production",
    );
  });
});
