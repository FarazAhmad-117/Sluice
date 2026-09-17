import { describe, expect, it } from "vitest";
import { VERSION } from "../src/index";

describe("package", () => {
  it("exports a version tag", () => {
    expect(VERSION).toBe("sluice-crypto/v1");
  });
});
