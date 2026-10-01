import { afterEach, describe, expect, it } from "vitest";
import { decoySalt } from "./salt";

const previous = process.env.AUTH_PEPPER;
afterEach(() => {
  if (previous === undefined) delete process.env.AUTH_PEPPER;
  else process.env.AUTH_PEPPER = previous;
});

describe("decoySalt", () => {
  it("matches the independent vector", () => {
    process.env.AUTH_PEPPER = "ab".repeat(32);
    expect(decoySalt("nobody@example.com")).toBe("3cdb14ca8f79ef0ce835b15f0cba7674");
  });
  it("is stable per address and differs across addresses", () => {
    process.env.AUTH_PEPPER = "ab".repeat(32);
    expect(decoySalt("a@b.io")).toBe(decoySalt("a@b.io"));
    expect(decoySalt("a@b.io")).not.toBe(decoySalt("c@d.io"));
  });
});
