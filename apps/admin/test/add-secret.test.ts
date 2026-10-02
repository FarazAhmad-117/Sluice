import { describe, expect, it } from "vitest";
import { newId } from "@sluice/crypto";
import {
  duplicateProblem,
  secretKeyProblem,
  unavailableEnvironments,
} from "../src/lib/secrets/add-secret";
import type { ProjectDataKeyState } from "../src/lib/secrets/environment-key";
import { createProjectDataKey } from "../src/lib/secrets/pdk";

const dev = { environmentId: "e-dev", name: "development" };
const prod = { environmentId: "e-prod", name: "production" };
const stg = { environmentId: "e-stg", name: "staging" };

describe("secretKeyProblem", () => {
  it("accepts environment variable names", () => {
    for (const name of ["API_KEY", "_private", "a1", "DATABASE_URL"]) {
      expect(secretKeyProblem(name)).toBeNull();
    }
  });

  it("refuses an empty key and anything that is not a variable name", () => {
    expect(secretKeyProblem("")).toBe("Enter a key.");
    for (const name of ["1ABC", "API-KEY", "A B", "café", "A.B"]) {
      expect(secretKeyProblem(name)).toMatch(/letters, digits and underscores/);
    }
  });
});

describe("duplicateProblem", () => {
  const names = new Map([
    ["e-dev", new Map([["1", "API_URL"]])],
    ["e-prod", new Map([["2", "API_URL"]])],
    ["e-stg", new Map<string, string>()],
  ]);

  it("names where the key already exists", () => {
    expect(duplicateProblem("API_URL", [dev], names)).toBe("API_URL already exists in development.");
    expect(duplicateProblem("API_URL", [dev, prod, stg], names)).toBe(
      "API_URL already exists in development and production.",
    );
  });

  it("refuses only when a target environment already has the key", () => {
    // "Add here": the key exists in development and production, and the one
    // target, staging, does not have it. That is the point, not a duplicate.
    expect(duplicateProblem("API_URL", [stg], names)).toBeNull();
    expect(duplicateProblem("API_URL", [stg, prod], names)).toBe("API_URL already exists in production.");
  });

  it("is null for a new key, and is case sensitive like the environment", () => {
    expect(duplicateProblem("NEW", [dev, prod, stg], names)).toBeNull();
    expect(duplicateProblem("api_url", [dev], names)).toBeNull();
  });
});

describe("unavailableEnvironments", () => {
  const ready: ProjectDataKeyState = {
    status: "ready",
    key: { pdk: createProjectDataKey(), environmentUid: newId("env"), pdkVersion: 1 },
  };

  it("is empty when every key is open and every listing's names are open", () => {
    const keys = new Map([["e-dev", ready], ["e-prod", ready]]);
    const names = new Map([["e-dev", new Map()], ["e-prod", new Map()]]);
    expect(unavailableEnvironments([dev, prod], keys, names)).toEqual([]);
  });

  it("names each environment that cannot be written, with why", () => {
    const keys = new Map<string, ProjectDataKeyState>([
      ["e-dev", ready],
      ["e-prod", { status: "refused", message: "No key for you." }],
      ["e-stg", { status: "loading" }],
    ]);
    expect(unavailableEnvironments([dev, prod, stg], keys, new Map())).toEqual([
      { name: "development", reason: "Its secrets are still loading." },
      { name: "production", reason: "No key for you." },
      { name: "staging", reason: "Its key is still opening." },
    ]);
  });
});
