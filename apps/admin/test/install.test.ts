import { describe, expect, it } from "vitest";
import {
  CLI_RELEASED,
  INSTALL_METHODS,
  defaultInstallMethod,
  installMethod,
  isInstallMethodId,
} from "../src/lib/projects/install";

describe("install methods", () => {
  it("offers every channel, each once", () => {
    const ids = INSTALL_METHODS.map((method) => method.id);
    expect(ids).toEqual(["npm", "pnpm", "yarn", "bun", "brew", "shell", "powershell"]);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("names the same package in every package-manager command", () => {
    for (const id of ["npm", "pnpm", "yarn", "bun"] as const) {
      expect(installMethod(id).command).toContain("@sluice/cli");
    }
  });

  it("fetches install scripts over https only", () => {
    expect(installMethod("shell").command).toMatch(/^curl -fsSL https:\/\//);
    expect(installMethod("powershell").command).toMatch(/^irm https:\/\//);
  });

  it("recognises only its own ids", () => {
    expect(isInstallMethodId("brew")).toBe(true);
    expect(isInstallMethodId("cargo")).toBe(false);
    expect(isInstallMethodId(null)).toBe(false);
  });

  it("is not marked released while the CLI is unpublished", () => {
    expect(CLI_RELEASED).toBe(false);
  });
});

describe("defaultInstallMethod", () => {
  it("opens PowerShell on Windows, Homebrew on a Mac, npm elsewhere", () => {
    expect(defaultInstallMethod("Win32")).toBe("powershell");
    expect(defaultInstallMethod("Windows")).toBe("powershell");
    expect(defaultInstallMethod("MacIntel")).toBe("brew");
    expect(defaultInstallMethod("macOS")).toBe("brew");
    expect(defaultInstallMethod("Linux x86_64")).toBe("npm");
    expect(defaultInstallMethod("")).toBe("npm");
  });

  it("does not mistake Darwin for Windows", () => {
    expect(defaultInstallMethod("Darwin")).toBe("brew");
  });
});
