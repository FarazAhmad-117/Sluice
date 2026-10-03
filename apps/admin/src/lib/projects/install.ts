/**
 * HOW A PERSON INSTALLS THE CLI, IN ONE PLACE.
 *
 * Every way the CLI will ship is listed, so the setup guide can offer the one
 * that fits the person's machine. None of these works yet: the CLI is not
 * published (`packages/cli` is version 0.0.0), so `CLI_RELEASED` is false and
 * the guide shows the steps with a "not released yet" note and no Copy
 * buttons. Flip it, and check each command, on the first release.
 */

export const CLI_RELEASED = false;

/** Where release notes will appear; linked from the "not released yet" note. */
export const RELEASES_URL = "https://github.com/FarazAhmad-117/Sluice/releases";

const RAW = "https://raw.githubusercontent.com/FarazAhmad-117/Sluice/main";

export type InstallMethodId = "npm" | "pnpm" | "yarn" | "bun" | "brew" | "shell" | "powershell";

export interface InstallMethod {
  readonly id: InstallMethodId;
  /** The tab's label. */
  readonly label: string;
  readonly command: string;
  /** One line under the command: what it needs, or what it does. */
  readonly note: string;
}

export const INSTALL_METHODS: readonly InstallMethod[] = [
  { id: "npm", label: "npm", command: "npm install -g @sluice/cli", note: "Needs Node.js 20 or newer." },
  { id: "pnpm", label: "pnpm", command: "pnpm add -g @sluice/cli", note: "Needs Node.js 20 or newer." },
  { id: "yarn", label: "Yarn", command: "yarn global add @sluice/cli", note: "Needs Node.js 20 or newer." },
  { id: "bun", label: "Bun", command: "bun add -g @sluice/cli", note: "Needs Bun 1.1 or newer." },
  { id: "brew", label: "Homebrew", command: "brew install FarazAhmad-117/sluice/sluice", note: "macOS and Linux." },
  {
    id: "shell",
    label: "macOS / Linux",
    command: `curl -fsSL ${RAW}/install.sh | sh`,
    note: "Downloads the CLI into ~/.sluice/bin and adds it to your PATH.",
  },
  {
    id: "powershell",
    label: "Windows",
    command: `irm ${RAW}/install.ps1 | iex`,
    note: "Run in PowerShell. Installs into %USERPROFILE%\\.sluice\\bin.",
  },
];

export function installMethod(id: InstallMethodId): InstallMethod {
  const found = INSTALL_METHODS.find((method) => method.id === id);
  if (found === undefined) throw new Error(`No install method ${id}`);
  return found;
}

export function isInstallMethodId(value: unknown): value is InstallMethodId {
  return INSTALL_METHODS.some((method) => method.id === value);
}

/**
 * The tab a person sees first, from their browser's platform string: the
 * PowerShell line on Windows, Homebrew on a Mac, npm everywhere else (it works
 * on all three wherever Node is installed).
 */
export function defaultInstallMethod(platform: string): InstallMethodId {
  const p = platform.toLowerCase();
  // Mac first: "darwin" contains "win".
  if (p.includes("mac") || p.includes("darwin") || p.includes("iphone") || p.includes("ipad")) return "brew";
  if (p.startsWith("win")) return "powershell";
  return "npm";
}

/** Where the person's chosen tab is remembered, in this browser only. */
export const INSTALL_METHOD_KEY = "sluice.install-method";
