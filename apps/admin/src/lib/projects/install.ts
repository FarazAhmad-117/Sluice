/**
 * HOW A PERSON INSTALLS THE CLI, IN ONE PLACE.
 *
 * Every way the CLI will ship is listed, so the setup guide can offer the one
 * that fits the person's machine. None of these works yet: the CLI is not
 * published to npm or any package manager yet, so `CLI_RELEASED` is false and
 * the guide shows the steps with a "not released yet" note and no Copy
 * buttons. Flip it, and check each command, on the first release.
 */

export const CLI_RELEASED = false;

/** Where release notes will appear; linked from the "not released yet" note. */
export const RELEASES_URL = "https://github.com/FarazAhmad-117/Sluice/releases";

const RAW = "https://raw.githubusercontent.com/FarazAhmad-117/Sluice/HEAD";

export type InstallMethodId = "npm" | "pnpm" | "yarn" | "bun" | "brew" | "shell" | "winget" | "scoop" | "powershell";

export interface InstallMethod {
  readonly id: InstallMethodId;
  /** The tab's label. */
  readonly label: string;
  readonly command: string;
  /** One line under the command: what it needs, or what it does. */
  readonly note: string;
}

/** The npm package. The command it installs is `sluice`. */
export const NPM_PACKAGE = "@getsluice/cli";

const STANDALONE = "A standalone executable: Node is not needed.";

export const INSTALL_METHODS: readonly InstallMethod[] = [
  { id: "npm", label: "npm", command: `npm install -g ${NPM_PACKAGE}`, note: "Needs Node.js 20 or newer." },
  { id: "pnpm", label: "pnpm", command: `pnpm add -g ${NPM_PACKAGE}`, note: "Needs Node.js 20 or newer." },
  { id: "yarn", label: "Yarn", command: `yarn global add ${NPM_PACKAGE}`, note: "Needs Node.js 20 or newer." },
  { id: "bun", label: "Bun", command: `bun add -g ${NPM_PACKAGE}`, note: "Needs Bun 1.1 or newer." },
  { id: "brew", label: "Homebrew", command: "brew install FarazAhmad-117/sluice/sluice", note: `macOS and Linux. ${STANDALONE}` },
  {
    id: "shell",
    label: "macOS / Linux",
    command: `curl -fsSL ${RAW}/install.sh | sh`,
    note: `Checks the download's checksum and installs to ~/.sluice/bin. ${STANDALONE}`,
  },
  { id: "winget", label: "winget", command: "winget install Sluice.Sluice", note: `Windows 10 and 11. ${STANDALONE}` },
  {
    id: "scoop",
    label: "Scoop",
    command: "scoop bucket add sluice https://github.com/FarazAhmad-117/scoop-sluice; scoop install sluice",
    note: `Windows. ${STANDALONE}`,
  },
  {
    id: "powershell",
    label: "PowerShell",
    command: `irm ${RAW}/install.ps1 | iex`,
    note: `Checks the download's checksum and installs to %USERPROFILE%\\.sluice\\bin. ${STANDALONE}`,
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
 * The tab a person sees first, from their browser's platform string: winget
 * on Windows, Homebrew on a Mac, npm everywhere else (it works on all three
 * wherever Node is installed).
 */
export function defaultInstallMethod(platform: string): InstallMethodId {
  const p = platform.toLowerCase();
  // Mac first: "darwin" contains "win".
  if (p.includes("mac") || p.includes("darwin") || p.includes("iphone") || p.includes("ipad")) return "brew";
  if (p.startsWith("win")) return "winget";
  return "npm";
}

/** Where the person's chosen tab is remembered, in this browser only. */
export const INSTALL_METHOD_KEY = "sluice.install-method";
