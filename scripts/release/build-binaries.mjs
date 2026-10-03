#!/usr/bin/env node
/**
 * BUILDS THE STANDALONE `sluice` EXECUTABLES FOR A RELEASE.
 *
 * Every channel except npm (Homebrew, winget, Scoop, the install scripts)
 * installs one of these, so nobody needs Node to run the CLI. Bun compiles the
 * same entry point the npm bundle uses into a single file per platform and
 * cross-compiles all of them from one machine.
 *
 *   node scripts/release/build-binaries.mjs            every target
 *   node scripts/release/build-binaries.mjs --host     this machine only
 *
 * Output, in packages/cli/release/:
 *   sluice-<os>-<arch>.tar.gz   (macOS, Linux; holds `sluice`)
 *   sluice-windows-x64.zip      (holds `sluice.exe`)
 *   SHA256SUMS                  one `<sha256>  <file>` line per archive
 *
 * The archive names are a contract: install.sh, install.ps1 and every package
 * manifest (`render-manifests.mjs`) build URLs from them.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(ROOT, "packages", "cli");
const OUT = join(CLI, "release");
const { version } = JSON.parse(readFileSync(join(CLI, "package.json"), "utf8"));

const TARGETS = [
  { os: "linux", arch: "x64", bun: "bun-linux-x64" },
  { os: "linux", arch: "arm64", bun: "bun-linux-arm64" },
  { os: "darwin", arch: "x64", bun: "bun-darwin-x64" },
  { os: "darwin", arch: "arm64", bun: "bun-darwin-arm64" },
  { os: "windows", arch: "x64", bun: "bun-windows-x64" },
];

function hostTargets() {
  const os = process.platform === "win32" ? "windows" : process.platform;
  return TARGETS.filter((target) => target.os === os && target.arch === process.arch);
}

const targets = process.argv.includes("--host") ? hostTargets() : TARGETS;
if (targets.length === 0) throw new Error(`No release target for ${process.platform}/${process.arch}.`);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const sums = [];
for (const target of targets) {
  const name = `sluice-${target.os}-${target.arch}`;
  const dir = join(OUT, name);
  mkdirSync(dir, { recursive: true });
  const exe = target.os === "windows" ? "sluice.exe" : "sluice";
  console.log(`building ${name} (${version})`);
  execFileSync(
    "bun",
    [
      "build",
      join(CLI, "src", "cli-entry.ts"),
      "--compile",
      "--minify",
      `--target=${target.bun}`,
      // The value is a JavaScript expression, so the version goes in as a
      // quoted string literal. No shell is involved, so no further quoting.
      `--define=__SLUICE_RELEASE__=${JSON.stringify(version)}`,
      "--outfile",
      join(dir, exe),
    ],
    { stdio: "inherit", cwd: CLI },
  );

  // On Windows, the system's own bsdtar: a GNU tar earlier on PATH (Git Bash)
  // reads "E:" as a remote host and cannot write zip at all.
  const tar = process.platform === "win32" ? join(process.env.SystemRoot ?? "C:/Windows", "System32", "tar.exe") : "tar";
  const archive = target.os === "windows" ? `${name}.zip` : `${name}.tar.gz`;
  if (target.os === "windows") {
    // bsdtar (Windows, macOS) writes zip with -a; GNU tar (Linux CI) cannot.
    if (process.platform === "linux") execFileSync("zip", ["-j", "-q", join(OUT, archive), join(dir, exe)]);
    else execFileSync(tar, ["-a", "-c", "-f", join(OUT, archive), "-C", dir, exe]);
  } else {
    execFileSync(tar, ["-c", "-z", "-f", join(OUT, archive), "-C", dir, exe]);
  }
  rmSync(dir, { recursive: true, force: true });
  const sha = createHash("sha256").update(readFileSync(join(OUT, archive))).digest("hex");
  sums.push(`${sha}  ${archive}`);
}

writeFileSync(join(OUT, "SHA256SUMS"), `${sums.join("\n")}\n`);
console.log(`\n${sums.join("\n")}`);
