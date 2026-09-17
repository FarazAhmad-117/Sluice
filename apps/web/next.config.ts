import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { NextConfig } from "next";

/**
 * WHY THIS FILE READS AN ENV FILE BY HAND.
 *
 * `npx convex dev` writes `CONVEX_URL` into the REPOSITORY ROOT `.env.local`.
 * Next only ever loads env files from the application directory, which is
 * `apps/web`, and it only exposes a variable to the browser when its name
 * starts with `NEXT_PUBLIC_`. So the value the CLI wrote is invisible twice
 * over: wrong directory and wrong prefix.
 *
 * The failure that costs an afternoon is that nothing errors. `next build`
 * succeeds, the page renders, and the first Convex call fails at runtime with
 * a message about an undefined deployment URL. So the bridge is built here,
 * once, and `src/lib/convex-url.ts` turns a missing value into a visible
 * message on the page rather than a rejected promise nobody awaited.
 *
 * PRECEDENCE, highest first:
 *   1. `NEXT_PUBLIC_CONVEX_URL` in the process environment.
 *   2. `CONVEX_URL` in the process environment (CI, Vercel).
 *   3. either name in `apps/web/.env.local`, then `apps/web/.env`.
 *   4. either name in the repo root `.env.local`, then the repo root `.env`.
 *
 * The value is INLINED INTO THE CLIENT BUNDLE, which is correct and is not a
 * leak: a Convex deployment URL is a public address, the same one every
 * browser must dial. Nothing secret may ever be added to this map.
 */
const ENV_FILE_CANDIDATES = [".env.local", ".env", "../../.env.local", "../../.env"];

const URL_LINE = /^\s*(?:export\s+)?(?:NEXT_PUBLIC_)?CONVEX_URL\s*=\s*["']?([^"'\r\n#]+)["']?/m;

function readConvexUrl(): string | undefined {
  const fromProcess = process.env.NEXT_PUBLIC_CONVEX_URL ?? process.env.CONVEX_URL;
  if (fromProcess !== undefined && fromProcess.length > 0) return fromProcess.trim();

  for (const candidate of ENV_FILE_CANDIDATES) {
    let text: string;
    try {
      text = readFileSync(resolve(process.cwd(), candidate), "utf8");
    } catch {
      // An absent env file is the normal case in CI and in a fresh clone. It
      // must not fail the build: the page says so at runtime instead.
      continue;
    }
    const match = URL_LINE.exec(text);
    const value = match?.[1]?.trim();
    if (value !== undefined && value.length > 0) return value;
  }
  return undefined;
}

const convexUrl = readConvexUrl();

const nextConfig: NextConfig = {
  /**
   * `@sluice/crypto` publishes TypeScript SOURCE (`"main": "./src/index.ts"`)
   * rather than a build artefact, which is deliberate -- an audited crypto
   * package that shipped a compiled bundle would be one whose reviewed code and
   * shipped code are different files. Next therefore has to compile it, in the
   * main bundle and in the key-derivation worker alike.
   *
   * This pairs with the extensionless relative imports inside that package: see
   * the note at the top of `packages/crypto/src/index.ts`. Turbopack applies
   * strict ESM resolution to a `"type": "module"` package, so `./bytes.js` in a
   * file that is really `bytes.ts` is an unresolvable specifier and no Next
   * config option fixes it -- `experimental.extensionAlias` is webpack-only.
   */
  transpilePackages: ["@sluice/crypto"],

  // Only set when a value was actually found. Assigning `undefined` here makes
  // Next emit the literal string "undefined" into the bundle, which reads as a
  // configured value and then dials a host that does not exist.
  ...(convexUrl === undefined ? {} : { env: { NEXT_PUBLIC_CONVEX_URL: convexUrl } }),
};

export default nextConfig;
