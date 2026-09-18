import type { NextConfig } from "next";

/**
 * THE CONVEX URL BRIDGE THAT USED TO LIVE HERE IS GONE, AND ITS ABSENCE IS THE
 * POINT.
 *
 * This file used to read the repository root `.env.local` by hand, because
 * `npx convex dev` writes `CONVEX_URL` there and Next reads env files only from
 * the application directory and exposes only `NEXT_PUBLIC_*`. That bridge moved
 * with the code that needed it: the dashboard is `apps/admin` now, and
 * `apps/admin/vite.config.ts` carries the same search with the same reasoning.
 *
 * THIS APPLICATION NO LONGER TALKS TO CONVEX AT ALL. The landing page opens no
 * WebSocket, holds no session and reads no deployment URL, which was already
 * the intent -- the previous revision kept the three providers off the landing
 * page precisely so that marketing could not open a socket -- and is now true
 * by construction rather than by discipline. If a marketing page ever needs
 * live data, put the bridge back here rather than reaching into `apps/admin`.
 *
 * `NEXT_PUBLIC_ADMIN_URL` is read directly by `src/components/landing/links.ts`
 * and needs no bridge: it is a plain `NEXT_PUBLIC_*` variable that belongs in
 * `apps/web/.env.local`, which is exactly where Next already looks.
 */
const nextConfig: NextConfig = {
  /**
   * `@sluice/crypto` publishes TypeScript SOURCE (`"main": "./src/index.ts"`)
   * rather than a build artefact, which is deliberate -- an audited crypto
   * package that shipped a compiled bundle would be one whose reviewed code and
   * shipped code are different files. Next therefore has to compile it.
   *
   * Still required after the dashboard moved: `lib/landing/hero-revocation.ts`
   * signs a real revocation notice in the browser to drive the hero animation,
   * so the landing page imports the package too.
   *
   * This pairs with the extensionless relative imports inside that package: see
   * the note at the top of `packages/crypto/src/index.ts`. Turbopack applies
   * strict ESM resolution to a `"type": "module"` package, so `./bytes.js` in a
   * file that is really `bytes.ts` is an unresolvable specifier and no Next
   * config option fixes it -- `experimental.extensionAlias` is webpack-only.
   */
  transpilePackages: ["@sluice/crypto"],
};

export default nextConfig;
