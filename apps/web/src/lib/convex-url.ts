/**
 * THE ONE PLACE THE CONVEX DEPLOYMENT URL IS READ.
 *
 * `process.env.NEXT_PUBLIC_CONVEX_URL` is spelled out in full below and must
 * stay that way. Next inlines `NEXT_PUBLIC_*` by STATIC TEXT SUBSTITUTION at
 * build time: `process.env[name]` with a computed name, or destructuring
 * `process.env`, produces `undefined` in the browser with no warning and no
 * build error. This is the same class of silent failure as the one
 * `next.config.ts` exists to fix, one layer up.
 *
 * WHERE THE VALUE COMES FROM. `npx convex dev` writes `CONVEX_URL` to the
 * REPOSITORY ROOT `.env.local`. That is the wrong directory (Next reads env
 * files from `apps/web`) and the wrong prefix (the browser only sees
 * `NEXT_PUBLIC_*`). `next.config.ts` bridges both. See its header.
 *
 * MISSING IS RETURNED, NOT THROWN. A module-scope throw in a client component
 * takes down the whole route with a stack trace that names this file and not
 * the cause. The pages render a plain sentence instead, which is the only
 * version of this failure a person can act on.
 */
const RAW = process.env.NEXT_PUBLIC_CONVEX_URL;

export const CONVEX_URL: string | undefined =
  RAW !== undefined && RAW.length > 0 && RAW !== "undefined" ? RAW : undefined;

/** What to put on the page when the URL is missing. One sentence, actionable. */
export const CONVEX_URL_MISSING_MESSAGE =
  "This build has no Convex deployment URL. Run `npx convex dev` to write CONVEX_URL " +
  "into the repository root .env.local, or set NEXT_PUBLIC_CONVEX_URL directly, then " +
  "rebuild. The value is read at build time and inlined, so restarting the dev server " +
  "is required after it changes.";
