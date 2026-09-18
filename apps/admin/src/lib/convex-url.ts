/**
 * THE ONE PLACE THE CONVEX DEPLOYMENT URL IS READ.
 *
 * `import.meta.env.VITE_CONVEX_URL` is spelled out in full below and must stay
 * that way. Vite inlines `import.meta.env.*` by STATIC TEXT SUBSTITUTION at
 * build time, exactly as Next does with `process.env.NEXT_PUBLIC_*`: a computed
 * key, or destructuring `import.meta.env`, produces `undefined` in the browser
 * with no warning and no build error. This is the same class of silent failure
 * as the one `vite.config.ts` exists to fix, one layer up.
 *
 * WHERE THE VALUE COMES FROM. `npx convex dev` writes `CONVEX_URL` to the
 * REPOSITORY ROOT `.env.local`. That is the wrong directory (Vite reads env
 * files from `apps/admin`) and the wrong prefix (the browser only sees
 * `VITE_*`). `vite.config.ts` bridges both. See its header.
 *
 * MISSING IS RETURNED, NOT THROWN. A module-scope throw takes down the whole
 * application with a stack trace that names this file and not the cause. The
 * routes render a plain sentence instead, which is the only version of this
 * failure a person can act on.
 */
const RAW = import.meta.env.VITE_CONVEX_URL;

export const CONVEX_URL: string | undefined =
  RAW !== undefined && RAW.length > 0 && RAW !== "undefined" ? RAW : undefined;

/** What to put on the page when the URL is missing. One sentence, actionable. */
export const CONVEX_URL_MISSING_MESSAGE =
  "This build has no Convex deployment URL. Run `npx convex dev` to write CONVEX_URL " +
  "into the repository root .env.local, or set VITE_CONVEX_URL directly, then restart " +
  "the dev server. The value is read at build time and inlined, so a running server " +
  "will not pick it up on its own.";
