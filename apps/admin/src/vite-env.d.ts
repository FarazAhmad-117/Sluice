/// <reference types="vite/client" />

/**
 * The environment variables this application reads.
 *
 * It is declared so that the name and its optionality are written down
 * somewhere a reader will find them. `vite/client` puts an index signature on
 * `ImportMetaEnv`, so this does not turn a typo into a compile error; what it
 * does is make the single supported name, and its type, explicit.
 *
 * Both are OPTIONAL, and for `VITE_CONVEX_URL` that is the point: the value is
 * absent in a fresh clone and in CI, and `lib/convex-url.ts` turns that into a
 * sentence on the page rather than a crash.
 *
 * `vite.config.ts` is what puts the Convex URL here; see its header for where it
 * comes from and why the search is not Vite's default.
 */
interface ImportMetaEnv {
  readonly VITE_CONVEX_URL?: string;
  /** The marketing site's origin. See `lib/site-url.ts`. */
  readonly VITE_SITE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
