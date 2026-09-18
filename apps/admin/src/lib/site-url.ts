/**
 * WHERE THE "sluice" WORDMARK GOES, NOW THAT IT IS NOT THE SAME APPLICATION.
 *
 * Under Next, the dashboard and the marketing site shared one origin and one
 * router, so the wordmark was `<Link href="/">` and landed on the landing page.
 * Splitting the admin panel into its own build broke that in a way that is
 * silent rather than loud: `/` in this application is the dashboard, so the
 * link still works, still has no error, and simply stops going where the label
 * implies.
 *
 * So the destination is stated. `VITE_SITE_URL` is the marketing site's origin
 * when the two are deployed apart -- `https://sluice.dev`, or whatever the
 * deployment calls it -- and the fallback below is what a local checkout gets.
 *
 * WHY THE FALLBACK IS `http://localhost:3000` AND NOT `/`. `next dev` serves
 * the marketing site there and `vite dev` serves this one on 5180, so during
 * development the two really are at different origins and a relative `/` would
 * be wrong. In a deployment that puts them behind one hostname with a path
 * split, set `VITE_SITE_URL` to `/` and the link becomes relative again.
 *
 * It is ALWAYS AN ORDINARY `<a>`, never a router `Link`. The target is outside
 * this application's route table, and handing it to the router would produce a
 * client-side navigation to a route that does not exist.
 */

const RAW = import.meta.env.VITE_SITE_URL;

export const SITE_URL: string =
  RAW !== undefined && RAW.length > 0 && RAW !== "undefined" ? RAW : "http://localhost:3000";
