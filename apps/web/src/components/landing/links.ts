/**
 * Every external destination the landing page points at, named once.
 *
 * File links use `blob/HEAD` rather than a branch name on purpose. GitHub
 * resolves HEAD to whatever the default branch is, so renaming or moving the
 * default branch cannot silently turn these into 404s. A dead link on a
 * security project's landing page is a credibility problem, not a cosmetic
 * one.
 *
 * Nothing here points at a service that does not exist. There is no docs site,
 * no status page, no sponsorship page and no npm package, so there is no link
 * to one.
 */
export const REPO_URL = "https://github.com/FarazAhmad-117/Sluice";

/**
 * THE ADMIN PANEL IS A DIFFERENT APPLICATION NOW, SO "SIGN IN" IS AN ORIGIN.
 *
 * `/login` and `/signup` used to be routes of this same Next application, so
 * the navigation linked to them relatively. They moved to `apps/admin`, which
 * is a separate Vite build; a relative link would still resolve, still render
 * no error, and land on this site's 404.
 *
 * `NEXT_PUBLIC_ADMIN_URL` is the admin panel's origin in a deployment, with no
 * trailing slash. The fallback is where `pnpm --filter admin dev` serves it, so
 * a local checkout works with nothing configured.
 *
 * The name is spelled out in full below and must stay that way: Next inlines
 * `NEXT_PUBLIC_*` by static text substitution, so a computed key or a
 * destructured `process.env` silently becomes `undefined` in the browser.
 */
const RAW_ADMIN_URL = process.env.NEXT_PUBLIC_ADMIN_URL;

const ADMIN_URL =
  RAW_ADMIN_URL !== undefined && RAW_ADMIN_URL.length > 0 && RAW_ADMIN_URL !== "undefined"
    ? RAW_ADMIN_URL.replace(/\/+$/, "")
    : "http://localhost:5180";

export const SIGN_IN_URL = `${ADMIN_URL}/login`;
export const SIGN_UP_URL = `${ADMIN_URL}/signup`;

const blob = (file: string) => `${REPO_URL}/blob/HEAD/${file}`;

export const IMPLEMENTATION_PLAN_URL = blob("Implementation_Plan.md");
export const SECURITY_URL = blob("SECURITY.md");
export const CONTRIBUTING_URL = blob("CONTRIBUTING.md");
export const LICENCE_URL = blob("LICENSE");
export const README_URL = blob("README.md");
