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

const blob = (file: string) => `${REPO_URL}/blob/HEAD/${file}`;

export const IMPLEMENTATION_PLAN_URL = blob("Implementation_Plan.md");
export const SECURITY_URL = blob("SECURITY.md");
export const CONTRIBUTING_URL = blob("CONTRIBUTING.md");
export const LICENCE_URL = blob("LICENSE");
export const README_URL = blob("README.md");
