/**
 * Every destination this site points at, named once.
 *
 * File links use `blob/HEAD` rather than a branch name on purpose. GitHub
 * resolves HEAD to whatever the default branch is, so renaming or moving the
 * default branch cannot silently turn these into 404s. A dead link on a
 * security project's site is a credibility problem, not a cosmetic one.
 *
 * Nothing here points at a service that does not exist. There is no docs site,
 * no hosted status page, no sponsorship page and no npm package, so there is no
 * link to one.
 */
export const REPO_URL = "https://github.com/FarazAhmad-117/Sluice";

/**
 * THE ADMIN PANEL IS A DIFFERENT APPLICATION, SO "SIGN IN" IS AN ORIGIN.
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

const blob = (file: string) => `${REPO_URL}/blob/HEAD/${file}`;

export const IMPLEMENTATION_PLAN_URL = blob("Implementation_Plan.md");
export const SECURITY_URL = blob("SECURITY.md");
export const CONTRIBUTING_URL = blob("CONTRIBUTING.md");
export const LICENCE_URL = blob("LICENSE");
export const README_URL = blob("README.md");
export const CLI_README_URL = `${REPO_URL}/tree/HEAD/packages/cli`;
export const ISSUES_URL = `${REPO_URL}/issues`;
export const WATCH_URL = `${REPO_URL}/subscription`;
export const CONTRIBUTORS_GRAPH_URL = `${REPO_URL}/graphs/contributors`;

/**
 * Where a vulnerability report goes. It is the only address on this site, and
 * it is the same one `SECURITY.md` gives. If these two ever disagree, the file
 * is right and this constant is a bug.
 */
export const SECURITY_CONTACT = "faraz@cupupmarketing.com";

/** Internal routes, so a rename is one edit rather than a search. */
export const ROUTES = {
  home: "/",
  howItWorks: "/how-it-works",
  security: "/security",
  openSource: "/open-source",
  status: "/status",
} as const;

/**
 * THE PRIMARY CALL TO ACTION, AS A STRING, DECLARED ONCE.
 *
 * It is `node server.js` and not `npm start`, and that is a platform fact
 * rather than a preference. `packages/cli/src/node-runtime.ts` spawns with
 * `shell: false` on every platform, deliberately, because a shell re-parses an
 * argument vector the operator's own shell has already read. On Windows `npm`
 * is a `.cmd` shim and Node has refused to spawn `.cmd` without a shell since
 * the 2024 hardening, so `sluice run -- npm start` fails there with EINVAL or
 * ENOENT. `node server.js` is a real executable on every platform.
 *
 * A call to action that fails on the reader's machine is worse than no call to
 * action, so this string does not change without checking that file again.
 */
export const PRIMARY_COMMAND = "sluice run -- node server.js";

/**
 * Where the command sends a reader who clicks it.
 *
 * Not a download and not a signup. `sluice` is not published to npm, so the
 * honest destination is the quickstart that shows how to get it today, from a
 * clone. That page says so in its first sentence.
 */
export const PRIMARY_COMMAND_HREF = `${ROUTES.howItWorks}#quickstart`;
