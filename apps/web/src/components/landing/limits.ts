/**
 * THE LIMITATIONS, WRITTEN ONCE.
 *
 * The site states these in three places: the homepage panel, `/security`, and
 * `/status`. The rule from the content strategy is that a limitation named on
 * `/security` must appear UNCHANGED everywhere else it appears, because a
 * reader who meets three phrasings of "there is no re-key" trusts none of them
 * and reasonably concludes that each one was tuned for its surroundings.
 *
 * Making that a module rather than a habit is the only way it survives an edit
 * six months from now. Nothing on this site writes one of these sentences in
 * JSX. If a limitation needs rewording, it gets reworded here and every page
 * moves with it.
 *
 * These are derived from `SECURITY.md`, which is the source of truth. Where a
 * sentence here is shorter than the one there, it is shorter by deletion and
 * never by softening.
 */

export interface Limit {
  /** Stable key, used for React keys and for anchors. */
  id: string;
  /** The limitation itself, as a noun phrase. */
  title: string;
  /** What it costs the reader, stated as consequence rather than as plan. */
  body: string;
}

/** The three sharpest, carried mid-page on the homepage. */
export const SHARPEST_LIMITS: readonly Limit[] = [
  {
    id: "no-audit",
    title: "No third-party cryptographic review",
    body:
      "The cryptographic core is written against published primitives and covered by tests, which is not the same thing as having been audited by someone who does this for a living. An external review is planned and has not happened. Do not store production secrets in Sluice yet.",
  },
  {
    id: "no-rekey",
    title: "No re-key, so revocation stops delivery but does not undo decryption",
    body:
      "A token that fetched its bundle once has already unwrapped the project data key for its environment. Revoking it stops every future fetch and shuts down every live process holding it. It does not re-key the environment, so whoever pulled that key first can still open every secret in it, including secrets written after the revocation.",
  },
  {
    id: "session-token",
    title: "The dashboard session token is readable by any script on the origin",
    body:
      "It sits in sessionStorage in plaintext, alongside the user id, the normalised email, both public keys and both wrapped key blobs. One cross-site scripting flaw, in the dashboard or in any dependency it loads, takes a live session for its full lifetime. This is architectural: a Convex call is made from the browser and carries no headers, so the token travels as a function argument and an argument has to be readable by the code that builds the call.",
  },
] as const;

/**
 * Everything else that is not true yet. Stated on `/security` and `/status`.
 *
 * Ordered by how early a reader hits it, not by severity: the missing npm
 * package is the first thing that stops someone, and account recovery is the
 * one that costs the most when it bites.
 */
export const OTHER_LIMITS: readonly Limit[] = [
  {
    id: "no-npm",
    title: "Nothing is published to npm",
    body:
      "There is no stable release, no versioned API and no upgrade path guarantee. The CLI is installed from a clone today, and the quickstart says so.",
  },
  {
    id: "node-only",
    title: "Node only",
    body:
      "There are no language shims beyond Node. Sluice runs your process as a child and injects its environment, so any runtime can be supervised, but there is no Python, Go or Ruby client library.",
  },
  {
    id: "rotation-needs-restart",
    title: "Rotation does not reach a running child",
    body:
      "A process's environment cannot be changed from outside it. When a secret's value changes, Sluice logs which keys moved and the running child keeps the values it started with. A changed secret needs a restart.",
  },
  {
    id: "no-recovery",
    title: "No account recovery",
    body:
      "The key hierarchy is rooted in a password-derived key, so a forgotten password is permanent data loss. There is nothing on the server that could reconstruct it, which is the same property that keeps the operator out.",
  },
  {
    id: "no-invites",
    title: "No invitation flow",
    body:
      "Only the account that created an organisation holds any key for it. A second person cannot be added yet, so Sluice is single-operator today whatever the role model says.",
  },
  {
    id: "enumeration",
    title: "Account existence is publicly enumerable",
    body:
      "Signup rejects a duplicate email with a message saying so, so anyone can test any address and learn whether it has an account. Login deliberately returns an identical error for a wrong verifier and an unknown address, and that hardening buys nothing while signup answers the same question for free. Treat account existence as public.",
  },
] as const;

/** Every limitation, in the order `/security` and `/status` present them. */
export const ALL_LIMITS: readonly Limit[] = [
  ...SHARPEST_LIMITS,
  ...OTHER_LIMITS,
] as const;
