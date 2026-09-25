/**
 * The repository's star count, read from the GitHub API at build time.
 *
 * Same three rules as the contributor roster, for the same reasons:
 *
 *  1. It cannot fail the build. Rate limiting, a network-less build machine, a
 *     renamed repository and malformed JSON all land in `null`. The fetch has a
 *     hard timeout, so an unreachable api.github.com costs five seconds rather
 *     than hanging a build.
 *  2. It cannot lie. A number that might be wrong is worse than no number, so
 *     there is no fallback figure. `null` means the caller renders the chip
 *     without a count, which is honest and still links to the page that has it.
 *  3. `revalidate` keeps callers on the static path. Making the route dynamic
 *     would put the unauthenticated rate limit, sixty requests an hour per IP,
 *     in front of every visitor.
 */

const REPO_API = "https://api.github.com/repos/FarazAhmad-117/Sluice";

export type RepoFacts = {
  /** Absent when the API could not be read. Never guessed. */
  stars: number | null;
};

const UNKNOWN: RepoFacts = { stars: null };

export async function loadRepoFacts(): Promise<RepoFacts> {
  try {
    const response = await fetch(REPO_API, {
      headers: { Accept: "application/vnd.github+json" },
      next: { revalidate: 86400 },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return UNKNOWN;
    const payload: unknown = await response.json();
    if (typeof payload !== "object" || payload === null) return UNKNOWN;
    const stars = (payload as Record<string, unknown>).stargazers_count;
    return typeof stars === "number" && Number.isFinite(stars) ? { stars } : UNKNOWN;
  } catch {
    return UNKNOWN;
  }
}

/**
 * Thousands separated, because a four-digit count with no separator reads as a
 * version number at chip size. Below a thousand this is the identity function.
 */
export function formatStars(stars: number): string {
  return stars.toLocaleString("en-GB");
}

/**
 * Whether a count is worth printing at all.
 *
 * A zero is not printed. That is a presentation decision rather than a
 * concealment one: "GitHub 0" is a worse signal than "GitHub", it invites the
 * reader to evaluate the project on a number that measures nothing about the
 * software, and omitting it claims nothing. The link still goes to the page
 * that shows the real figure, which is the test this has to pass.
 *
 * Anything above zero is shown exactly as the API reported it, and a count that
 * could not be read is never guessed.
 */
export function showStars(stars: number | null): stars is number {
  return stars !== null && stars > 0;
}
