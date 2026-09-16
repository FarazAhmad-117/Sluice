import {
  CONTRIBUTING_URL,
  REPO_URL,
  SECURITY_URL,
} from "@/components/landing/links";
import {
  Container,
  SectionHeading,
  focusRing,
  textLink,
} from "@/components/landing/primitives";

/**
 * Contributors.
 *
 * Read from the GitHub API at build time, with no token and no dependency.
 *
 * The rules this obeys, in order of importance:
 *
 *  1. It cannot fail the build. Rate limiting, a network-less build machine,
 *     a renamed repository and malformed JSON all land in the same place: the
 *     static fallback below. The fetch is wrapped and given a hard timeout, so
 *     an unreachable api.github.com costs five seconds, not a hung build.
 *  2. It cannot lie. The unauthenticated limit is sixty requests an hour per
 *     IP, so a fallback render is plausible. The fallback is therefore not a
 *     silently-wrong list: it is the one account that certainly has commits,
 *     with no commit count attached, because a count that might be wrong is
 *     worse than no count.
 *  3. It is not a grid. There is roughly one human here. A three-across grid
 *     of avatar cards holding one entry announces that the design expected a
 *     crowd and did not get one. A hairline list of rows reads the same at one
 *     row as at forty.
 *
 * `revalidate` keeps this on the static path rather than making the route
 * dynamic, which would put the GitHub rate limit in front of every visitor.
 *
 * Note for whoever reads this list: it counts GitHub accounts with commits,
 * not people. Two accounts here belong to the same person.
 */

const CONTRIBUTORS_API =
  "https://api.github.com/repos/FarazAhmad-117/Sluice/contributors?per_page=24";

type Contributor = {
  login: string;
  profileUrl: string;
  /** Absent when the API could not be read. Never guessed. */
  commits?: number;
};

const FALLBACK: Contributor[] = [
  { login: "FarazAhmad-117", profileUrl: "https://github.com/FarazAhmad-117" },
];

function parseContributors(payload: unknown): Contributor[] | null {
  if (!Array.isArray(payload)) return null;

  const parsed: Contributor[] = [];
  for (const entry of payload) {
    if (typeof entry !== "object" || entry === null) continue;
    const record = entry as Record<string, unknown>;
    const login = record.login;
    const profileUrl = record.html_url;
    const commits = record.contributions;
    if (typeof login !== "string" || typeof profileUrl !== "string") continue;
    if (!profileUrl.startsWith("https://github.com/")) continue;
    parsed.push({
      login,
      profileUrl,
      commits: typeof commits === "number" ? commits : undefined,
    });
  }

  return parsed.length > 0 ? parsed : null;
}

type Roster = { contributors: Contributor[]; live: boolean };

const FELL_BACK: Roster = { contributors: FALLBACK, live: false };

async function loadContributors(): Promise<Roster> {
  try {
    const response = await fetch(CONTRIBUTORS_API, {
      headers: { Accept: "application/vnd.github+json" },
      next: { revalidate: 86400 },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return FELL_BACK;
    const parsed = parseContributors(await response.json());
    return parsed === null ? FELL_BACK : { contributors: parsed, live: true };
  } catch {
    return FELL_BACK;
  }
}

export async function Contributors() {
  const { contributors, live } = await loadContributors();

  return (
    <section
      id="contributors"
      className="scroll-mt-28 border-b border-hairline"
      aria-labelledby="contributors-heading"
    >
      <Container className="py-20 sm:py-24">
        <SectionHeading id="contributors-heading" className="max-w-[22ch]">
          Everyone who has committed to Sluice
        </SectionHeading>

        <p className="mt-6 max-w-[62ch] text-base leading-relaxed text-text-muted sm:text-lg">
          The list below is the whole of it, and it is short because the
          project is young. The crypto core is where review is worth the most
          right now, so a test case, a reproduction or an argument with a
          domain separator is a more useful contribution than a large feature.
          Vulnerabilities go to{" "}
          <a
            href={SECURITY_URL}
            target="_blank"
            rel="noreferrer noopener"
            className={textLink}
          >
            SECURITY.md
          </a>
          , never to an issue.
        </p>

        <ul className="mt-12 max-w-2xl divide-y divide-hairline border-y border-hairline">
          {contributors.map((contributor) => (
            <li key={contributor.login}>
              <a
                href={contributor.profileUrl}
                target="_blank"
                rel="noreferrer noopener"
                className={`group flex cursor-pointer items-baseline justify-between gap-6 py-5 transition-colors hover:text-brand ${focusRing}`}
              >
                <span className="font-mono text-base text-text-primary transition-colors group-hover:text-brand">
                  {contributor.login}
                </span>
                {contributor.commits !== undefined ? (
                  <span className="shrink-0 font-mono text-sm text-text-muted">
                    {contributor.commits === 1
                      ? "1 commit"
                      : `${contributor.commits} commits`}
                  </span>
                ) : null}
              </a>
            </li>
          ))}
        </ul>

        <p className="mt-4 max-w-2xl text-base leading-relaxed text-text-muted">
          {live ? (
            <>
              Read from the GitHub API when this page was built, so it counts
              accounts with commits rather than people.
            </>
          ) : (
            <>
              The GitHub API could not be reached when this page was built, so
              this is the static fallback. The{" "}
              <a
                href={`${REPO_URL}/graphs/contributors`}
                target="_blank"
                rel="noreferrer noopener"
                className={textLink}
              >
                contributor graph
              </a>{" "}
              is authoritative.
            </>
          )}
        </p>

        <div className="mt-10 flex flex-wrap items-center gap-x-8 gap-y-3">
          <a
            href={CONTRIBUTING_URL}
            target="_blank"
            rel="noreferrer noopener"
            className={`${textLink} text-base`}
          >
            Read CONTRIBUTING.md
          </a>
          <a
            href={`${REPO_URL}/issues`}
            target="_blank"
            rel="noreferrer noopener"
            className={`${textLink} text-base`}
          >
            Open an issue
          </a>
          <p className="text-base text-text-muted">
            Commits need a Developer Certificate of Origin sign-off. There is no
            contributor licence agreement and there is not going to be one.
          </p>
        </div>
      </Container>
    </section>
  );
}
