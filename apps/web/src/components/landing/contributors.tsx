import { CONTRIBUTING_URL, REPO_URL } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  focusRing,
  primaryAction,
  secondaryAction,
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

/**
 * Two initials on a gradient chip.
 *
 * Deliberately not a GitHub avatar image. Avatars would mean three more network
 * requests to a third-party CDN on a page that otherwise makes none, a layout
 * shift while they land, and a privacy footnote, all to show faces nobody
 * recognises. Initials render instantly and say the same thing.
 */
function Initials({ login }: { login: string }) {
  const letters = login.replace(/[^a-zA-Z]/g, "").slice(0, 2).toUpperCase() || "?";
  return (
    <span
      aria-hidden="true"
      className="grid size-9 shrink-0 place-items-center rounded-full text-[13px] font-semibold text-white"
      style={{ background: "linear-gradient(135deg, #3b82f6, #1e3a8a)" }}
    >
      {letters}
    </span>
  );
}

export async function Contributors() {
  const { contributors, live } = await loadContributors();

  return (
    <Section id="contributors" labelledBy="contributors-heading">
      <Container className="grid gap-14 lg:grid-cols-2 lg:items-start">
        <div>
          <Reveal>
            <Eyebrow>Contributors</Eyebrow>
          </Reveal>

          <Reveal delay={80}>
            <SectionHeading id="contributors-heading" className="ink mt-5">
              Everyone who has committed to Sluice.
            </SectionHeading>
          </Reveal>

          <Reveal delay={160}>
            <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
              The list is short because the project is young. The crypto core is
              where review is worth the most right now, so a test case, a
              reproduction or an argument about a domain separator beats a large
              feature.
            </p>
          </Reveal>

          <Reveal delay={240}>
            <div className="mt-8 flex flex-wrap gap-2.5">
              <a
                href={CONTRIBUTING_URL}
                target="_blank"
                rel="noreferrer noopener"
                className={`${primaryAction} h-9 rounded-full px-4 text-[13px]`}
              >
                Read CONTRIBUTING.md
              </a>
              <a
                href={`${REPO_URL}/issues`}
                target="_blank"
                rel="noreferrer noopener"
                className={`${secondaryAction} h-9 rounded-full px-4 text-[13px]`}
              >
                Open an issue
              </a>
            </div>
          </Reveal>
        </div>

        <Reveal delay={120}>
          <ul className="panel">
            {contributors.map((contributor, index) => (
              <li
                key={contributor.login}
                className={index === 0 ? "" : "border-t border-hairline"}
              >
                <a
                  href={contributor.profileUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className={`flex cursor-pointer items-center gap-3.5 px-5 py-4 transition-colors hover:bg-white/3 ${focusRing}`}
                >
                  <Initials login={contributor.login} />
                  <span className="font-mono text-sm text-text-primary">
                    {contributor.login}
                  </span>
                  {contributor.commits !== undefined ? (
                    <span className="ml-auto shrink-0 font-mono text-[12.5px] text-text-muted">
                      {contributor.commits === 1
                        ? "1 commit"
                        : `${contributor.commits} commits`}
                    </span>
                  ) : null}
                </a>
              </li>
            ))}
          </ul>

          <p className="mt-4 text-[13px] leading-relaxed text-text-faint">
            {live
              ? "Read from the GitHub API at build time; it counts accounts with commits rather than people. "
              : "The GitHub API could not be reached at build time, so this is the static fallback; the contributor graph is authoritative. "}
            Vulnerabilities go to SECURITY.md, never an issue. Commits need a
            Developer Certificate of Origin sign-off &mdash; no CLA, and there is
            not going to be one.
          </p>
        </Reveal>
      </Container>
    </Section>
  );
}
