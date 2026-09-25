import { CONTRIBUTORS_GRAPH_URL } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { focusRing, textLink } from "@/components/landing/primitives";

/**
 * The contributor roster. `/open-source` only.
 *
 * IT USED TO BE ON THE HOMEPAGE AND IT SHOULD NOT HAVE BEEN. None of the
 * thirty-five sites studied for the content strategy put contributor avatars on
 * a homepage, and the reason is not fashion: a homepage visitor is deciding
 * whether to adopt, and a roster answers a question they have not asked. Here,
 * on the page a reader opens to find out whether the project is alive, it is
 * exactly the right evidence.
 *
 * IT IS NOT A RECRUITMENT DRIVE. There is no "become a contributor" button and
 * no call for help. The roster is project health for an adopter: how many
 * people touch this, and how recently. `CONTRIBUTING.md` is a footer link for
 * the reader who went looking for it.
 *
 * Read from the GitHub API at build time, with no token and no dependency, and
 * the rules it obeys are in order of importance:
 *
 *  1. It cannot fail the build. Rate limiting, a network-less build machine, a
 *     renamed repository and malformed JSON all land in the same place: the
 *     static fallback below. The fetch is wrapped and given a hard timeout, so
 *     an unreachable api.github.com costs five seconds, not a hung build.
 *  2. It cannot lie. The unauthenticated limit is sixty requests an hour per
 *     IP, so a fallback render is plausible. The fallback is therefore not a
 *     silently-wrong list: it is the one account that certainly has commits,
 *     with no commit count attached, because a count that might be wrong is
 *     worse than no count.
 *  3. It is not a grid. There are roughly two accounts here. A three-across
 *     grid of avatar cards holding two entries announces that the design
 *     expected a crowd and did not get one. A hairline list of rows reads the
 *     same at two rows as at forty.
 *
 * `revalidate` keeps this on the static path rather than making the route
 * dynamic, which would put the GitHub rate limit in front of every visitor.
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
 * recognises. Initials render instantly and say the same thing. The gradient is
 * built from the brand tokens rather than from literal colours.
 */
function Initials({ login }: { login: string }) {
  const letters = login.replace(/[^a-zA-Z]/g, "").slice(0, 2).toUpperCase() || "?";
  return (
    <span
      aria-hidden="true"
      className="grid size-9 shrink-0 place-items-center rounded-full bg-linear-to-br from-brand to-brand-solid text-[13px] font-semibold text-text-on-brand-solid"
    >
      {letters}
    </span>
  );
}

export async function ContributorRoster() {
  const { contributors, live } = await loadContributors();

  return (
    <Reveal>
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

      <p className="mt-4 text-[16px] leading-relaxed text-text-muted">
        {live
          ? "Read from the GitHub API at build time. It counts accounts with commits rather than people, and two of these accounts belong to the same person. "
          : "The GitHub API could not be reached at build time, so this is the static fallback. "}
        <a
          href={CONTRIBUTORS_GRAPH_URL}
          target="_blank"
          rel="noreferrer noopener"
          className={textLink}
        >
          The contributor graph is authoritative
        </a>
        .
      </p>
    </Reveal>
  );
}
