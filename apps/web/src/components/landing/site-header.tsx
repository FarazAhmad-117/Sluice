import { loadRepoFacts } from "@/components/landing/github-repo";
import { SiteNav } from "@/components/landing/site-nav";

/**
 * The navigation bar's server half.
 *
 * `SiteNav` needs the scroll position, so it is a client component and cannot
 * read the GitHub API itself. This reads the star count at build time and hands
 * it down. Every page renders this rather than `SiteNav` directly, so no page
 * can accidentally ship a bar with no star chip.
 */
export async function SiteHeader({ cta = true }: { cta?: boolean }) {
  const { stars } = await loadRepoFacts();
  return <SiteNav stars={stars} cta={cta} />;
}
