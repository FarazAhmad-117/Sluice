import Link from "next/link";

import { formatStars, loadRepoFacts, showStars } from "@/components/landing/github-repo";
import { ROUTES } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { Container, focusRing } from "@/components/landing/primitives";

/**
 * The open source proof point. One line and a link.
 *
 * WHY IT IS THIS SMALL. Open source is evidence that the project is alive and
 * that its claims can be checked, which is one sentence of work. It is not a
 * pitch, and the page it links to is not a recruitment drive. The contributor
 * roster that used to sit on the homepage has moved to `/open-source`, where a
 * reader who wants it will go looking: none of the thirty-five sites studied
 * put contributor avatars on a homepage, because a homepage visitor is deciding
 * whether to adopt, not whether to commit.
 *
 * No eyebrow and no section heading, so it reads as a rule across the page
 * rather than as a section competing with the two either side of it.
 */
export async function OpenSourceProof() {
  const { stars } = await loadRepoFacts();

  return (
    <section aria-label="Open source" className="scroll-mt-24 py-8">
      <Container>
        <Reveal className="flex flex-wrap items-baseline gap-x-3 gap-y-2 border-y border-hairline py-8">
          <p className="text-[17px] leading-relaxed text-text-body">
            Apache-2.0, every line of it, including the cryptography and the
            tests that pin it.
            {showStars(stars) ? (
              <span className="text-text-muted">{` ${formatStars(stars)} stars on GitHub.`}</span>
            ) : null}
          </p>
          <Link
            href={ROUTES.openSource}
            className={`cursor-pointer rounded-input text-[17px] text-brand underline underline-offset-4 transition-colors hover:text-brand-hover ${focusRing}`}
          >
            The licence, the repository and who works on it
          </Link>
        </Reveal>
      </Container>
    </section>
  );
}
