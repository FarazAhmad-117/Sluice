import type { Metadata } from "next";

import { ContributorRoster } from "@/components/landing/contributors";
import { formatStars, loadRepoFacts, showStars } from "@/components/landing/github-repo";
import { LICENCE_URL, REPO_URL } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { PageHeader } from "@/components/landing/page-header";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  focusRing,
  textLink,
} from "@/components/landing/primitives";
import { SiteFooter } from "@/components/landing/site-footer";
import { SiteHeader } from "@/components/landing/site-header";

/**
 * THE OPEN SOURCE PAGE.
 *
 * ITS READER is the same adopter, checking whether the project is alive before
 * they put it in something. Its one job is to read as PROJECT HEALTH and never
 * as a call to contribute.
 *
 * So there is no "become a contributor", no good-first-issue shelf, no
 * community banner and no roadmap of help wanted. "View on GitHub" is the only
 * button on the page. `CONTRIBUTING.md` is in the footer of every page, where a
 * reader who came looking for it will find it and a reader who did not will
 * never be asked.
 *
 * THE TEST SECTION IS FRAMED FOR AN ADOPTER, which is a different framing from
 * the same numbers on a contributor page. An adopter does not care that the
 * suite is satisfying to run. They care that the thing they are about to trust
 * has a discipline behind it and that the discipline reaches the parts that
 * would hurt them. So the numbers are broken out by package and the property
 * test is named, because "892 tests" alone is a number and "the kill switch is
 * enumerated over 599,184 event sequences" is an argument.
 *
 * NO ILLUSTRATION HERE, per the graphics brief. Star counts and contributor
 * avatars are UI, not illustration subjects.
 */

export const metadata: Metadata = {
  title: "Sluice is open source",
  description:
    "Apache-2.0, on GitHub, with 892 tests across six packages. The licence, the repository, who works on it, and the test discipline behind it.",
};

const SUITES = [
  ["packages/crypto", 259, "Key derivation, wrapping, token minting, AEAD use, canonical encoding and signature verification."],
  ["convex", 323, "The backend. Sessions, orgs, projects, environments, secrets, tokens, the handshake and the bundle subscription."],
  ["packages/cli", 124, "The transport shell around the decision core. Spawning, draining, the epoch floor and every way a kill can be missed."],
  ["packages/sdk", 93, "The pure decision core: events in, decisions out, no network and no clock."],
  ["apps/admin", 85, "The dashboard, including that a typed password yields the key that decrypts a secret."],
  ["apps/web", 8, "This site, pinning the cryptography behind the live demonstration on the homepage."],
] as const;

export default async function OpenSourcePage() {
  const { stars } = await loadRepoFacts();

  return (
    <>
      <SiteHeader />
      <main>
        <PageHeader
          eyebrow="Open source"
          title="Apache-2.0, all of it, including the cryptography."
          aside={
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={`inline-flex h-11 cursor-pointer items-center gap-2.5 rounded-input bg-control-solid px-5 text-[15px] font-medium text-text-on-control-solid transition-colors hover:bg-control-solid-hover ${focusRing}`}
            >
              <svg aria-hidden="true" width="17" height="17" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 .5a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.4-1.4-1.8-1.4-1.8-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.7 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .5Z" />
              </svg>
              View on GitHub
              {showStars(stars) ? (
                <span className="opacity-60">{formatStars(stars)}</span>
              ) : null}
            </a>
          }
        >
          <p>
            Everything in this repository today is under{" "}
            <a
              href={LICENCE_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={textLink}
            >
              the Apache License 2.0
            </a>
            , which includes a patent grant, and you can fork it, self-host it
            and read every line that touches a key. Future commercial features
            are planned to live in a separate{" "}
            <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
              ee/
            </code>{" "}
            directory under a commercial licence. That directory does not exist
            yet, and this page will say so until it does.
          </p>
        </PageHeader>

        <Section id="tests" labelledBy="tests-heading" divided>
          <Container>
            <div className="grid gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:gap-16">
              <div>
                <Reveal>
                  <Eyebrow>Project health</Eyebrow>
                </Reveal>
                <Reveal delay={80}>
                  <SectionHeading id="tests-heading" className="ink mt-5">
                    892 tests, and the ones that matter are enumerated.
                  </SectionHeading>
                </Reveal>
                <Reveal delay={160}>
                  <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
                    A count on its own proves nothing, so here is the breakdown
                    and what each suite covers. You can reproduce the total in
                    about a minute:{" "}
                    <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                      pnpm test
                    </code>{" "}
                    at the root prints 323, and{" "}
                    <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                      pnpm -r test
                    </code>{" "}
                    prints the other five.
                  </p>
                </Reveal>
                <Reveal delay={200}>
                  <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
                    The kill switch is not sampled. The decision core&apos;s
                    property that losing a connection never kills a process is
                    ENUMERATED over 599,184 event sequences carrying just under
                    four million events, alongside hostile sequences with real
                    Ed25519 verification that produce no shutdown and never move
                    the epoch floor.
                  </p>
                </Reveal>
              </div>

              <Reveal delay={80}>
                <ul className="panel divide-y divide-hairline">
                  {SUITES.map(([name, count, covers]) => (
                    <li key={name} className="p-6">
                      <div className="flex items-baseline justify-between gap-4">
                        <p className="font-mono text-[14px] text-text-primary">{name}</p>
                        <p className="shrink-0 font-mono text-[14px] text-text-muted">
                          {`${count} tests`}
                        </p>
                      </div>
                      <p className="mt-2 text-[16px] leading-relaxed text-text-muted">
                        {covers}
                      </p>
                    </li>
                  ))}
                </ul>
              </Reveal>
            </div>
          </Container>
        </Section>

        <Section id="people" labelledBy="people-heading" divided>
          <Container className="grid gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:gap-16">
            <div>
              <Reveal>
                <Eyebrow>People</Eyebrow>
              </Reveal>
              <Reveal delay={80}>
                <SectionHeading id="people-heading" className="ink mt-5">
                  Who has committed to it.
                </SectionHeading>
              </Reveal>
              <Reveal delay={160}>
                <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
                  The list is short because the project is young, and knowing
                  that before you adopt is worth more than a banner saying the
                  community is thriving. Commits need a Developer Certificate of
                  Origin sign-off. There is no contributor licence agreement and
                  there is not going to be one.
                </p>
              </Reveal>
            </div>

            <ContributorRoster />
          </Container>
        </Section>
      </main>
      <SiteFooter />
    </>
  );
}
