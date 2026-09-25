import type { Metadata } from "next";
import Link from "next/link";

import { ALL_LIMITS } from "@/components/landing/limits";
import { REPO_URL, ROUTES, WATCH_URL } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { PageHeader } from "@/components/landing/page-header";
import {
  Container,
  Section,
  focusRing,
  textLink,
} from "@/components/landing/primitives";
import { SiteFooter } from "@/components/landing/site-footer";
import { SiteHeader } from "@/components/landing/site-header";

/**
 * THE STATUS PAGE. THIN, AND THIN ON PURPOSE.
 *
 * ITS READER arrived because they clicked something and want to know how much
 * of this is real. Its one job is to land them honestly, in about thirty
 * seconds, without a form.
 *
 * NO DATES. Not a quarter, not a season, not "soon". A solo pre-release project
 * that publishes a date publishes a thing it will later be wrong about, and the
 * whole credibility of this site rests on not doing that. The only live signal
 * anyone should trust is the commit log, so the one action here is a GitHub
 * watch.
 *
 * NO EMAIL CAPTURE. There is no email delivery infrastructure in this project,
 * so a notify-me form would either do nothing or promise something no code
 * exists to keep. Inventing one would be its own overclaim, on the page least
 * able to afford it.
 *
 * NOT A HOSTED UPTIME PAGE. There is no deployment being monitored and no
 * incident history, so this page never shows a green dot. If that ever changes
 * this file should be replaced, not extended.
 *
 * THE "NOT BUILT" LIST IS `limits.ts`, unchanged, same as `/security`.
 */

export const metadata: Metadata = {
  title: "Sluice status",
  description:
    "What exists in Sluice today, what is named and not built, and where to watch for changes. Pre-release, no dates.",
};

const WORKING = [
  "A crypto core: Argon2id key derivation, AES-256-GCM, the HKDF auth and unwrap token split, and signed revocation notices.",
  "A backend with sessions, organisations, projects, environments, ciphertext-only secrets, service tokens, a handshake endpoint with replay protection, and a reactive bundle subscription.",
  "A decision core whose “connection loss never kills a process” property is enumerated over 599,184 event sequences, not sampled.",
  "A working CLI. sluice run fetches a bundle, decrypts it locally, injects the environment, supervises your command, and kills it when a signed revocation notice arrives.",
  "A dashboard where a typed password yields the key that decrypts a secret.",
  "892 tests across six packages.",
] as const;

export default function StatusPage() {
  return (
    <>
      <SiteHeader />
      <main>
        <PageHeader eyebrow="Status" title="Pre-release. Here is exactly where it is.">
          <p>
            No dates on this page, and there will not be any. A solo project
            that publishes a date publishes something it will later be wrong
            about. The commit log is the only live signal worth trusting, so the
            one thing to do here is watch it.
          </p>
        </PageHeader>

        <Section id="what-exists" labelledBy="what-exists-heading" className="!pt-4">
          <Container className="grid gap-4 lg:grid-cols-2">
            <Reveal className="panel p-7 sm:p-8">
              <h2
                id="what-exists-heading"
                className="text-xl font-semibold tracking-[-0.02em] text-text-primary"
              >
                Working today
              </h2>
              <ul className="mt-6 space-y-4">
                {WORKING.map((item) => (
                  <li key={item} className="grid grid-cols-[18px_1fr] gap-3.5">
                    <svg
                      aria-hidden="true"
                      className="mt-1.5"
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="var(--status-healthy)"
                      strokeWidth="3"
                      strokeLinecap="round"
                    >
                      <path d="M5 12l5 5 9-10" />
                    </svg>
                    <p className="text-[16px] leading-relaxed text-text-body">{item}</p>
                  </li>
                ))}
              </ul>
            </Reveal>

            <Reveal delay={80} className="panel p-7 sm:p-8">
              <h2 className="text-xl font-semibold tracking-[-0.02em] text-text-primary">
                Named, and not true yet
              </h2>
              <p className="mt-3 text-[16px] leading-relaxed text-text-muted">
                The same words as{" "}
                <Link href={ROUTES.security} className={textLink}>
                  the security page
                </Link>
                , because they are the same facts.
              </p>
              <ul className="mt-6 space-y-4">
                {ALL_LIMITS.map((limit) => (
                  <li key={limit.id} className="grid grid-cols-[18px_1fr] gap-3.5">
                    <svg
                      aria-hidden="true"
                      className="mt-1.5"
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="var(--status-warning)"
                      strokeWidth="3"
                      strokeLinecap="round"
                    >
                      <path d="M6 6l12 12M18 6 6 18" />
                    </svg>
                    <p className="text-[16px] leading-relaxed text-text-body">
                      {limit.title}
                    </p>
                  </li>
                ))}
              </ul>
            </Reveal>
          </Container>
        </Section>

        <Section id="watch" className="!pt-0">
          <Container>
            <Reveal className="panel flex flex-wrap items-center justify-between gap-6 p-8">
              <div>
                <p className="text-[17px] font-medium text-text-primary">
                  Watch the repository.
                </p>
                <p className="mt-2 max-w-[56ch] text-[16px] leading-relaxed text-text-muted">
                  There is no mailing list, because there is no email delivery
                  in this project and a form that collects an address it cannot
                  use would be the wrong thing to put on this page of all pages.
                  A GitHub watch is real and it is instant.
                </p>
              </div>
              <a
                href={WATCH_URL}
                target="_blank"
                rel="noreferrer noopener"
                className={`inline-flex h-11 shrink-0 cursor-pointer items-center gap-2.5 rounded-input bg-control-solid px-5 text-[15px] font-medium text-text-on-control-solid transition-colors hover:bg-control-solid-hover ${focusRing}`}
              >
                <svg aria-hidden="true" width="17" height="17" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 .5a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.4-1.4-1.8-1.4-1.8-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.7 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .5Z" />
                </svg>
                Watch on GitHub
              </a>
            </Reveal>

            <Reveal delay={80}>
              <p className="mt-6 text-[16px] leading-relaxed text-text-muted">
                This page is not a hosted uptime dashboard. Nothing is deployed
                for production use, so there is no incident history to show.{" "}
                <a
                  href={REPO_URL}
                  target="_blank"
                  rel="noreferrer noopener"
                  className={textLink}
                >
                  The repository
                </a>{" "}
                is the whole of it.
              </p>
            </Reveal>
          </Container>
        </Section>
      </main>
      <SiteFooter />
    </>
  );
}
