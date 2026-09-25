import Link from "next/link";

import { SHARPEST_LIMITS } from "@/components/landing/limits";
import { ROUTES } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  focusRing,
} from "@/components/landing/primitives";

/**
 * WHAT IS REAL TODAY. THE HONESTY PANEL.
 *
 * It sits in the middle of the page, at reading size, between the mechanism and
 * the close. Everything about that placement is deliberate and none of it is
 * negotiable:
 *
 *  - MID-PAGE, not the footer. A site that buries its limits has contradicted
 *    the reason it listed them. The only version of this section worth shipping
 *    is one the reader cannot get past.
 *  - READING SIZE. Set smaller than the paragraphs around it, this becomes
 *    legal text, and legal text is skipped by every reader alive.
 *  - BEFORE the close, not after. A reader who is going to say no should be
 *    able to say it before being asked for anything.
 *
 * THE THREE LIMITS ARE THE THREE SHARPEST and they are imported rather than
 * written here. `limits.ts` holds the canonical sentences, `/security` renders
 * the same objects, and the two therefore cannot drift. A reader who meets two
 * phrasings of "there is no re-key" trusts neither.
 *
 * The left column is not a consolation prize. Everything in it is running code
 * with tests behind it, and a limits panel with nothing beside it reads as an
 * apology rather than as an inventory.
 */

const EXISTS = [
  "A backend with sessions, organisations, projects, environments, ciphertext-only secrets, service tokens, a handshake endpoint with replay protection, and a reactive bundle subscription.",
  "A working CLI. It fetches a bundle, decrypts it locally, injects the environment, supervises your command, and kills it when a signed revocation notice arrives.",
  "A decision core whose “connection loss never kills a process” property is enumerated over 599,184 event sequences, not sampled.",
  "A dashboard where a typed password yields the key that decrypts a secret.",
  "892 tests across six packages: crypto 259, backend 323, CLI 124, SDK 93, dashboard 85, this site 8.",
] as const;

export function WhatsReal() {
  return (
    <Section id="whats-real" labelledBy="whats-real-heading">
      <Container>
        <Reveal>
          <Eyebrow>What is real today</Eyebrow>
        </Reveal>

        <Reveal delay={80}>
          <SectionHeading id="whats-real-heading" className="ink mt-5 max-w-[24ch]">
            The bad news, before you find it yourself.
          </SectionHeading>
        </Reveal>

        <Reveal delay={160}>
          <p className="mt-6 max-w-160 text-[17px] leading-relaxed text-text-muted">
            Sluice is pre-release. Both columns are accurate as of this build,
            and the right-hand one is not a roadmap: nothing below has a date
            attached to it, because nothing below has a date.
          </p>
        </Reveal>

        <div className="mt-14 grid gap-4 lg:grid-cols-2">
          <Reveal className="panel p-7 sm:p-8">
            <h3 className="text-lg font-semibold tracking-[-0.02em] text-text-primary">
              What exists and runs
            </h3>
            <ul className="mt-6 space-y-4">
              {EXISTS.map((item) => (
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
            <h3 className="text-lg font-semibold tracking-[-0.02em] text-text-primary">
              What is not true yet
            </h3>
            <dl className="mt-6 space-y-6">
              {SHARPEST_LIMITS.map((limit) => (
                <div key={limit.id} className="grid grid-cols-[18px_1fr] gap-3.5">
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
                  <div>
                    <dt className="text-[16px] font-medium text-text-primary">
                      {limit.title}
                    </dt>
                    <dd className="mt-1.5 text-[16px] leading-relaxed text-text-muted">
                      {limit.body}
                    </dd>
                  </div>
                </div>
              ))}
            </dl>
          </Reveal>
        </div>

        <Reveal delay={80}>
          <p className="mt-8 max-w-160 text-[16px] leading-relaxed text-text-muted">
            There are more limits than these three.{" "}
            <Link
              href={ROUTES.security}
              className={`cursor-pointer rounded-input text-brand underline underline-offset-4 transition-colors hover:text-brand-hover ${focusRing}`}
            >
              The full threat model lists all of them
            </Link>
            , including what the server can still see and what a compromised
            browser build could do.
          </p>
        </Reveal>
      </Container>
    </Section>
  );
}
