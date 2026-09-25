import Link from "next/link";

import { CommandCta } from "@/components/landing/command-cta";
import { ROUTES } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  SectionHeading,
  focusRing,
} from "@/components/landing/primitives";

/**
 * The closing card. The third and last appearance of the command on this site.
 *
 * ONE HONEST NEXT ACTION, PLUS A QUIETER ONE. The command goes to the
 * quickstart, which opens by saying Sluice is not on npm and shows the clone
 * that works today. Nothing here collects an email address, because there is no
 * release to notify anyone about and no email delivery to do it with, and a
 * waitlist form on a page whose whole argument is "we do not overclaim" would
 * be the single loudest contradiction on the site.
 *
 * The second link is to `/security`, deliberately quiet and deliberately
 * present. A meaningful share of the people who reach the bottom of this page
 * are not going to run anything next; they are going to go looking for the
 * reason to say no. Sending them somewhere better than a search engine is worth
 * more than pretending they do not exist.
 *
 * The glow is anchored below the card and bleeds up through it, which is the
 * one place on the page where light comes from beneath. That is deliberate: it
 * is the last thing seen before the footer, and a horizon reads as an ending.
 */
export function FinalCta() {
  return (
    <section aria-labelledby="final-cta-heading" className="pb-8">
      <Container>
        <Reveal className="panel relative overflow-hidden px-8 py-20 text-center sm:px-10">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute bottom-[-260px] left-1/2 h-[420px] w-[760px] -translate-x-1/2"
            style={{
              background: "radial-gradient(ellipse, var(--glow-brand), transparent 65%)",
              filter: "blur(20px)",
            }}
          />

          <div className="relative">
            <div className="flex justify-center">
              <Eyebrow>Run it</Eyebrow>
            </div>

            <SectionHeading
              id="final-cta-heading"
              className="ink mx-auto mt-5 max-w-[20ch]"
            >
              Put it in front of one process and see.
            </SectionHeading>

            <p className="mx-auto mt-5 max-w-[52ch] text-[17px] leading-relaxed text-text-muted">
              The quickstart installs the CLI from a clone, because nothing is on
              npm yet, and gets you from an empty environment to a revoked
              process without touching your application code.
            </p>

            <div className="mt-9 flex flex-wrap justify-center gap-4">
              <CommandCta size="md" />
            </div>

            <p className="mt-7 text-[16px] text-text-muted">
              Looking for a reason to say no?{" "}
              <Link
                href={ROUTES.security}
                className={`cursor-pointer rounded-input text-brand underline underline-offset-4 transition-colors hover:text-brand-hover ${focusRing}`}
              >
                Read the threat model first
              </Link>
              .
            </p>
          </div>
        </Reveal>
      </Container>
    </section>
  );
}
