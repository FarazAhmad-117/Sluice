import { RevokeDemo } from "@/components/landing/revoke-demo";
import {
  Container,
  primaryAction,
  secondaryAction,
} from "@/components/landing/primitives";

/**
 * Hero.
 *
 * Asymmetric split: copy in seven columns, the generative particle field in
 * five. Exactly four text elements, which is the budget: headline, subtext,
 * and two control labels. No trust strip, no tagline under the buttons, no
 * version badge.
 *
 * The subtext carries the pre-release disclosure rather than a badge. A badge
 * would be a fifth element and would read as decoration; a sentence reads as a
 * statement. The headline describes the design Sluice is being built to, which
 * is the same claim the README makes, and the sentence directly under it says
 * the delivery path does not exist yet. Neither line survives on its own and
 * they are not meant to.
 */
export function Hero() {
  return (
    <section
      id="top"
      className="scroll-mt-28 border-b border-hairline"
      aria-labelledby="hero-heading"
    >
      <Container className="grid items-center gap-14 py-16 sm:py-20 lg:grid-cols-12 lg:gap-12 lg:py-28">
        <div className="lg:col-span-7 lg:pr-6">
          <h1
            id="hero-heading"
            className="max-w-[24ch] text-[2.5rem] leading-[1.05] font-medium tracking-[-0.035em] text-text-primary sm:text-6xl lg:text-[3.5rem]"
          >
            Revocation that reaches live processes.
          </h1>

          <p className="mt-6 max-w-[44ch] text-base leading-relaxed text-text-muted sm:mt-7 sm:text-lg">
            Zero-knowledge environment variables on Convex. Pre-release: the
            crypto core is built, the delivery path is not.
          </p>

          <div className="mt-9 flex flex-wrap items-center gap-3 sm:mt-10">
            <a href="#quickstart" className={primaryAction}>
              Quickstart
            </a>
            <a href="#threat-model" className={secondaryAction}>
              Read the threat model
            </a>
          </div>
        </div>

        <div className="lg:col-span-5">
          {/*
            The hero visual is the product mechanic, not decoration. A sphere
            of points that holds coherent and then comes apart on a revoke is
            what revocation looks like, which is why the design direction
            chose it. It rotated and did nothing until 2026-09-18, which made
            it exactly the decoration that direction ruled out.
          */}
          <RevokeDemo />
        </div>
      </Container>
    </section>
  );
}
