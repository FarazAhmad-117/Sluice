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
          {/* SLOT: <ParticleField /> mounts here, wired after merge */}
          {/*
            The real component is <ParticleField state?: "idle" | "scattered"
            className?: string />, built on the `particle` branch. It is not
            imported here and must not be created here.

            This placeholder holds the exact box the real one inherits: a
            square that fills its column, capped so it never dwarfs the copy,
            right-aligned from `lg` up where the split becomes asymmetric.
            Swap the div for the component and keep the className.
          */}
          <div
            aria-hidden="true"
            className="mx-auto flex aspect-square w-full max-w-[380px] items-center justify-center rounded-card border border-dashed border-hairline sm:max-w-[440px] lg:mr-0 lg:ml-auto lg:max-w-[520px]"
          >
            <span className="font-mono text-xs tracking-[0.18em] text-text-muted uppercase">
              ParticleField
            </span>
          </div>
        </div>
      </Container>
    </section>
  );
}
