import { ParticleField } from "@/components/particle-field";
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
            The particle field is the one visual on this page, and it is not
            decoration. A sphere of points that holds coherent and then
            scatters is what revocation looks like, which is why the design
            doc chose it.

            It sizes itself from its wrapper, so the box below is load
            bearing: an unsized host paints nothing rather than collapsing.
            Do not pass `absolute` here. The component hardcodes `relative`
            and Tailwind v4 resolves conflicts by source order, so `relative`
            would win and the override would fail silently.

            `state` is an edge trigger, not a held pose: passing "scattered"
            detonates and reforms over roughly two seconds, then rests on the
            sphere again. It is left at the "idle" default until there is a
            real interaction worth spending it on.
          */}
          <ParticleField className="mx-auto aspect-square w-full max-w-[380px] sm:max-w-[440px] lg:mr-0 lg:ml-auto lg:max-w-[520px]" />
        </div>
      </Container>
    </section>
  );
}
