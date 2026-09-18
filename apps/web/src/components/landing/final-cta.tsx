import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  SectionHeading,
  primaryAction,
  secondaryAction,
} from "@/components/landing/primitives";

/**
 * The closing card.
 *
 * WHAT IT ASKS FOR, AND WHY IT IS NOT "GET STARTED". Every other landing page
 * in this category closes by asking for a signup. This one cannot: there is no
 * release, no published package and no upgrade path, so a signup would be
 * collecting an address against a product that does not exist and the visitor
 * would find that out on the next screen.
 *
 * What it asks for instead is the thing the project genuinely needs at this
 * stage, which is adversarial reading. "Read the threat model before you read
 * the code" is a real instruction with a real destination, and it is a stronger
 * close than a disabled signup form because it is the only ask on the page that
 * a security-minded reader will actually respect.
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
              background:
                "radial-gradient(ellipse, rgb(37 99 235 / 0.55), transparent 65%)",
              filter: "blur(20px)",
            }}
          />

          <div className="relative">
            <div className="flex justify-center">
              <Eyebrow>Start here</Eyebrow>
            </div>

            <SectionHeading
              id="final-cta-heading"
              className="ink mx-auto mt-5 max-w-[20ch]"
            >
              Read the threat model before you read the code.
            </SectionHeading>

            <p className="mx-auto mt-5 max-w-[46ch] text-[17px] leading-relaxed text-text-muted">
              Then clone it, break it, and tell us where it bends.
            </p>

            <div className="mt-9 flex flex-wrap justify-center gap-3">
              <a
                href="#quickstart"
                className={`${primaryAction} h-11 rounded-full px-5 text-[15px]`}
              >
                Clone and run the tests
              </a>
              <a
                href="#threat-model"
                className={`${secondaryAction} h-11 rounded-full px-5 text-[15px]`}
              >
                Threat model
              </a>
            </div>
          </div>
        </Reveal>
      </Container>
    </section>
  );
}
