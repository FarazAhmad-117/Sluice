import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
} from "@/components/landing/primitives";

/**
 * The problem, in four failure modes a reader has personally seen.
 *
 * WHY IT IS FOUR SPECIFIC STORIES AND NOT A PARAGRAPH ABOUT "SECRETS SPRAWL".
 * The category's own marketing has worn that phrase down to nothing, and a
 * reader who has heard it six times reads the seventh as filler. A sentence
 * they recognise from their own week does the job the abstraction cannot.
 *
 * THE FOURTH ONE IS THE HINGE. The first three are problems every competent
 * secrets manager already addresses, and saying so is what makes the fourth
 * land: it is the only one in the list where storing the secret somewhere
 * better changes nothing, because the damage is being done by a process that
 * already has it. The section is ordered so the reader walks into that.
 *
 * ON AGENTS. A script or an agent still running after someone thought they cut
 * it off is the canonical case, so it is here, in the problem, as an example.
 * It is deliberately NOT the headline. Nothing in the product is agent-specific
 * and the thing that proves the claim is a plain process, so an agent headline
 * would promise something the demonstration does not show. That gap is exactly
 * what the rest of this site is built to avoid.
 *
 * NO CALL TO ACTION IN THIS SECTION, or in any section between the hero and the
 * close. A page that asks for something every screen is negotiating; a page
 * that asks once is arguing.
 */

const CASES = [
  {
    title: "The secret that went into Slack",
    body: "Someone needed the staging key at 6pm and rotating it properly meant a pull request, a deploy and a restart. So it was pasted into a channel, and it is still there, and it is still valid.",
  },
  {
    title: "The .env that drifted",
    body: "The file on the machine that deploys stopped matching the file on three laptops months ago. Nobody noticed until an outage, and then the first twenty minutes went on working out which copy was right.",
  },
  {
    title: "The offboarded engineer whose token still works",
    body: "Access was removed in the identity provider on their last day. The service token they minted is held by a worker that has not restarted since, so it kept pulling secrets until someone redeployed.",
  },
  {
    title: "The process still running after you cut it off",
    body: "A script, a job, an agent. You disabled the credential, the dashboard went green, and the thing that already read it kept going. Storing that secret somewhere better would not have changed a single step of this.",
  },
] as const;

export function Problem() {
  return (
    <Section id="problem" labelledBy="problem-heading">
      <Container>
        <Reveal>
          <Eyebrow>The problem</Eyebrow>
        </Reveal>

        <Reveal delay={80}>
          <SectionHeading id="problem-heading" className="ink mt-5 max-w-[22ch]">
            Four things that go wrong with secrets you already own.
          </SectionHeading>
        </Reveal>

        <Reveal delay={160}>
          <p className="mt-6 max-w-160 text-[17px] leading-relaxed text-text-muted">
            The first three are what a secrets manager is for, and Doppler,
            Infisical, Vault and 1Password all handle them. Read the fourth one
            twice. It is the only one on this list where moving the secret
            somewhere better changes nothing at all.
          </p>
        </Reveal>

        <div className="mt-16 grid gap-4 sm:grid-cols-2">
          {CASES.map((item, index) => {
            const hinge = index === CASES.length - 1;
            return (
              <Reveal
                key={item.title}
                delay={index * 70}
                className={`panel p-7 ${hinge ? "sm:col-span-2" : ""}`}
              >
                <div className="relative">
                  <p
                    aria-hidden="true"
                    className="font-mono text-[11px] tracking-[0.14em] text-text-faint uppercase"
                  >
                    {`0${index + 1}`}
                  </p>
                  <h3 className="mt-4 text-lg font-semibold tracking-[-0.02em] text-text-primary">
                    {item.title}
                  </h3>
                  <p
                    className={`mt-3 text-[16px] leading-relaxed ${
                      hinge ? "max-w-[68ch] text-text-body" : "text-text-muted"
                    }`}
                  >
                    {item.body}
                  </p>
                </div>
              </Reveal>
            );
          })}
        </div>
      </Container>
    </Section>
  );
}
