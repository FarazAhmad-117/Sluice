import Link from "next/link";

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
 * The mechanism in three lines: store, run, revoke.
 *
 * WHAT THIS SECTION IS DEFENDING AGAINST. A reader who has just watched a
 * signature verify wants to know whether the thing behind it is simple enough
 * to trust and specific enough to check. Three steps answers the first. Naming
 * the actual primitive in each step answers the second, and it is the reason
 * this is not "military-grade encryption": Argon2id, AES-256-GCM and Ed25519
 * are things a reader can go and look up, and a vague word is what a product
 * writes when it does not want its choices examined.
 *
 * THE ONLY OUTBOUND LINK IS TO THE MECHANISM PAGE, and it is a text link
 * rather than a button. Nothing between the hero and the closing card asks for
 * an action.
 */

const STEPS = [
  {
    ordinal: "01",
    title: "Store",
    lede: "Your secrets are encrypted before they leave you.",
    body: "A key is derived from your password with Argon2id and never leaves your device. Each secret value is sealed with AES-256-GCM under a per-environment data key, which is itself wrapped to each member's public key. The server receives ciphertext, wrapped blobs it cannot open, and public keys.",
  },
  {
    ordinal: "02",
    title: "Run",
    lede: "Sluice wraps your process instead of replacing your code.",
    body: "A service token splits under HKDF into two independent halves: one authenticates to the server, the other unwraps the data key and is never sent anywhere. The CLI fetches the bundle, decrypts it locally, injects the environment, and supervises your command as a child process. There is no SDK to import and no code change.",
  },
  {
    ordinal: "03",
    title: "Revoke",
    lede: "One signature reaches every process still holding the token.",
    body: "An admin signs an Ed25519 revocation notice with a key the server has never held. Every live process verifies it against the org public key you configured yourself, drains for five seconds, and exits with status 1. A forged notice fails verification and changes nothing.",
  },
] as const;

export function MechanismSteps() {
  return (
    <Section id="mechanism" labelledBy="mechanism-heading">
      <Container>
        <div className="grid gap-12 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
          <div>
            <Reveal>
              <Eyebrow>How it works</Eyebrow>
            </Reveal>

            <Reveal delay={80}>
              <SectionHeading id="mechanism-heading" className="ink mt-5">
                Store, run, revoke.
              </SectionHeading>
            </Reveal>

            <Reveal delay={160}>
              <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
                Three steps, and every primitive in them is named so you can go
                and check it. Nothing here asks you to import a library or
                change a line of your application.
              </p>
            </Reveal>

            {/* THE COMMAND IS DELIBERATELY NOT REPEATED HERE. It appears three
                times on this site and no more: the navigation bar, the hero and
                the closing card. A fourth printing in the middle of the page
                would turn a section that is explaining into a section that is
                selling, which is the thing the whole middle of this page is
                built to avoid. */}

            <Reveal delay={200}>
              <p className="mt-8">
                <Link
                  href={ROUTES.howItWorks}
                  className={`cursor-pointer rounded-input text-[15px] text-brand underline underline-offset-4 transition-colors hover:text-brand-hover ${focusRing}`}
                >
                  The mechanism in full, with the key hierarchy
                </Link>
              </p>
            </Reveal>
          </div>

          <div>
            {STEPS.map((step, index) => (
              <Reveal
                key={step.ordinal}
                delay={index * 90}
                className={`grid grid-cols-[3.25rem_1fr] gap-x-4 gap-y-2 py-7 ${
                  index === 0 ? "" : "border-t border-hairline"
                }`}
              >
                <p
                  aria-hidden="true"
                  className="font-mono text-[13px] text-text-faint"
                >
                  {step.ordinal}
                </p>
                <div>
                  <h3 className="text-lg font-semibold tracking-[-0.02em] text-text-primary">
                    {step.title}
                  </h3>
                  <p className="mt-2 text-[16px] leading-relaxed text-text-body">
                    {step.lede}
                  </p>
                  <p className="mt-3 max-w-[62ch] text-[16px] leading-relaxed text-text-muted">
                    {step.body}
                  </p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </Container>
    </Section>
  );
}
