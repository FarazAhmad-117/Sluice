import { SECURITY_URL } from "@/components/landing/links";
import {
  Container,
  Eyebrow,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";

/**
 * Threat model, from Implementation_Plan.md section 2.
 *
 * Both lists, side by side, symmetric. The second column is not softened and
 * is not shorter than it is in the plan. A zero-knowledge claim with no named
 * adversary is marketing, and a security reader who cannot find the limits
 * assumes they were hidden rather than absent.
 *
 * Layout family: symmetric two-column opposition. It is text against text,
 * which is a different thing from the hero's asymmetric text against visual,
 * and the two are separated by the quickstart and the ledger.
 *
 * Eyebrow 2 of 2 on the page.
 */

const DEFENDED = [
  {
    adversary: "A stolen database dump or backup",
    mitigation: "Ciphertext only. No key material is stored alongside it.",
  },
  {
    adversary:
      "A malicious or legally compelled operator, meaning the people running Sluice",
    mitigation: "No decryption key ever reaches the server.",
  },
  {
    adversary: "A compromise of the Convex platform",
    mitigation: "The same answer. There is no key there to take.",
  },
  {
    adversary: "A network attacker with TLS stripped",
    mitigation: "Payloads are already encrypted end to end.",
  },
  {
    adversary: "A stolen service token",
    mitigation: "Revocable, and scoped to a single environment.",
  },
  {
    adversary: "A server pushing forged revocations",
    mitigation: "Notices are signed by keys the customer holds.",
  },
  {
    adversary: "An insider at a customer organisation",
    mitigation:
      "Role checks, an audit log, and a separate key per environment.",
  },
];

const NOT_DEFENDED = [
  {
    adversary: "A compromised client device",
    detail:
      "If an admin's laptop is owned, their keys are owned. Sluice cannot tell the difference between the admin and malware running as the admin.",
  },
  {
    adversary: "Malicious JavaScript served to the web dashboard",
    detail:
      "This is the unsolved problem of browser-based end-to-end encryption. A compromised server can serve a build that exfiltrates the master unlock key. A strict CSP, subresource integrity, reproducible builds and a transparency log narrow the window and make tampering detectable afterwards. They do not eliminate the attack.",
  },
  {
    adversary: "A workload that has already decrypted a value",
    detail:
      "Once a process decrypts a secret it can log it, leak it or send it anywhere. Sluice controls delivery, not use.",
  },
  {
    adversary: "A customer choosing a weak password",
    detail:
      "The key hierarchy is rooted in a password-derived key. A weak password is a weak root. A minimum is enforced and SSO-backed key wrapping is planned, neither of which saves a password that is guessable.",
  },
];

function ColumnHeading({
  id,
  title,
  note,
}: {
  id: string;
  title: string;
  note: string;
}) {
  return (
    <div className="border-b border-hairline pb-5">
      <h3 id={id} className="text-xl font-medium text-text-primary sm:text-2xl">
        {title}
      </h3>
      <p className="mt-2 text-base leading-relaxed text-text-muted">{note}</p>
    </div>
  );
}

export function ThreatModel() {
  return (
    <section
      id="threat-model"
      className="scroll-mt-28 border-b border-hairline bg-surface-panel"
      aria-labelledby="threat-model-heading"
    >
      <Container className="py-20 sm:py-24">
        <Eyebrow>Threat model</Eyebrow>

        <SectionHeading
          id="threat-model-heading"
          className="mt-4 max-w-[24ch]"
        >
          What Sluice defends against, and what it does not
        </SectionHeading>

        <p className="mt-6 max-w-[62ch] text-base leading-relaxed text-text-muted sm:text-lg">
          A zero-knowledge claim means nothing until you say who it holds
          against. Both lists below are published in full in{" "}
          <a
            href={SECURITY_URL}
            target="_blank"
            rel="noreferrer noopener"
            className={textLink}
          >
            SECURITY.md
          </a>
          . The second one is not a list of things that get quietly fixed
          later. Those are the cost of the design.
        </p>

        <div className="mt-14 grid gap-12 lg:grid-cols-2 lg:gap-14">
          <div>
            <ColumnHeading
              id="threat-defended"
              title="Defended against"
              note="What the architecture is built to hold against, and the reason it holds."
            />
            <dl className="mt-2 divide-y divide-hairline">
              {DEFENDED.map((item) => (
                <div key={item.adversary} className="py-5">
                  <dt className="text-base font-medium text-text-primary">
                    {item.adversary}
                  </dt>
                  <dd className="mt-1.5 text-base leading-relaxed text-text-muted">
                    {item.mitigation}
                  </dd>
                </div>
              ))}
            </dl>
          </div>

          <div>
            <ColumnHeading
              id="threat-not-defended"
              title="Not defended against"
              note="Real limits, stated plainly. They are not oversights and they are not going away."
            />
            <dl className="mt-2 divide-y divide-hairline">
              {NOT_DEFENDED.map((item) => (
                <div key={item.adversary} className="py-5">
                  <dt className="text-base font-medium text-text-primary">
                    {item.adversary}
                  </dt>
                  <dd className="mt-1.5 text-base leading-relaxed text-text-muted">
                    {item.detail}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>

        <p className="mt-12 max-w-[62ch] text-base leading-relaxed text-text-muted">
          The design has a standing cost too. Server-side secret scanning,
          server-side rotation of third-party credentials and push sync to
          other platforms cannot be built on a server that holds no key.
          Anything needing plaintext has to run on the customer's own machine.
        </p>
      </Container>
    </section>
  );
}
