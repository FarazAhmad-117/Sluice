import { SECURITY_URL } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";

/**
 * Threat model, from Implementation_Plan.md section 2.
 *
 * Both lists, side by side, symmetric. The second column is not softened and is
 * not shorter than it is in the plan. A zero-knowledge claim with no named
 * adversary is marketing, and a security reader who cannot find the limits
 * assumes they were hidden rather than absent.
 *
 * The two panels are deliberately identical in construction -- same padding,
 * same row rhythm, same header shape -- and differ only in the tick or cross
 * and the colour of it. Any asymmetry here would be read as an argument, and
 * the argument this section is making is that both lists are equally real.
 *
 * Eyebrow 2 of 2 on the page.
 */

const DEFENDED = [
  ["A stolen database dump or backup", "Ciphertext only. No key material is stored alongside it."],
  [
    "A malicious or legally compelled operator",
    "No decryption key ever reaches the people running Sluice.",
  ],
  ["A compromise of the Convex platform", "The same answer. There is no key there to take."],
  ["A network attacker with TLS stripped", "Payloads are already encrypted end to end."],
  ["A stolen service token", "Revocable, and scoped to a single environment."],
  ["A server pushing forged revocations", "Notices are signed by keys the customer holds."],
  [
    "An insider at a customer organisation",
    "Role checks, an audit log, and a separate key per environment.",
  ],
] as const;

const NOT_DEFENDED = [
  [
    "A compromised client device",
    "If an admin's laptop is owned, their keys are owned. Sluice cannot tell the admin from malware running in the same window.",
  ],
  [
    "Malicious JavaScript served to the web dashboard",
    "The unsolved problem of browser-based end-to-end encryption. A compromised server can serve a build that exfiltrates the master unlock key. CSP, subresource integrity, reproducible builds and a transparency log narrow the window and make tampering detectable afterwards. They do not eliminate the attack.",
  ],
  [
    "A workload that has already decrypted a value",
    "Once a process has a secret it can log it, leak it or send it anywhere. Sluice controls delivery, not use.",
  ],
  [
    "A customer choosing a weak password",
    "The key hierarchy is rooted in a password-derived key, so a weak password is a weak root. A minimum length and SSO-backed wrapping are both planned, and neither saves a password that is guessable.",
  ],
] as const;

const TICK = (
  <path d="M5 12l5 5 9-10" />
);
const CROSS = <path d="M6 6l12 12M18 6 6 18" />;

function Panel({
  id,
  title,
  note,
  rows,
  tone,
}: {
  id: string;
  title: string;
  note: string;
  rows: readonly (readonly [string, string])[];
  tone: "defended" | "open";
}) {
  const accent = tone === "defended" ? "var(--status-healthy)" : "var(--status-warning)";

  return (
    <div className="panel p-2.5">
      <div className="flex items-start gap-3 p-4 pb-4">
        <div
          className="grid size-7.5 shrink-0 place-items-center rounded-[9px]"
          style={{ background: `color-mix(in srgb, ${accent} 12%, transparent)` }}
        >
          <svg
            aria-hidden="true"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke={accent}
            strokeWidth="2.4"
            strokeLinecap="round"
          >
            {tone === "defended" ? (
              <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3z" />
            ) : (
              <>
                <circle cx="12" cy="12" r="9" />
                <path d="M12 8v5M12 16v.01" />
              </>
            )}
          </svg>
        </div>
        <h3 id={id} className="text-lg font-semibold tracking-[-0.02em] text-text-primary">
          {title}
        </h3>
        <p className="ml-auto hidden max-w-57.5 text-right text-[13px] leading-snug text-text-muted lg:block">
          {note}
        </p>
      </div>

      <dl>
        {rows.map(([adversary, detail]) => (
          <div
            key={adversary}
            className="grid grid-cols-[18px_1fr] gap-3.5 border-t border-hairline p-4"
          >
            <svg
              aria-hidden="true"
              className="mt-1"
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke={accent}
              strokeWidth="3"
              strokeLinecap="round"
            >
              {tone === "defended" ? TICK : CROSS}
            </svg>
            <div>
              <dt className="text-[14.5px] font-medium text-text-primary">{adversary}</dt>
              <dd className="mt-1 text-[13.5px] leading-relaxed text-text-muted">
                {detail}
              </dd>
            </div>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function ThreatModel() {
  return (
    <Section id="threat-model" labelledBy="threat-model-heading" className="overflow-hidden">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 60% 40% at 20% 0%, rgb(59 130 246 / 0.10), transparent 70%)",
        }}
      />

      <Container className="relative">
        <Reveal>
          <Eyebrow>Threat model</Eyebrow>
        </Reveal>

        <Reveal delay={80}>
          <SectionHeading id="threat-model-heading" className="ink mt-5 max-w-[24ch]">
            What Sluice defends against, and what it does not.
          </SectionHeading>
        </Reveal>

        <Reveal delay={160}>
          <p className="mt-6 max-w-160 text-[17px] leading-relaxed text-text-muted">
            A zero-knowledge claim means nothing until you say who it holds
            against. Both lists are published in full in{" "}
            <a
              href={SECURITY_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={textLink}
            >
              SECURITY.md
            </a>
            . The second one is not a to-do list &mdash; it is the cost of the
            design.
          </p>
        </Reveal>

        <div className="mt-16 grid gap-4 lg:grid-cols-2">
          <Reveal>
            <Panel
              id="threat-defended"
              tone="defended"
              title="Defended against"
              note="Describes the architecture, not shipped software. Only the crypto core exists today."
              rows={DEFENDED}
            />
          </Reveal>
          <Reveal delay={80}>
            <Panel
              id="threat-not-defended"
              tone="open"
              title="Not defended against"
              note="Real limits, stated plainly. Not oversights, and not going away."
              rows={NOT_DEFENDED}
            />
          </Reveal>
        </div>

        <Reveal delay={80}>
          <p className="mt-8 max-w-180 text-[14.5px] leading-relaxed text-text-muted">
            The design has a standing cost too. Server-side secret scanning,
            server-side rotation of third-party credentials and push sync to
            other platforms cannot be built on a server that holds no key.
            Anything needing plaintext runs on the customer&apos;s own machine.
          </p>
        </Reveal>
      </Container>
    </Section>
  );
}
