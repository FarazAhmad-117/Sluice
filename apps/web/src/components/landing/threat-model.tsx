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
 * The threat model, close to verbatim from `SECURITY.md`.
 *
 * Both lists, side by side, symmetric. The second column is not softened and is
 * not shorter than it is in the file. A zero-knowledge claim with no named
 * adversary is marketing, and a security reader who cannot find the limits
 * assumes they were hidden rather than absent.
 *
 * The two panels are deliberately identical in construction: same padding, same
 * row rhythm, same header shape, differing only in the tick or cross and the
 * colour of it. Any asymmetry here would be read as an argument, and the
 * argument this section makes is that both lists are equally real.
 *
 * WHAT IS DELIBERATELY NOT IN THE RIGHT-HAND PANEL. Account enumeration, which
 * `SECURITY.md` lists here, is on this page in the limitations section instead,
 * because it is a consequence of a signup flow that has no email delivery
 * behind it yet rather than a property of the design. Stating it in both places
 * would put two phrasings of the same fact on one page, which is the exact
 * failure this site's honesty rules exist to prevent.
 */

const DEFENDED = [
  ["A database dump or backup theft", "Ciphertext only. No key material in the database."],
  [
    "A malicious or legally compelled operator, including the maintainer",
    "No decryption key ever reaches the server.",
  ],
  ["A compromise of the Convex platform", "The same answer. There is no key there to take."],
  ["A network attacker with TLS stripped", "Payloads are already encrypted end to end."],
  ["A stolen service token", "Instantly revocable, and scoped to one environment."],
  [
    "A malicious server pushing fake revocations",
    "Revocation notices are signed by customer-held keys.",
  ],
  [
    "An insider at a customer organisation",
    "Role-based access control, an audit log, and per-environment key separation.",
  ],
] as const;

const NOT_DEFENDED = [
  [
    "A compromised client device",
    "If an admin's laptop is owned, their keys are owned. Sluice cannot tell the difference between the admin and malware running as the admin.",
  ],
  [
    "Malicious JavaScript served to the web dashboard",
    "This is the unsolved problem of browser-based end-to-end encryption. A compromised server can serve a dashboard build that exfiltrates the master unlock key. Strict CSP, subresource integrity, reproducible builds and a code transparency log reduce the window and make tampering detectable after the fact. They do not eliminate the attack. The planned answer is to make the CLI the trust anchor, and to document that security-critical operations belong there rather than in a browser.",
  ],
  [
    "A workload that has already decrypted a value",
    "Once a process decrypts a secret, that process can leak it, log it, or send it anywhere. Sluice controls delivery, not use.",
  ],
  [
    "A customer choosing a weak password",
    "The key hierarchy is rooted in a password-derived key, so a weak password is a weak root. Nothing enforces a minimum today. A strength gate and SSO-backed key wrapping are both planned, and neither saves a password that is guessable: the salt is derived from a public user id, so the password is the only entropy in the key.",
  ],
  [
    "A measured timing difference on login",
    "A login for a known address is consistently 0.08 to 0.15 ms slower than one for an unknown address, about 5 to 8 percent, because the known path materialises a user document while the unknown path resolves an empty index range. The error payload is byte identical in both cases. It sits far below network jitter, so it is not extractable from a single sample, and it is extractable with enough of them. Measured rather than assumed.",
  ],
] as const;

const TICK = <path d="M5 12l5 5 9-10" />;
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
              <dt className="text-[16px] font-medium text-text-primary">{adversary}</dt>
              <dd className="mt-1 text-[16px] leading-relaxed text-text-muted">{detail}</dd>
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
            , which is the source of truth for this page. The second list is not
            a roadmap. It is the cost of the design.
          </p>
        </Reveal>

        <div className="mt-14 grid gap-4 lg:grid-cols-2">
          <Reveal>
            <Panel
              id="threat-defended"
              tone="defended"
              title="Defended against"
              note="Describes the architecture as built. Nothing here has been reviewed by a third party."
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
          <p className="mt-8 max-w-180 text-[16px] leading-relaxed text-text-muted">
            The design has a standing cost too. Server-side secret scanning,
            server-side rotation of third-party credentials and push sync to
            other platforms cannot be built on a server that holds no key.
            Anything needing plaintext runs on your own machine.
          </p>
        </Reveal>
      </Container>
    </Section>
  );
}
