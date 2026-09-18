import type { CSSProperties, ReactNode } from "react";
import { IMPLEMENTATION_PLAN_URL } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { ScrollTrack } from "@/components/landing/scroll-track";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";

/**
 * How revocation differs, from Implementation_Plan.md section 4.
 *
 * Layout family: a three-card bento over a wide timeline card. The previous
 * version was a three-column ledger, and a ledger was the wrong shape for this
 * content: the three events are not three rows of one table, they are three
 * DIFFERENT behaviours, and one of them -- `token.revocation` -- is the entire
 * product. A table gives all three rows equal weight by construction. Cards let
 * the middle one be lit and the other two be context, which is the actual
 * hierarchy.
 *
 * The timeline underneath is the one place on the page that states the five
 * second drain, and it is labelled as specified behaviour rather than measured,
 * because there is no SDK yet to measure.
 *
 * Eyebrow 1 of 2 on the page.
 */

const EVENTS = [
  {
    event: "value.rotation",
    meaning: "A secret's value changed.",
    behaviour: "Push the new value, fire onChange, let the app hot-swap it. No crash.",
    lit: false,
    icon: (
      <path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5" />
    ),
  },
  {
    event: "token.revocation",
    meaning: "This machine identity is no longer trusted.",
    behaviour:
      "Verify the signature, drain for five seconds, then exit with status 1.",
    lit: true,
    icon: <path d="M12 2v10M18.4 6.6a9 9 0 1 1-12.8 0" />,
  },
  {
    event: "epoch.bump",
    meaning: "The project data key was re-keyed, usually a member leaving.",
    behaviour: "Re-fetch the bundle with the new wrapped key. No crash.",
    lit: false,
    icon: (
      <>
        <rect x="4" y="10" width="16" height="11" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3" />
      </>
    ),
  },
] as const;

/**
 * The four steps, and where each one sits along the line.
 *
 * `at` is the fraction of the track's length the dot stands at, and it is what
 * the CSS compares `--p` against to decide when that dot lights. It is declared
 * here rather than derived from the index because the first dot must be lit the
 * instant the line starts -- a track that begins with four dark dots reads as
 * broken until the reader scrolls further.
 */
const STEPS = [
  { at: 0, label: "t = 0", what: "Admin signs the notice with a customer-held key" },
  { at: 0.33, label: "t + ms", what: "Delivered to every live process" },
  { at: 0.66, label: "verify", what: "Signature checked locally, against the org key" },
  { at: 1, label: "t + 5s", what: "Drain, then exit(1)" },
] as const;

function EventIcon({ children, lit }: { children: ReactNode; lit: boolean }) {
  return (
    <div
      className={`mb-6 grid size-10 place-items-center rounded-[11px] border bg-white/3 ${
        lit ? "border-status-danger/35" : "border-hairline-strong"
      }`}
    >
      <svg
        aria-hidden="true"
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke={lit ? "var(--status-danger)" : "#9cc3ff"}
        strokeWidth="2"
        strokeLinecap="round"
      >
        {children}
      </svg>
    </div>
  );
}

export function Revocation() {
  return (
    <Section id="revocation" labelledBy="revocation-heading">
      <Container>
        <Reveal>
          <Eyebrow>Kill switch</Eyebrow>
        </Reveal>

        <Reveal delay={80}>
          <SectionHeading id="revocation-heading" className="ink mt-5 max-w-[20ch]">
            Rotating a value is not revoking a token.
          </SectionHeading>
        </Reveal>

        <Reveal delay={160}>
          <p className="mt-6 max-w-160 text-[17px] leading-relaxed text-text-muted">
            Doppler, Infisical, 1Password, Vault and EnvKey all store secrets.
            Storage is not the differentiator. A value changing and an identity
            being withdrawn arrive down the same channel elsewhere &mdash; and if
            rotating can take an app down, nobody rotates. Sluice keeps them
            apart by design. What follows is specified behaviour, not a
            description of shipped software.
          </p>
        </Reveal>

        <div className="mt-16 grid gap-4 lg:grid-cols-3">
          {EVENTS.map((row, index) => (
            <Reveal
              key={row.event}
              delay={index * 80}
              className={`panel p-7 ${
                row.lit
                  ? "!border-brand/35 !bg-gradient-to-b !from-brand/[0.09] !to-brand/[0.01]"
                  : ""
              }`}
            >
              {row.lit ? (
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute -top-20 -right-20 size-52 rounded-full"
                  style={{
                    background:
                      "radial-gradient(circle, rgb(59 130 246 / 0.35), transparent 70%)",
                  }}
                />
              ) : null}

              <div className="relative">
                <EventIcon lit={row.lit}>{row.icon}</EventIcon>
                <h3 className="font-mono text-[15px] font-medium tracking-[-0.01em] text-text-primary">
                  {row.event}
                </h3>
                <p className="mt-2 min-h-[46px] text-[14.5px] text-text-muted">
                  {row.meaning}
                </p>
                <div className="mt-6 border-t border-dashed border-hairline-strong pt-4">
                  <p className="font-mono text-[11px] tracking-[0.12em] text-text-faint uppercase">
                    Default behaviour
                  </p>
                  <p className="mt-2 text-[14px] leading-relaxed text-text-body">
                    {row.behaviour}
                  </p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={120} className="panel mt-4 grid gap-10 p-8 lg:grid-cols-[1fr_1.6fr] lg:items-center">
          <p className="text-[15px] leading-relaxed text-text-muted">
            <strong className="font-medium text-text-primary">
              Losing the connection is a fourth thing, and it is not revocation.
            </strong>{" "}
            A dropped socket keeps the last known good values and reconnects with
            backoff. Only a notice carrying a valid signature from a
            customer-held key starts a shutdown &mdash; so the operator, a
            platform compromise or a network attacker cannot kill a fleet. Full
            spec in{" "}
            <a
              href={IMPLEMENTATION_PLAN_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={textLink}
            >
              section 4 of the plan
            </a>
            .
          </p>

          {/*
            The rail draws itself as the reader scrolls the section past, and
            each dot lights as the line reaches it. It is decorative -- the four
            steps below it carry the meaning in text -- so the rail itself is
            hidden from assistive technology and only the list is announced.
          */}
          <ScrollTrack>
            <ol className="relative grid grid-cols-2 gap-y-7 sm:grid-cols-4">
              <div
                aria-hidden="true"
                className="absolute top-1.5 right-1.5 left-1.5 hidden h-px bg-hairline-strong sm:block"
              />
              <div
                aria-hidden="true"
                className="track-line absolute top-1.5 left-1.5 hidden h-px sm:block"
                style={{ maxWidth: "calc(100% - 0.75rem)" }}
              />

              {STEPS.map((step, index) => {
                const last = index === STEPS.length - 1;
                return (
                  <li key={step.label} className="relative pr-3">
                    <span className="relative z-10 block size-3.5">
                      {/* Base ring, always present, so an unlit dot is still a
                          dot rather than a gap in the line. */}
                      <span
                        aria-hidden="true"
                        className="absolute inset-0 rounded-full border border-hairline-strong bg-surface-base"
                      />
                      {/* Lit ring. Its opacity is pure CSS arithmetic against
                          `--p`, so lighting up costs no JavaScript per dot. The
                          last one lands red: the sequence ends in exit(1), and
                          a green dot there would be the animation contradicting
                          the label underneath it. */}
                      <span
                        aria-hidden="true"
                        className={`track-dot-lit absolute inset-0 rounded-full border-2 ${
                          last
                            ? "border-status-danger bg-status-danger/20"
                            : "border-status-healthy bg-status-healthy/20"
                        }`}
                        style={
                          {
                            "--at": step.at,
                            boxShadow: `0 0 10px var(--status-${last ? "danger" : "healthy"})`,
                          } as CSSProperties
                        }
                      />
                    </span>
                    <p className="mt-3.5 font-mono text-[11px] text-text-faint">
                      {step.label}
                    </p>
                    <p className="mt-1 text-[13.5px] leading-snug text-text-body">
                      {step.what}
                    </p>
                  </li>
                );
              })}
            </ol>
          </ScrollTrack>
        </Reveal>

        {/*
          SLOT: terminal recording of a signed revocation.

          Deliberately empty. There is no SDK and no delivery path, so there is
          nothing to record, and the design doc bans building a fake product
          screenshot out of divs. When an SDK exists, drop an asciinema player
          in here and delete the caption.
        */}
        <Reveal delay={80} as="figure" className="mt-16">
          <div className="flex min-h-[14rem] items-center justify-center rounded-card border border-dashed border-hairline bg-surface-deep px-6 py-12">
            <p className="font-mono text-xs tracking-[0.18em] text-text-faint uppercase">
              Terminal recording slot
            </p>
          </div>
          <figcaption className="mt-4 max-w-[62ch] text-[14.5px] leading-relaxed text-text-muted">
            A recording of a real revocation goes here once there is an SDK to
            record. Until then this box stays empty on purpose: a simulated demo
            of software that does not exist would undo everything the rest of
            this page is trying to establish.
          </figcaption>
        </Reveal>
      </Container>
    </Section>
  );
}
