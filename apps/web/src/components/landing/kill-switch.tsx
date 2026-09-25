import type { CSSProperties, ReactNode } from "react";

import { FleetGlobe } from "@/components/landing/fleet-globe";
import { Reveal } from "@/components/landing/motion";
import { ScrollTrack } from "@/components/landing/scroll-track";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
} from "@/components/landing/primitives";

/**
 * THE WEDGE, AND THE DEMONSTRATION OF IT.
 *
 * The shape is the one Arcjet uses and it is the only one that survives being
 * read by someone who already uses Doppler: concede the incumbent's strength in
 * the first sentence, then name the thing it cannot do. A section that opens by
 * claiming to be better at storage loses, because it is not, and the reader
 * knows it before the paragraph ends.
 *
 * THE DEMONSTRATION IS REAL AND IS THE POINT OF THE SECTION. Every incumbent
 * fakes its demo, because a dashboard cannot be run live in a marketing page.
 * Sluice's differentiator is the one thing in this category that genuinely can:
 * `FleetGlobe` generates two Ed25519 keypairs in the reader's tab, signs a real
 * `RevocationNotice` with each, and runs both through the same
 * `verifyRevocation` the SDK calls. The verdict on screen is that function's
 * return value and never a literal. `test/hero-revocation.test.ts` pins that,
 * so nobody can simplify the demo into an assertion of its own conclusion.
 *
 * WHAT IT DOES NOT CLAIM, stated on the widget itself: the processes are
 * simulated. The cryptography is real and the fleet is not, and that line sits
 * under the globe rather than in a footnote, because the exact claim a sceptical
 * reader pokes first is this one.
 *
 * THE MOTION IS SLOWER THAN THE MEASUREMENT, DELIBERATELY. Signing and
 * verifying land under a couple of milliseconds, below the threshold at which
 * an eye reads an event as an event; at true speed it looks like the page
 * glitched rather than like the product is fast. The readout carries the truth
 * and the motion carries the legibility, and that stays honest only while the
 * printed figure is the measured one. It is.
 *
 * NO CALL TO ACTION HERE. The reader is mid-argument.
 */

const EVENTS = [
  {
    event: "value.rotation",
    meaning: "A secret's value changed.",
    behaviour:
      "Fetch the new bundle, log which keys moved, and leave the child running. A process's environment cannot be changed from outside it, so the child keeps the values it started with until you restart it.",
    lit: false,
    icon: <path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5" />,
  },
  {
    event: "token.revocation",
    meaning: "This machine identity is no longer trusted.",
    behaviour:
      "Verify the signature against the org key you configured, drain for five seconds, then exit with status 1.",
    lit: true,
    icon: <path d="M12 2v10M18.4 6.6a9 9 0 1 1-12.8 0" />,
  },
  {
    event: "connection.lost",
    meaning: "The socket dropped, or the server went away.",
    behaviour:
      "Keep the last known good values and reconnect with backoff. Losing the connection never kills a process, and that property is enumerated over 599,184 event sequences rather than sampled.",
    lit: false,
    icon: (
      <>
        <path d="M2 12h4M18 12h4" />
        <path d="M9 9l6 6M15 9l-6 6" />
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
 * instant the line starts: a track that begins with four dark dots reads as
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
        stroke={lit ? "var(--status-danger)" : "var(--brand-hover)"}
        strokeWidth="2"
        strokeLinecap="round"
      >
        {children}
      </svg>
    </div>
  );
}

export function KillSwitch() {
  return (
    /*
      `overflow-hidden` IS LOAD-BEARING. `FleetGlobe` paints its light as an
      absolutely positioned wash wider than itself, and it used to live in the
      hero, whose <header> clipped it. Here it sits inside a Section, and without
      this the glow escapes the right edge and the whole document scrolls
      sideways on a phone. Measured at 375px, not assumed.
    */
    <Section
      id="kill-switch"
      labelledBy="kill-switch-heading"
      className="overflow-hidden"
    >
      <Container>
        <div className="grid items-center gap-14 lg:grid-cols-[0.95fr_1.05fr] lg:gap-12">
          <div>
            <Reveal>
              <Eyebrow>The kill switch</Eyebrow>
            </Reveal>

            <Reveal delay={80}>
              <SectionHeading
                id="kill-switch-heading"
                className="ink mt-5 max-w-[20ch]"
              >
                Everyone can stop issuing a secret. Nobody can take one back.
              </SectionHeading>
            </Reveal>

            <Reveal delay={160}>
              <p className="mt-6 max-w-150 text-[17px] leading-relaxed text-text-muted">
                Doppler, Infisical, 1Password, Vault and EnvKey all store
                secrets well, and Sluice is not going to out-store them. The gap
                is somewhere else. Withdrawing a credential stops the next
                fetch; it does not reach a process that pulled the value an hour
                ago and is still running. Reaching that process means waiting
                for a restart, and a restart is a deploy, and a deploy is twenty
                minutes you do not have at the moment you need it.
              </p>
            </Reveal>

            <Reveal delay={200}>
              <p className="mt-5 max-w-150 text-[16px] leading-relaxed text-text-body">
                Sluice keeps a signed channel open to every process holding a
                token. An admin signs a revocation notice with a key the server
                has never held. Each process verifies it locally and shuts
                itself down. The server cannot forge that notice, so it cannot
                kill your fleet either. Press the buttons and watch both cases:
                the keys are generated in your tab and the signatures are real
                Ed25519. The three processes are simulated, and the widget says
                so under itself.
              </p>
            </Reveal>
          </div>

          <Reveal delay={120}>
            <FleetGlobe />
          </Reveal>
        </div>

        <div className="mt-20 grid gap-4 lg:grid-cols-3">
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
                      "radial-gradient(circle, var(--glow-brand), transparent 70%)",
                  }}
                />
              ) : null}

              <div className="relative">
                <EventIcon lit={row.lit}>{row.icon}</EventIcon>
                <h3 className="font-mono text-[15px] font-medium tracking-[-0.01em] text-text-primary">
                  {row.event}
                </h3>
                <p className="mt-2 min-h-[46px] text-[16px] text-text-muted">
                  {row.meaning}
                </p>
                <div className="mt-6 border-t border-dashed border-hairline-strong pt-4">
                  <p className="font-mono text-[11px] tracking-[0.12em] text-text-faint uppercase">
                    What the CLI does
                  </p>
                  <p className="mt-2 text-[16px] leading-relaxed text-text-body">
                    {row.behaviour}
                  </p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal
          delay={120}
          className="panel mt-4 grid gap-10 p-8 lg:grid-cols-[1fr_1.6fr] lg:items-center"
        >
          <p className="text-[16px] leading-relaxed text-text-muted">
            <strong className="font-medium text-text-primary">
              Only a valid signature starts a shutdown.
            </strong>{" "}
            Not a dropped socket, not a server instruction, not a network
            attacker. That is what keeps an instant kill switch from being an
            instant outage switch, and it is why the operator of Sluice cannot
            take your fleet down.
          </p>

          {/*
            The rail draws itself as the reader scrolls the section past, and
            each dot lights as the line reaches it. It is decorative: the four
            steps below it carry the meaning in text, so the rail itself is
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
      </Container>
    </Section>
  );
}
