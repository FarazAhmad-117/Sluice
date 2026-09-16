import { IMPLEMENTATION_PLAN_URL } from "@/components/landing/links";
import {
  Container,
  Eyebrow,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";

/**
 * How revocation differs, from Implementation_Plan.md section 4.
 *
 * Layout family: a three-row ledger. Each row is a grid from `md` up and a
 * stacked block below it, with the column names repeated as small mono labels
 * on mobile. A real `<table>` would be semantically neater and would need a
 * horizontal scrollbar at 375px to hold three columns of prose, which is the
 * trade this makes deliberately.
 *
 * Eyebrow 1 of 2 on the page.
 */

const EVENTS = [
  {
    event: "Value rotation",
    meaning: "A secret's value changed.",
    behaviour:
      "Push the new value, fire onChange, let the app hot-swap it. No crash.",
  },
  {
    event: "Token revocation",
    meaning: "This machine identity is no longer trusted.",
    behaviour:
      "Verify the signature, drain for five seconds, then exit with status 1.",
  },
  {
    event: "Epoch bump",
    meaning: "The project data key was re-keyed, usually a member leaving.",
    behaviour: "Re-fetch the bundle with the new wrapped key. No crash.",
  },
];

const COLUMNS = ["Event", "Meaning", "Default behaviour"];

export function Revocation() {
  return (
    <section
      id="revocation"
      className="scroll-mt-28 border-b border-hairline"
      aria-labelledby="revocation-heading"
    >
      <Container className="py-20 sm:py-24">
        <Eyebrow>Kill switch</Eyebrow>

        <SectionHeading id="revocation-heading" className="mt-4 max-w-[20ch]">
          Rotating a value is not revoking a token
        </SectionHeading>

        <p className="mt-6 max-w-[62ch] text-base leading-relaxed text-text-muted sm:text-lg">
          Doppler, Infisical, 1Password, HashiCorp Vault and EnvKey all store
          secrets. Storage is not the differentiator. A value changing and an
          identity being withdrawn arrive down the same channel, and they are
          not the same event. If rotating a value can take an app down, nobody
          rotates anything, and the premise collapses. Sluice keeps them apart
          by design. What follows is the specified behaviour, not a description
          of shipped software.
        </p>

        <div className="mt-12 border-t border-hairline">
          <div
            aria-hidden="true"
            className="hidden gap-8 border-b border-hairline px-1 py-3 md:grid md:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)_minmax(0,1.5fr)]"
          >
            {COLUMNS.map((column) => (
              <p
                key={column}
                className="font-mono text-xs tracking-[0.14em] text-text-muted uppercase"
              >
                {column}
              </p>
            ))}
          </div>

          <dl className="divide-y divide-hairline">
            {EVENTS.map((row) => (
              <div
                key={row.event}
                className="grid gap-3 px-1 py-6 md:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)_minmax(0,1.5fr)] md:items-baseline md:gap-8"
              >
                <dt className="font-mono text-base font-medium text-text-primary">
                  {row.event}
                </dt>
                <dd className="text-base leading-relaxed text-text-muted">
                  <span className="mb-1 block font-mono text-xs tracking-[0.14em] uppercase md:hidden">
                    {COLUMNS[1]}
                  </span>
                  {row.meaning}
                </dd>
                <dd className="text-base leading-relaxed text-text-primary">
                  <span className="mt-3 mb-1 block font-mono text-xs tracking-[0.14em] text-text-muted uppercase md:mt-0 md:hidden">
                    {COLUMNS[2]}
                  </span>
                  {row.behaviour}
                </dd>
              </div>
            ))}
          </dl>
        </div>

        <p className="mt-12 max-w-[62ch] text-base leading-relaxed text-text-muted sm:text-lg">
          Losing the connection is a fourth thing, and it is not revocation. A
          dropped socket keeps the last known good values, reconnects with
          backoff and alarms. Only a revocation notice carrying
          a valid signature from a customer-held key starts a shutdown, which
          is what stops the operator of Sluice, a platform compromise or a
          network attacker from killing a fleet. Section 4 of the{" "}
          <a
            href={IMPLEMENTATION_PLAN_URL}
            target="_blank"
            rel="noreferrer noopener"
            className={textLink}
          >
            implementation plan
          </a>{" "}
          has the full behaviour.
        </p>

        {/*
          SLOT: terminal recording of a signed revocation.

          Deliberately empty. There is no SDK and no delivery path, so there is
          nothing to record, and the design doc bans building a fake product
          screenshot out of divs. When an SDK exists, drop an asciinema player
          or a video in here and delete the caption.
        */}
        <figure className="mt-12">
          <div className="flex min-h-[13rem] items-center justify-center rounded-card border border-dashed border-hairline px-6 py-10">
            <p className="font-mono text-xs tracking-[0.18em] text-text-muted uppercase">
              Terminal recording slot
            </p>
          </div>
          <figcaption className="mt-4 max-w-[62ch] text-base leading-relaxed text-text-muted">
            A recording of a real revocation goes here once there is an SDK to
            record. Until then this box stays empty on purpose: a simulated
            demo of software that does not exist would undo everything the rest
            of this page is trying to establish.
          </figcaption>
        </figure>
      </Container>
    </section>
  );
}
