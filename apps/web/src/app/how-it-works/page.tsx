import type { Metadata } from "next";
import Link from "next/link";

import { ALL_LIMITS } from "@/components/landing/limits";
import {
  IMPLEMENTATION_PLAN_URL,
  ROUTES,
} from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { IllustrationSlot, PageHeader } from "@/components/landing/page-header";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";
import { Quickstart } from "@/components/landing/quickstart";
import { SiteFooter } from "@/components/landing/site-footer";
import { SiteHeader } from "@/components/landing/site-header";

/**
 * THE MECHANISM PAGE.
 *
 * ITS READER has already accepted the hook and now wants the crypto claim to
 * survive detail. Its one job is to make "zero-knowledge" and "signature-gated
 * revocation" CHECKABLE rather than asserted, which means naming primitives,
 * naming the files they live in, and being specific about the one thing a
 * marketing page would leave vague: what the server actually receives.
 *
 * A vague word here would cost more than it saves. "Military-grade encryption"
 * is what a product writes when it does not want its choices examined, and the
 * reader this page is for knows that.
 *
 * THE LIMITS ARE NOT REPEATED IN FULL HERE. Two of them are, because they are
 * properties of the mechanism this page describes and leaving them out would
 * make the description wrong: rotation does not reach a running child, and
 * revocation does not undo decryption. Both are quoted from `limits.ts`
 * verbatim, and `/security` carries the rest.
 */

export const metadata: Metadata = {
  title: "How Sluice works",
  description:
    "The key hierarchy, the token split, and what a signed revocation notice actually does. Argon2id, AES-256-GCM, HKDF and Ed25519, named so you can check them.",
};

/**
 * The two limits that are properties of the mechanism described on this page.
 *
 * Looked up by id rather than spelled out, so this page and `/security` cannot
 * drift into two different phrasings of the same fact. If an id here stops
 * matching, the array is empty and the box is visibly wrong, which is the
 * failure mode worth having.
 */
const NAMED_HERE = ALL_LIMITS.filter(
  (limit) => limit.id === "no-rekey" || limit.id === "rotation-needs-restart",
);

const SERVER_HOLDS = [
  ["Public keys", "Both of them, per member. Nothing openable."],
  ["Wrapped key blobs", "Sealed under a key derived from a password it never sees."],
  ["Ciphertext", "AES-256-GCM, with the environment id bound into the associated data."],
] as const;

const SERVER_NEVER_HOLDS = [
  ["The master unlock key", "Derived from your password with Argon2id, on your device."],
  ["Any unwrapped private key", "It exists in memory on your machine and nowhere else."],
  ["The unwrap half of a service token", "It never leaves the process that holds the token."],
] as const;

export default function HowItWorks() {
  return (
    <>
      <SiteHeader />
      <main>
        <PageHeader eyebrow="How it works" title="Two keys, and a server that holds neither.">
          <p>
            Sluice is a delivery mechanism, not a vault the operator can open.
            Everything below names the primitive it uses and the file it lives
            in, so that a claim on this page is something you can go and check
            rather than something you have to take. The full protocol is{" "}
            <a
              href={IMPLEMENTATION_PLAN_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={textLink}
            >
              section 2 of the implementation plan
            </a>
            .
          </p>
        </PageHeader>

        {/*
          ==================================================================
          GRAPHICS SLOT 2 OF 3: TWO KEYS MEET IN THE MIDDLE
          ==================================================================
          Owner-designed illustration. Do not fill this with hand-rolled SVG.

          Target size   1200 x 640, landscape, transparent background, and
                        legible when it is 343px wide on a phone. If it cannot
                        survive that, it needs a stacked variant.
          Placement     first section of /how-it-works, full container width.

          It must communicate one idea: two independent trust roots meeting at
          a boundary the server cannot cross.

            - A HUMAN PATH: a person, through a password, to a lock.
            - A MACHINE PATH: a service token splitting into two labelled
              halves, "auth" and "unwrap".
            - Both converge on ONE wrapped blob.
            - A box drawn around the server, and it touches only the outer
              CLOSED shapes. It must never overlap an open one. That containment
              is the whole claim; if the box and an open shape intersect
              anywhere, the picture is saying the opposite of the text.

          Palette: tokens only.
        */}
        <Section id="key-hierarchy" labelledBy="key-hierarchy-heading">
          <Container>
            <Reveal>
              <IllustrationSlot name="two keys meet in the middle" width={1200} height={640} />
            </Reveal>

            <div className="mt-16 grid gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:gap-16">
              <div>
                <Reveal>
                  <Eyebrow>The key hierarchy</Eyebrow>
                </Reveal>
                <Reveal delay={80}>
                  <SectionHeading id="key-hierarchy-heading" className="ink mt-5">
                    Your password is the root.
                  </SectionHeading>
                </Reveal>
                <Reveal delay={160}>
                  <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
                    Argon2id turns your password into a master unlock key on
                    your own device. That key unwraps your private keys, which
                    unwrap a per-environment data key, which decrypts the
                    secrets. Every link in that chain is computed where you are.
                  </p>
                </Reveal>
                <Reveal delay={200}>
                  <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
                    The salt is derived from a public user id, so the password
                    is the only entropy in the key. A weak password is a weak
                    root, and nothing in the design rescues one.
                  </p>
                </Reveal>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <Reveal className="panel p-6">
                  <h3 className="text-[15px] font-semibold text-text-primary">
                    What the server receives
                  </h3>
                  <dl className="mt-5 space-y-4">
                    {SERVER_HOLDS.map(([name, detail]) => (
                      <div key={name}>
                        <dt className="text-[15px] font-medium text-text-body">{name}</dt>
                        <dd className="mt-1 text-[16px] leading-relaxed text-text-muted">
                          {detail}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </Reveal>
                <Reveal delay={80} className="panel p-6">
                  <h3 className="text-[15px] font-semibold text-text-primary">
                    What it never receives
                  </h3>
                  <dl className="mt-5 space-y-4">
                    {SERVER_NEVER_HOLDS.map(([name, detail]) => (
                      <div key={name}>
                        <dt className="text-[15px] font-medium text-text-body">{name}</dt>
                        <dd className="mt-1 text-[16px] leading-relaxed text-text-muted">
                          {detail}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </Reveal>
              </div>
            </div>
          </Container>
        </Section>

        <Section id="token-split" labelledBy="token-split-heading" divided>
          <Container className="grid gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:gap-16">
            <div>
              <Reveal>
                <Eyebrow>The service token</Eyebrow>
              </Reveal>
              <Reveal delay={80}>
                <SectionHeading id="token-split-heading" className="ink mt-5">
                  One token, two halves, and only one of them travels.
                </SectionHeading>
              </Reveal>
            </div>

            <div>
              <Reveal>
                <p className="text-[17px] leading-relaxed text-text-muted">
                  A token looks like{" "}
                  <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] break-all text-text-primary">
                    slc_&lt;environment&gt;_&lt;id&gt;.&lt;secret&gt;
                  </code>
                  . HKDF-SHA256 expands the secret half into two 32-byte keys
                  under different info strings, which is the only thing
                  separating them and is enough: HKDF-Expand runs HMAC-SHA256
                  over distinct inputs, so neither output reveals the other.
                </p>
              </Reveal>
              <Reveal delay={80}>
                <div className="mt-8 grid gap-4 sm:grid-cols-2">
                  <div className="panel p-6">
                    <p className="font-mono text-[13px] text-text-faint">authSeed</p>
                    <p className="mt-3 text-[16px] leading-relaxed text-text-body">
                      Proves to the server that this token is who it says it is.
                      This half goes over the wire, through a handshake endpoint
                      with replay protection.
                    </p>
                  </div>
                  <div className="panel p-6">
                    <p className="font-mono text-[13px] text-text-faint">unwrapKey</p>
                    <p className="mt-3 text-[16px] leading-relaxed text-text-body">
                      Opens the wrapped data key for that one environment. It
                      never leaves the process. A server that had it could
                      recompute the environment&apos;s plaintext, which is why
                      it is derived rather than issued.
                    </p>
                  </div>
                </div>
              </Reveal>
              <Reveal delay={120}>
                <p className="mt-6 text-[16px] leading-relaxed text-text-muted">
                  The bundle then arrives over a reactive subscription rather
                  than a poll, which is what lets a revocation reach a running
                  process in the time it takes to deliver a message rather than
                  in the time it takes for the next interval to come round.
                </p>
              </Reveal>
            </div>
          </Container>
        </Section>

        <Section id="revocation" labelledBy="revocation-heading" divided>
          <Container className="grid gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:gap-16">
            <div>
              <Reveal>
                <Eyebrow>Revocation</Eyebrow>
              </Reveal>
              <Reveal delay={80}>
                <SectionHeading id="revocation-heading" className="ink mt-5">
                  The server delivers the notice. It cannot write one.
                </SectionHeading>
              </Reveal>
              <Reveal delay={160}>
                <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
                  An admin signs a revocation notice with an Ed25519 key held by
                  the organisation. You configure the matching public key
                  yourself, in{" "}
                  <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.85em] break-all text-text-primary">
                    SLUICE_ORG_REVOCATION_PUBLIC_KEY
                  </code>
                  , and Sluice never fetches it for you. A server that could
                  supply that key could sign its own notices and kill every
                  process you run.
                </p>
              </Reveal>
            </div>

            <div>
              <Reveal>
                <ol className="panel divide-y divide-hairline">
                  {[
                    [
                      "The notice is verified locally",
                      "Against the public key in your environment, not against anything the server sent. A forged notice fails here and changes nothing.",
                    ],
                    [
                      "The epoch floor moves",
                      "Persisted to disk, so a replay of an old notice after a restart is refused. Ed25519 signatures are deterministic, so anyone who ever saw a genuine notice could otherwise replay it forever.",
                    ],
                    [
                      "The process drains for five seconds",
                      "Default, and configurable up to sixty. In-flight work finishes; nothing new starts.",
                    ],
                    [
                      "It exits with status 1",
                      "Your supervisor sees a failure, which is what you want, because the process was told to stop being trusted.",
                    ],
                  ].map(([title, detail], index) => (
                    <li key={title} className="grid grid-cols-[2rem_1fr] gap-4 p-6">
                      <span
                        aria-hidden="true"
                        className="font-mono text-[13px] text-text-faint"
                      >
                        {`0${index + 1}`}
                      </span>
                      <div>
                        <p className="text-[15.5px] font-medium text-text-primary">{title}</p>
                        <p className="mt-1.5 text-[16px] leading-relaxed text-text-muted">
                          {detail}
                        </p>
                      </div>
                    </li>
                  ))}
                </ol>
              </Reveal>

              <Reveal delay={80}>
                <div className="mt-4 rounded-card border border-status-warning/20 bg-status-warning/4 px-6 py-5">
                  <p className="text-[15.5px] font-medium text-text-primary">
                    Two things revocation does not do
                  </p>
                  {/* Rendered from `limits.ts` rather than retyped. The rule is
                      that a limitation named on /security appears unchanged
                      everywhere else, and the only way that survives an edit is
                      for there to be one copy of the sentence. */}
                  {NAMED_HERE.map((limit) => (
                    <p
                      key={limit.id}
                      className="mt-3 text-[16px] leading-relaxed text-text-body"
                    >
                      {limit.body}
                    </p>
                  ))}
                  <p className="mt-4 text-[16px] leading-relaxed text-text-muted">
                    Both of these are in{" "}
                    <Link href={ROUTES.security} className={textLink}>
                      the threat model
                    </Link>
                    , in the same words.
                  </p>
                </div>
              </Reveal>
            </div>
          </Container>
        </Section>

        <Quickstart />
      </main>
      <SiteFooter />
    </>
  );
}
