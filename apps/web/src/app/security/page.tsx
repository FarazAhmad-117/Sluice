import type { Metadata } from "next";

import { ALL_LIMITS } from "@/components/landing/limits";
import {
  IMPLEMENTATION_PLAN_URL,
  SECURITY_CONTACT,
  SECURITY_URL,
} from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { IllustrationSlot, PageHeader } from "@/components/landing/page-header";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  focusRing,
  textLink,
} from "@/components/landing/primitives";
import { SiteFooter } from "@/components/landing/site-footer";
import { SiteHeader } from "@/components/landing/site-header";
import { ThreatModel } from "@/components/landing/threat-model";

/**
 * THE SECURITY PAGE.
 *
 * ITS READER is the person who gates the decision and is actively looking for a
 * reason to say no. Its one job is to survive their read by being more rigorous
 * than the pitch, which means it is close to verbatim from `SECURITY.md`, whose
 * voice is already right: plain, specific, no false comfort.
 *
 * THIS PAGE HAS NO PRODUCT CALL TO ACTION. Not in the body, and not in the
 * navigation bar either, which is why `SiteHeader` is given `cta={false}`. Its
 * only action is reporting a vulnerability. That restraint is not decoration;
 * it is the argument. A page that lists the ways this software could hurt you
 * and then sells to you at the bottom has told you what the list was for.
 *
 * EVERY LIMITATION ON THIS PAGE COMES FROM `limits.ts` or from the threat model
 * table, and each one appears exactly once. Two phrasings of the same fact on
 * one page is worse than one blunt phrasing, because the reader now has to work
 * out which is the real one.
 */

export const metadata: Metadata = {
  title: "Sluice security and threat model",
  description:
    "Pre-release, not third-party audited. The full threat model, what the server can still see, every limitation, and where to report a vulnerability.",
};

const PLAINTEXT_ON_SERVER = [
  "Organisation names and slugs",
  "Project names and slugs",
  "Environment names, such as production",
  "Email addresses",
  "Which users belong to which organisation, and with what role",
  "Audit metadata: who acted, when, from which address, and on what",
  "The existence, count and modification times of secrets, though not their names or values",
] as const;

const REPORT_SHOULD_INCLUDE = [
  "What you think the impact is, and who it affects.",
  "The steps to reproduce, or a proof of concept.",
  "The commit SHA or version you tested.",
  "Whether you have disclosed this anywhere else, and any deadline you intend to hold the project to.",
] as const;

const COMMITMENTS = [
  [
    "Acknowledgement within 5 working days",
    "If you have not heard anything by then, send a follow up. It was missed, not ignored.",
  ],
  [
    "An assessment and a rough plan within 10 working days",
    "Counted from acknowledgement, with regular updates while a fix is in progress.",
  ],
  [
    "Credit, if you want it",
    "In the release notes and in the repository. Say so in your report, and say how you want to be named.",
  ],
  [
    "No bug bounty and no payment",
    "This is a solo project with no security team, no pager and no service level agreement. That may change after launch.",
  ],
] as const;

export default function SecurityPage() {
  return (
    <>
      {/* cta={false}. See the note at the top of this file. */}
      <SiteHeader cta={false} />
      <main>
        <PageHeader
          eyebrow="Security"
          title="Read this before you put anything real into Sluice."
        >
          <p>
            Sluice is a secrets product, so the honest description of its
            security posture matters more than the marketing. This page is close
            to verbatim from{" "}
            <a
              href={SECURITY_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={textLink}
            >
              SECURITY.md
            </a>
            , which is the source of truth. Where the two disagree, the file is
            right.
          </p>
        </PageHeader>

        <Section id="status" labelledBy="status-heading" className="!pt-4">
          <Container>
            <Reveal className="rounded-card border border-status-warning/25 bg-status-warning/4 px-7 py-7 sm:px-8">
              <h2
                id="status-heading"
                className="text-xl font-semibold tracking-[-0.02em] text-text-primary"
              >
                Project status: pre-release
              </h2>
              <ul className="mt-5 space-y-4 text-[16px] leading-relaxed text-text-body">
                <li>
                  Sluice is <b className="font-medium text-text-primary">pre-release</b>.
                  There is no stable release, no versioned API and no upgrade
                  path guarantee.
                </li>
                <li>
                  The cryptographic core has{" "}
                  <b className="font-medium text-text-primary">
                    not had a third-party review
                  </b>
                  . It is written against published primitives and covered by
                  tests, which is not the same thing as having been audited by
                  someone who does this for a living. An external crypto review
                  is planned and has not happened.
                </li>
                <li>
                  <b className="font-medium text-text-primary">
                    Do not store production secrets in Sluice yet.
                  </b>{" "}
                  Treat anything you put into it as recoverable by an attacker
                  who finds a flaw nobody has looked for yet.
                </li>
              </ul>
              <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
                This section will change when the review happens, and not
                before.
              </p>
            </Reveal>
          </Container>
        </Section>

        <ThreatModel />

        {/*
          ==================================================================
          GRAPHICS SLOT 3 OF 3: WHAT THE SERVER CAN SEE
          ==================================================================
          Owner-designed illustration. Do not fill this with hand-rolled SVG.

          Target size   1100 x 620, landscape, transparent background, and
                        legible at 343px wide on a phone. If it cannot survive
                        that, it needs a stacked variant.
          Placement     /security, directly above the plaintext list, full
                        container width.

          Two columns, same shapes in both, and that sameness is the whole
          device:

            LEFT, what it stores: OPEN shapes, readable, labelled as org names,
            project slugs, environment names, timestamps and counts.
            RIGHT, what it never has: THE SAME SHAPES as sealed opaque blocks.

          It must be precise enough that a reader can audit the picture against
          the list underneath it, item for item. If the drawing shows a shape
          the list does not name, or omits one it does, the picture is the
          claim that is wrong.

          Palette: tokens only. No padlock cliche.
        */}
        <Section id="what-the-server-sees" labelledBy="what-the-server-sees-heading" divided>
          <Container>
            <Reveal>
              <Eyebrow>Metadata</Eyebrow>
            </Reveal>
            <Reveal delay={80}>
              <SectionHeading
                id="what-the-server-sees-heading"
                className="ink mt-5 max-w-[24ch]"
              >
                What the server can see, stated plainly.
              </SectionHeading>
            </Reveal>
            <Reveal delay={160}>
              <p className="mt-6 max-w-160 text-[17px] leading-relaxed text-text-muted">
                The zero-knowledge claim is about secret names and secret
                values. It is not a claim that the operator can see nothing. The
                following are plaintext in the database, by design, because the
                server has to route, authorise and index on them.
              </p>
            </Reveal>

            <Reveal delay={200} className="mt-12">
              <IllustrationSlot name="what the server can see" width={1100} height={620} />
            </Reveal>

            <div className="mt-12 grid gap-10 lg:grid-cols-[1fr_1fr] lg:gap-16">
              <Reveal>
                <ul className="panel divide-y divide-hairline">
                  {PLAINTEXT_ON_SERVER.map((item) => (
                    <li key={item} className="px-6 py-4 text-[16px] leading-relaxed text-text-body">
                      {item}
                    </li>
                  ))}
                </ul>
              </Reveal>
              <Reveal delay={80}>
                <p className="text-[16px] leading-relaxed text-text-muted">
                  So an operator, or anyone who compels one, can see that your
                  company has a project called{" "}
                  <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                    payments
                  </code>{" "}
                  with a{" "}
                  <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                    production
                  </code>{" "}
                  environment holding 34 secrets, that a particular engineer
                  read from it at 02:14, and that one of those secrets changed
                  an hour later. They cannot see what any of them are called or
                  what any of them contain.
                </p>
                <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
                  That is a real metadata leak and it is not going away, because
                  a server that cannot index on any of it cannot route a
                  request. Said here rather than discovered later.
                </p>
                <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
                  What the server does hold: public keys, wrapped key blobs it
                  cannot open, and ciphertext. Sluice&apos;s own bootstrap
                  secrets, such as a JWT signing key and the password pepper,
                  live in deployment environment variables precisely because
                  they are not secret-decrypting material. If you find a place
                  where that is not true, that is a critical finding.
                </p>
              </Reveal>
            </div>
          </Container>
        </Section>

        <Section id="limitations" labelledBy="limitations-heading" divided>
          <Container>
            <Reveal>
              <Eyebrow>Limitations</Eyebrow>
            </Reveal>
            <Reveal delay={80}>
              <SectionHeading id="limitations-heading" className="ink mt-5 max-w-[24ch]">
                Everything that is not true yet.
              </SectionHeading>
            </Reveal>
            <Reveal delay={160}>
              <p className="mt-6 max-w-160 text-[17px] leading-relaxed text-text-muted">
                No dates, because there are none. Each of these appears in the
                same words anywhere else on this site that it appears at all.
              </p>
            </Reveal>

            <dl className="mt-12 grid gap-4 lg:grid-cols-2">
              {ALL_LIMITS.map((limit, index) => (
                <Reveal
                  key={limit.id}
                  delay={(index % 2) * 60}
                  className="panel p-7"
                  as="div"
                >
                  <div id={limit.id} className="relative scroll-mt-28">
                    <dt className="text-[17px] font-semibold tracking-[-0.01em] text-text-primary">
                      {limit.title}
                    </dt>
                    <dd className="mt-3 text-[16px] leading-relaxed text-text-muted">
                      {limit.body}
                    </dd>
                  </div>
                </Reveal>
              ))}
            </dl>

            <Reveal delay={80}>
              <p className="mt-8 max-w-180 text-[16px] leading-relaxed text-text-muted">
                One more, and it belongs to the platform rather than to Sluice: a
                Convex admin key grants complete control over a deployment and
                cannot be revoked once created. It does not let anyone decrypt
                customer secrets, because the material needed to do that is
                never on the server. It does let the holder read everything in
                the metadata list above, and change what the deployment serves.
                That constrains self-hosters as much as it constrains this
                project.
              </p>
            </Reveal>
          </Container>
        </Section>

        <Section id="report" labelledBy="report-heading" divided>
          <Container className="grid gap-12 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16">
            <div>
              <Reveal>
                <Eyebrow>Disclosure</Eyebrow>
              </Reveal>
              <Reveal delay={80}>
                <SectionHeading id="report-heading" className="ink mt-5">
                  Report a vulnerability.
                </SectionHeading>
              </Reveal>
              <Reveal delay={160}>
                <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
                  Please do not open a public GitHub issue, discussion or pull
                  request for a suspected vulnerability. Public reports are
                  visible to everyone, including anyone who would use the
                  finding, before there is a fix.
                </p>
              </Reveal>
              <Reveal delay={200}>
                <p className="mt-6">
                  <a
                    href={`mailto:${SECURITY_CONTACT}`}
                    className={`inline-flex h-11 cursor-pointer items-center justify-center rounded-input bg-brand-solid px-5 text-[15px] font-medium text-text-on-brand-solid transition-colors hover:bg-brand-solid-hover ${focusRing}`}
                  >
                    {SECURITY_CONTACT}
                  </a>
                </p>
              </Reveal>
              <Reveal delay={240}>
                <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
                  If you want to encrypt the report, say so in a first email and
                  a key will be exchanged. There is no published PGP key yet.
                  Coordinated disclosure is preferred, and a fix will be shipped
                  as fast as a solo maintainer reasonably can. If you set a
                  deadline, state it up front so it can be planned around rather
                  than discovered late.
                </p>
              </Reveal>
            </div>

            <div>
              <Reveal className="panel p-7">
                <h3 className="text-[15px] font-semibold text-text-primary">
                  Useful reports include
                </h3>
                <ul className="mt-5 space-y-3">
                  {REPORT_SHOULD_INCLUDE.map((item) => (
                    <li key={item} className="text-[16px] leading-relaxed text-text-muted">
                      {item}
                    </li>
                  ))}
                </ul>
              </Reveal>

              <Reveal delay={80} className="panel mt-4 divide-y divide-hairline">
                {COMMITMENTS.map(([title, detail]) => (
                  <div key={title} className="p-6">
                    <p className="text-[15.5px] font-medium text-text-primary">{title}</p>
                    <p className="mt-1.5 text-[16px] leading-relaxed text-text-muted">
                      {detail}
                    </p>
                  </div>
                ))}
              </Reveal>

              <Reveal delay={120}>
                <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
                  Scope, in and out, is listed in full in{" "}
                  <a
                    href={SECURITY_URL}
                    target="_blank"
                    rel="noreferrer noopener"
                    className={textLink}
                  >
                    SECURITY.md
                  </a>
                  . The full threat model is section 2 of the{" "}
                  <a
                    href={IMPLEMENTATION_PLAN_URL}
                    target="_blank"
                    rel="noreferrer noopener"
                    className={textLink}
                  >
                    implementation plan
                  </a>
                  .
                </p>
              </Reveal>
            </div>
          </Container>
        </Section>
      </main>
      <SiteFooter />
    </>
  );
}
