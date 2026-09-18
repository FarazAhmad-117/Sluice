import { CopyButton } from "@/components/landing/copy-button";
import { CONTRIBUTING_URL, SECURITY_URL } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";

/**
 * Quickstart.
 *
 * Two columns: the argument on the left, the thing you can actually run on the
 * right. A centred single column was the previous shape and it buried the
 * terminal below the fold on a laptop, which is backwards for a section whose
 * entire job is to get a stranger to run four commands.
 *
 * These four lines are the real thing. Nothing is published to npm, so an
 * `npm i @sluice/sdk` would 404 on the first command a visitor ran, and a
 * landing page whose quickstart does not work is worse than no quickstart.
 * What is shown is what a person can run today: clone, install, and watch the
 * crypto suite go green.
 *
 * ON THE WELL. It sits on `--surface-deep`, which is the one surface in the
 * system that is DARKER than the canvas-adjacent panel above it, and colder.
 * That is what makes it read as recessed without an inset shadow, and it is
 * the only place that token is allowed. The three dots are a window chrome
 * cliche and they are here anyway, because they do one useful thing no label
 * does: they tell a reader at a glance, before reading a character, that the
 * block is a terminal and not a configuration sample.
 */

const COMMANDS = [
  "git clone https://github.com/FarazAhmad-117/Sluice.git",
  "cd Sluice",
  "pnpm install",
  "pnpm -r test",
];

const COMMAND_BLOCK = COMMANDS.join("\n");

/** Window chrome. Purely decorative, hence inert and unlabelled. */
function TrafficLights() {
  return (
    <div aria-hidden="true" className="flex items-center gap-1.5">
      <span className="size-2.5 rounded-full bg-status-danger/60" />
      <span className="size-2.5 rounded-full bg-status-warning/60" />
      <span className="size-2.5 rounded-full bg-status-healthy/60" />
    </div>
  );
}

export function Quickstart() {
  return (
    <Section id="quickstart" labelledBy="quickstart-heading">
      <Container className="grid items-center gap-14 lg:grid-cols-[0.9fr_1.1fr]">
        <div>
          <Reveal>
            <Eyebrow>Quickstart</Eyebrow>
          </Reveal>

          <Reveal delay={80}>
            <SectionHeading id="quickstart-heading" className="ink mt-5">
              Clone it and run the tests.
            </SectionHeading>
          </Reveal>

          <Reveal delay={160}>
            <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
              Nothing is published to npm yet, so this is the whole of what you
              can run today. It needs Node 22 and pnpm 10.
            </p>
          </Reveal>

          <Reveal delay={200}>
            <p className="mt-5 text-[15px] leading-relaxed text-text-muted">
              The tests live in{" "}
              <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                packages/crypto
              </code>
              , which is all there is. No backend, no dashboard, no SDK &mdash;
              and no dependency on Convex, Next.js, React or Node built-ins, so
              it runs unchanged in a browser, in Node and in Bun.
            </p>
          </Reveal>
        </div>

        <Reveal delay={120}>
          <div className="panel overflow-hidden bg-surface-deep">
            <div className="flex items-center gap-2 border-b border-hairline px-4 py-3.5">
              <TrafficLights />
              <p className="ml-2 font-mono text-xs text-text-faint">~/code</p>
              <div className="ml-auto">
                <CopyButton
                  value={COMMAND_BLOCK}
                  describes="the four quickstart commands"
                />
              </div>
            </div>

            <pre className="overflow-x-auto px-6 py-5">
              <code className="block font-mono text-sm leading-8 text-text-body">
                {COMMANDS.map((command) => (
                  <span key={command} className="block whitespace-pre">
                    <span aria-hidden="true" className="text-text-faint select-none">
                      {"$ "}
                    </span>
                    {command}
                  </span>
                ))}
                {/* The last two lines are output, not input, so they carry no
                    prompt. They are what the suite actually prints. */}
                <span className="block whitespace-pre text-text-faint">
                  {"  packages/crypto  7 files"}
                </span>
                <span className="block whitespace-pre text-status-healthy">
                  {"  ✓ 187 passed"}
                </span>
              </code>
            </pre>
          </div>

          {/*
            The disclosure is a tinted card, not a plain paragraph. It is the
            most important sentence on the page for a reader deciding whether to
            trust this with production, and it cannot be set in the same weight
            as the sentence above it about package dependencies.
          */}
          <div className="mt-5 flex gap-3.5 rounded-[14px] border border-status-warning/20 bg-status-warning/4 px-5 py-4.5">
            <svg
              aria-hidden="true"
              className="mt-0.5 shrink-0"
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="var(--status-warning)"
              strokeWidth="2"
              strokeLinecap="round"
            >
              <path d="M12 3 2 21h20L12 3zM12 10v5M12 18v.01" />
            </svg>
            <p className="text-[14px] leading-relaxed text-[#c9b98f]">
              <b className="font-medium text-[#fde68a]">
                Do not put production secrets in Sluice yet.
              </b>{" "}
              There has been no third-party cryptographic review, no release and
              no upgrade path. That is written down in{" "}
              <a
                href={SECURITY_URL}
                target="_blank"
                rel="noreferrer noopener"
                className={textLink}
              >
                SECURITY.md
              </a>{" "}
              and{" "}
              <a
                href={CONTRIBUTING_URL}
                target="_blank"
                rel="noreferrer noopener"
                className={textLink}
              >
                CONTRIBUTING.md
              </a>{" "}
              too.
            </p>
          </div>
        </Reveal>
      </Container>
    </Section>
  );
}
