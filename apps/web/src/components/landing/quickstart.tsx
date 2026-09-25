import { CopyButton } from "@/components/landing/copy-button";
import { CLI_README_URL, PRIMARY_COMMAND, ROUTES } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import {
  Container,
  Eyebrow,
  Section,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";
import Link from "next/link";

/**
 * Quickstart. The page the primary call to action lands on.
 *
 * IT OPENS BY SAYING WHAT IS MISSING. Nothing is published to npm, so
 * `npm i -g @sluice/cli` would 404 on the first command a visitor ran, and a
 * quickstart whose first line fails is worse than no quickstart. What is below
 * is what a person can actually run today, and every line of it has been run.
 *
 * ON `node server.js` RATHER THAN `npm start`, which is the example every other
 * site in this category would reach for. `packages/cli/src/node-runtime.ts`
 * spawns with `shell: false` on every platform, deliberately, because putting a
 * shell between the operator and their command re-parses an argument vector
 * their own shell has already read. On Windows `npm` is a `.cmd` shim and Node
 * has refused to spawn `.cmd` without a shell since the 2024 hardening, so
 * `sluice run -- npm start` fails there. That is a design position in the CLI
 * rather than an unfinished corner, so the note below says so plainly instead
 * of promising it will be fixed.
 *
 * ON THE WELL. It sits on `--surface-deep`, which is the one surface in the
 * system that is DARKER than the panel above it, and colder. That is what makes
 * it read as recessed without an inset shadow, and it is the only place that
 * token is allowed. The three dots are a window chrome cliche and they are here
 * anyway, because they do one useful thing no label does: they tell a reader at
 * a glance, before reading a character, that the block is a terminal and not a
 * configuration sample.
 */

const COMMANDS = [
  "git clone https://github.com/FarazAhmad-117/Sluice.git",
  "cd Sluice",
  "pnpm install",
  "pnpm --filter @sluice/cli build",
  "node packages/cli/bin/sluice.js --help",
];

const COMMAND_BLOCK = COMMANDS.join("\n");

const ENVIRONMENT = [
  ["SLUICE_TOKEN", "the service token you minted, slc_..."],
  [
    "SLUICE_ORG_REVOCATION_PUBLIC_KEY",
    "your org's Ed25519 public key, 64 hex characters. Sluice never fetches this for you: a server that could supply it could sign its own notices and kill every process you run.",
  ],
  ["SLUICE_CONVEX_URL", "your deployment address"],
] as const;

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
      <Container className="grid items-start gap-14 lg:grid-cols-[0.9fr_1.1fr]">
        <div>
          <Reveal>
            <Eyebrow>Quickstart</Eyebrow>
          </Reveal>

          <Reveal delay={80}>
            <SectionHeading id="quickstart-heading" className="ink mt-5">
              Install it from a clone.
            </SectionHeading>
          </Reveal>

          <Reveal delay={160}>
            <p className="mt-6 text-[17px] leading-relaxed text-text-muted">
              Nothing is published to npm yet, so there is no install command to
              give you. This is the whole of what works today. It needs Node 22
              and pnpm 10, and the five lines opposite have been run on this
              machine.
            </p>
          </Reveal>

          <Reveal delay={200}>
            <p className="mt-5 text-[16px] leading-relaxed text-text-muted">
              Once{" "}
              <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                sluice
              </code>{" "}
              is on your PATH, the command you will actually type is{" "}
              <code className="rounded-sm bg-surface-card px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                {PRIMARY_COMMAND}
              </code>
              . It takes three environment variables and no code change:
            </p>
          </Reveal>

          <Reveal delay={240}>
            <dl className="mt-6 space-y-4">
              {ENVIRONMENT.map(([name, meaning]) => (
                <div key={name}>
                  <dt className="font-mono text-[13px] break-all text-text-primary">
                    {name}
                  </dt>
                  <dd className="mt-1 text-[16px] leading-relaxed text-text-muted">
                    {meaning}
                  </dd>
                </div>
              ))}
            </dl>
          </Reveal>
        </div>

        {/*
          `min-w-0` IS THE ONLY THING STOPPING THIS SECTION SCROLLING SIDEWAYS
          ON A PHONE. A grid item's default `min-width` is `auto`, which resolves
          to its content's min-content width, and the terminal below contains
          `whitespace-pre` lines 470px wide. Without this the column refuses to
          shrink below 470px, the grid grows past the viewport, and the whole
          document scrolls horizontally even though the <pre> has its own
          `overflow-x-auto`. Measured in a 375px browser, where it was real.
        */}
        <Reveal delay={120} className="min-w-0">
          <div className="panel overflow-hidden bg-surface-deep">
            <div className="flex items-center gap-2 border-b border-hairline px-4 py-3.5">
              <TrafficLights />
              <p className="ml-2 font-mono text-xs text-text-faint">~/code</p>
              <div className="ml-auto">
                <CopyButton
                  value={COMMAND_BLOCK}
                  describes="the five quickstart commands"
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
                {/* Output, not input, so no prompt. This is what the build
                    prints and what the help text opens with. */}
                <span className="block whitespace-pre text-text-faint">
                  {"  dist/sluice.js  126.35 kB"}
                </span>
                {/* Not green. Green in a terminal means a suite passed, and
                    this is the first line of the help text. */}
                <span className="block whitespace-pre text-text-faint">
                  {"  sluice run -- <command> [args...]"}
                </span>
              </code>
            </pre>
          </div>

          {/*
            Two disclosures, and they are different kinds of thing. The first is
            a platform fact about the reader's own machine, which they will hit
            within a minute. The second is the one sentence on this site that a
            reader deciding about production must not miss.
          */}
          <div className="mt-5 rounded-card border border-hairline bg-surface-card px-5 py-4.5">
            <p className="text-[16px] leading-relaxed text-text-muted">
              <b className="font-medium text-text-primary">On Windows,</b> name a
              real executable rather than an npm script.{" "}
              <code className="rounded-sm bg-surface-panel px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                sluice run -- npm start
              </code>{" "}
              works on macOS and Linux and fails on Windows, where{" "}
              <code className="rounded-sm bg-surface-panel px-1.5 py-0.5 font-mono text-[0.9em] text-text-primary">
                npm
              </code>{" "}
              is a .cmd shim that Node will not spawn without a shell. Sluice
              will not silently put a shell there, because that re-parses an
              argument vector your own shell has already read, so it tells you
              to name the executable instead.{" "}
              <a
                href={CLI_README_URL}
                target="_blank"
                rel="noreferrer noopener"
                className={textLink}
              >
                The CLI source says the same thing
              </a>
              .
            </p>
          </div>

          <div className="mt-4 flex gap-3.5 rounded-card border border-status-warning/20 bg-status-warning/4 px-5 py-4.5">
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
            <p className="text-[16px] leading-relaxed text-text-body">
              <b className="font-medium text-text-primary">
                Do not put production secrets in Sluice yet.
              </b>{" "}
              There has been no third-party cryptographic review, no release and
              no upgrade path, and a forgotten password is permanent data loss
              because there is no account recovery.{" "}
              <Link href={ROUTES.security} className={textLink}>
                Every limit is on the security page
              </Link>
              .
            </p>
          </div>
        </Reveal>
      </Container>
    </Section>
  );
}
