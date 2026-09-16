import { CopyButton } from "@/components/landing/copy-button";
import { CONTRIBUTING_URL, SECURITY_URL } from "@/components/landing/links";
import {
  Container,
  SectionHeading,
  textLink,
} from "@/components/landing/primitives";

/**
 * Quickstart.
 *
 * Centred single column with one full-width mono block, which is a different
 * layout family from every other section on the page.
 *
 * These four lines are the real thing. Nothing is published to npm, so an
 * `npm i @sluice/sdk` would 404 on the first command a visitor ran, and a
 * landing page whose quickstart does not work is worse than no quickstart.
 * What is shown is what a person can run today: clone, install, and watch the
 * crypto suite go green.
 *
 * The test count and file count below were taken from a real `pnpm -r test`
 * run, not from the README, which still reports the pre-`muk.ts` numbers.
 */

const COMMANDS = [
  "git clone https://github.com/FarazAhmad-117/Sluice.git",
  "cd Sluice",
  "pnpm install",
  "pnpm -r test",
];

const COMMAND_BLOCK = COMMANDS.join("\n");

export function Quickstart() {
  return (
    <section
      id="quickstart"
      className="scroll-mt-28 border-b border-hairline"
      aria-labelledby="quickstart-heading"
    >
      <Container className="py-20 sm:py-24">
        <div className="mx-auto max-w-3xl">
          <SectionHeading id="quickstart-heading" className="text-center">
            Clone it and run the tests
          </SectionHeading>

          <p className="mx-auto mt-5 max-w-[56ch] text-center text-base leading-relaxed text-text-muted sm:text-lg">
            Nothing is published to npm yet, so this is the whole of what you
            can run today. It needs Node 22 and pnpm 10.
          </p>

          <div className="mt-10 overflow-hidden rounded-card border border-hairline bg-surface-panel">
            <div className="flex items-center justify-between gap-4 border-b border-hairline px-4 py-3 sm:px-5">
              <p className="font-mono text-xs tracking-[0.14em] text-text-muted uppercase">
                Terminal
              </p>
              <CopyButton
                value={COMMAND_BLOCK}
                describes="the four quickstart commands"
              />
            </div>

            <pre className="overflow-x-auto px-4 py-5 sm:px-5">
              <code className="block font-mono text-sm leading-7 text-text-primary sm:text-base">
                {COMMANDS.map((command) => (
                  <span key={command} className="block whitespace-pre">
                    <span
                      aria-hidden="true"
                      className="text-text-muted select-none"
                    >
                      {"$ "}
                    </span>
                    {command}
                  </span>
                ))}
              </code>
            </pre>
          </div>

          <p className="mt-8 text-base leading-relaxed text-text-muted">
            That runs 187 tests across seven files in{" "}
            <code className="font-mono text-text-primary">packages/crypto</code>
            , which is all there is. No backend, no dashboard, no SDK. The
            package has no dependency on Convex, Next.js, React or Node
            built-ins, so it runs unchanged in a browser, in Node and in Bun.
          </p>

          <p className="mt-5 rounded-card border border-hairline bg-surface-card p-5 text-base leading-relaxed text-text-primary">
            Do not put production secrets in Sluice yet. There has been no
            third-party cryptographic review, there is no release and there is
            no upgrade path. This is the accurate description of a security
            product that has not been reviewed, and it is written down in{" "}
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
      </Container>
    </section>
  );
}
