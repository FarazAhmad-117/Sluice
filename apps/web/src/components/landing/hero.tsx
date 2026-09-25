import Link from "next/link";

import { CommandCta } from "@/components/landing/command-cta";
import { ROUTES } from "@/components/landing/links";
import { Reveal } from "@/components/landing/motion";
import { IllustrationSlot } from "@/components/landing/page-header";
import { Container, ghostAction } from "@/components/landing/primitives";

/**
 * Hero.
 *
 * WHAT IT HAS TO WIN, IN ORDER. Two concessions from a senior developer who
 * arrived sceptical: first that this solves something they deal with every
 * week, and only then that it does one thing nothing else does. Leading on the
 * second alone is how a secrets manager ends up being read as a research
 * project. Leading on the first alone puts Sluice on a feature comparison
 * against Doppler and Infisical, who are mature and shipping, and it loses
 * every row but one.
 *
 * So the headline is one sentence carrying both halves: a `.env` file replaced,
 * which is the daily problem, and taken back, which is the thing nobody else
 * can do. The accent is on "take back" because that is the half the rest of the
 * page has to prove.
 *
 * THE PILL CARRIES THE DISCLOSURE AND IT COMES FIRST. It is the first thing
 * read on the page, which is where "not third-party audited" belongs on a
 * security product that has not been audited. Stating the limit before the
 * claim is a different act from attaching it to one afterwards: the first is a
 * fact, the second is a hedge. It links to `/security`, which is where the rest
 * of the limits are, rather than out to the raw file.
 *
 * ONE CALL TO ACTION, AND IT IS THE COMMAND. The second control is a plain
 * ghost link to the mechanism, for the reader whose next move is scrutiny.
 * After this section nothing on the homepage asks for anything until the very
 * last card.
 */
export function Hero() {
  return (
    <header className="relative overflow-hidden pt-28 pb-20 sm:pt-32 lg:pt-36 lg:pb-24">
      {/* Graph paper, masked to an ellipse behind the stage. It gives the black
          something to be measured against; without it the artwork floats. */}
      <div
        aria-hidden="true"
        className="graph-paper pointer-events-none absolute inset-0"
      />

      <Container className="relative grid items-center gap-16 lg:grid-cols-[1.05fr_1fr] lg:gap-10">
        <div>
          <Reveal>
            <Link
              href={ROUTES.security}
              className="inline-flex items-center gap-2.5 rounded-full border border-hairline-strong bg-surface-card py-1.5 pr-4 pl-1.5 text-[12.5px] text-text-muted transition-colors hover:border-hairline-strong hover:text-text-body"
            >
              <b className="rounded-full bg-status-warning/10 px-2.5 py-0.5 text-[11.5px] font-medium text-status-warning">
                Pre-release
              </b>
              Not third-party audited yet
            </Link>
          </Reveal>

          <Reveal delay={80}>
            <h1 className="display-xl ink mt-7 max-w-[17ch]">
              Replace your .env with something you can{" "}
              <em className="ink-accent">take back</em>.
            </h1>
          </Reveal>

          <Reveal delay={160}>
            <p className="mt-6 max-w-125 text-[18px] leading-[1.65] text-text-muted">
              Sluice hands your process its secrets from a server that has never
              held the key to read them. Revoke a token and every process still
              holding it shuts down, because each one verified a signature the
              server could not have produced.
            </p>
          </Reveal>

          <Reveal delay={240}>
            <div className="mt-9 flex flex-wrap items-center gap-3">
              <CommandCta size="lg" />
              <Link
                href={ROUTES.howItWorks}
                className={`${ghostAction} h-12 rounded-full border border-hairline-strong bg-surface-card px-5 text-[15px] text-text-primary hover:bg-surface-panel`}
              >
                How it works
              </Link>
            </div>
          </Reveal>

          <Reveal delay={300}>
            <p className="mt-6 max-w-125 text-[16px] leading-relaxed text-text-muted">
              Not on npm yet. The command is real and the quickstart installs it
              from a clone.
            </p>
          </Reveal>
        </div>

        {/*
          ==================================================================
          GRAPHICS SLOT 1 OF 3: THE KILL SWITCH
          ==================================================================
          Owner-designed illustration. Do not fill this with hand-rolled SVG.

          Target size   560 x 560 at the largest step, square, transparent
                        background, and legible at 320px wide on a phone.
          Placement     hero, opposite the copy, vertically centred.

          It must communicate three things and nothing else:

            1. INSTANT. A signature glyph travels from an admin action to one
               process node, and only ON ARRIVAL does that node fade from solid
               to hollow. The fade must not begin before the glyph lands, or
               the picture claims the server can kill a process on its own.
            2. SELECTIVE. A cluster of process nodes, each holding a token, one
               marked as targeted. Every neighbour is untouched at the end.
            3. GATED ON THE SIGNATURE. The glyph is the cause, drawn as such.

          Palette: tokens only. Brand blue for the signature path, the danger
          token for the node that dies, hairline for everything at rest.

          Drop the asset in as <Image> with explicit width and height, delete
          this placeholder box, and keep the comment.
        */}
        <Reveal delay={160}>
          <IllustrationSlot
            name="the kill switch"
            width={560}
            height={560}
            className="mx-auto max-w-[560px]"
          />
        </Reveal>
      </Container>
    </header>
  );
}
