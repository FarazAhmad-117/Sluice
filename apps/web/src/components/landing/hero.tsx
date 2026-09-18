import { FleetGlobe } from "@/components/landing/fleet-globe";
import { Reveal } from "@/components/landing/motion";
import { REPO_URL, SECURITY_URL } from "@/components/landing/links";
import {
  Container,
  ghostAction,
  primaryAction,
} from "@/components/landing/primitives";

/**
 * Hero.
 *
 * Asymmetric split: copy slightly wider than the stage, both vertically
 * centred. The stage is the globe and its two controls, and it carries the
 * entire argument -- there is no console card under it any more, because the
 * card duplicated in a table what the globe already said in a picture and won
 * the reader's attention by default, which demoted the globe back to
 * decoration.
 *
 * ON THE HEADLINE. The display face is an editorial serif and the accent phrase
 * is the only coloured type above the fold. One word is emphasised, "live",
 * because the sentence's whole claim rests on it: everyone in this category
 * revokes tokens, and nobody else reaches a process that is already running.
 *
 * THE PILL CARRIES THE DISCLOSURE. It is the first thing read on the page,
 * which is where "not third-party audited" belongs on a security product that
 * has not been audited. Putting it in the subtext instead, which is what this
 * page used to do, made it read as a hedge attached to a sales claim rather
 * than as a fact stated before one.
 */
export function Hero() {
  return (
    <header className="relative overflow-hidden pt-28 pb-20 sm:pt-32 lg:pt-36 lg:pb-24">
      {/* Graph paper, masked to an ellipse behind the globe. It gives the black
          something to be measured against; without it the globe floats. */}
      <div
        aria-hidden="true"
        className="graph-paper pointer-events-none absolute inset-0"
      />

      <Container className="relative grid items-center gap-16 lg:grid-cols-[1.05fr_1fr] lg:gap-10">
        <div>
          <Reveal>
            <a
              href={SECURITY_URL}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-2.5 rounded-full border border-hairline-strong bg-white/3 py-1.5 pr-4 pl-1.5 text-[12.5px] text-text-muted transition-colors hover:border-white/25 hover:text-text-body"
            >
              <b className="rounded-full bg-status-warning/10 px-2.5 py-0.5 text-[11.5px] font-medium text-status-warning">
                Pre-release
              </b>
              Not third-party audited yet
            </a>
          </Reveal>

          <Reveal delay={80}>
            <h1 className="display-xl ink mt-7 max-w-[13ch]">
              Revocation that reaches <em className="ink-accent">live</em>{" "}
              processes.
            </h1>
          </Reveal>

          <Reveal delay={160}>
            <p className="mt-6 max-w-125 text-[18px] leading-[1.65] text-text-muted">
              Zero-knowledge environment variables. When an admin revokes a
              token, every process holding it exits &mdash;{" "}
              <strong className="font-medium text-text-primary">
                and only because it verified a signature the server never could
                have made.
              </strong>
            </p>
          </Reveal>

          <Reveal delay={240}>
            <div className="mt-9 flex flex-wrap gap-3">
              <a href="#quickstart" className={`${primaryAction} h-11 gap-2 px-5 text-[15px]`}>
                Clone and run the tests
                <svg
                  aria-hidden="true"
                  width="14"
                  height="14"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2.4"
                  strokeLinecap="round"
                >
                  <path d="M5 12h14M13 6l6 6-6 6" />
                </svg>
              </a>
              <a
                href="#threat-model"
                className={`${ghostAction} h-11 rounded-full border border-hairline-strong bg-white/4 px-5 text-[15px] text-text-primary hover:bg-white/8`}
              >
                Read the threat model
              </a>
            </div>
          </Reveal>

          <Reveal delay={300}>
            <p className="mt-6 flex items-center gap-2 font-mono text-xs text-text-faint">
              <span className="text-text-muted" aria-hidden="true">
                $
              </span>
              <a
                href={REPO_URL}
                target="_blank"
                rel="noreferrer noopener"
                className="transition-colors hover:text-text-body"
              >
                git clone github.com/FarazAhmad-117/Sluice
              </a>
            </p>
          </Reveal>
        </div>

        <Reveal delay={160}>
          <FleetGlobe />
        </Reveal>
      </Container>
    </header>
  );
}
