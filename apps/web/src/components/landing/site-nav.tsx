"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { CommandCta } from "@/components/landing/command-cta";
import { formatStars, showStars } from "@/components/landing/github-repo";
import { REPO_URL, ROUTES, SIGN_IN_URL } from "@/components/landing/links";
import { focusRing } from "@/components/landing/primitives";

/**
 * Site navigation.
 *
 * Full width and invisible over the top of a page; a detached glass island once
 * the page has moved. That is the one bit of state here, and the transition
 * between the two is the point: the sides draw in, the corners round, a
 * hairline and a blur appear, and the bar lifts off the top edge, all on one
 * duration and one easing so it reads as a single contraction rather than as
 * five properties animating.
 *
 * THE SHAPE IS THE ONE EVERY SITE IN THIS CATEGORY USES, and it is used here
 * because it is load-bearing rather than because it is common: logo, section
 * links, a star chip, "Sign in" as a plain text link, then the primary action.
 * Sign in is a text link and never a button. A signed-in customer looking for
 * their dashboard and a stranger evaluating the product are different people,
 * and giving both of them a button makes the page ask two questions at once.
 *
 * `/security` PASSES `cta={false}`. That page exists to be read by someone
 * looking for a reason to say no, and its only action is reporting a
 * vulnerability. A sticky button selling the product across the top of a threat
 * model undoes the restraint the page is built on, so the bar goes without one
 * there.
 *
 * NO LOGO MARK. Just the wordmark. A generated glyph next to a four-letter name
 * is a placeholder pretending to be an identity, and it would be the only piece
 * of invented brand on a site that is otherwise careful to show nothing it
 * cannot back up.
 *
 * WHAT DROPS OUT AS THE VIEWPORT NARROWS, and why there is no hamburger. Below
 * 1024px the section links go, below 768px the star chip goes, and below 640px
 * the command goes, because the command is 28 monospaced characters and a phone
 * cannot hold it beside a wordmark and a sign-in link without scrolling
 * sideways. Every one of those destinations is in the footer of every page, the
 * command is the first thing in the hero one screen up, and a disclosure menu
 * would need state, would stay open after a navigation, and would buy nothing
 * on a site with four destinations.
 */

const LINKS = [
  { label: "How it works", href: ROUTES.howItWorks },
  { label: "Security", href: ROUTES.security },
  { label: "Open source", href: ROUTES.openSource },
] as const;

export function SiteNav({
  stars,
  cta = true,
}: {
  /** From `loadRepoFacts`. `null` renders the chip with no count. */
  stars: number | null;
  /** `false` on `/security`, which carries no product call to action. */
  cta?: boolean;
}) {
  const [scrolled, setScrolled] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    /*
      The fixed element is a full-width, inert layer; the island inside it is
      what moves and what takes pointer events. Keeping those two jobs on
      separate elements is what allows the island's box to shrink without the
      fixed positioning fighting it, and it means the transparent gutters either
      side of a docked island never swallow a click meant for the page.
    */
    <header className="pointer-events-none fixed inset-x-0 top-0 z-50">
      <div
        data-docked={scrolled}
        className="nav-dock pointer-events-auto relative mx-auto px-5 sm:px-8"
      >
        <div className="relative flex h-16 items-center gap-6">
          <Link
            href={ROUTES.home}
            className={`shrink-0 rounded-input text-[17px] font-semibold tracking-[-0.02em] text-text-primary ${focusRing}`}
          >
            Sluice
          </Link>

          <nav aria-label="Sections" className="hidden items-center gap-6 text-sm lg:flex">
            {LINKS.map((link) => {
              const active = pathname === link.href;
              return (
                <Link
                  key={link.label}
                  href={link.href}
                  aria-current={active ? "page" : undefined}
                  className={`relative cursor-pointer rounded-input py-1 transition-colors ${
                    active ? "text-text-primary" : "text-text-muted hover:text-text-primary"
                  } ${focusRing}`}
                >
                  {link.label}
                  {active ? (
                    <span
                      aria-hidden="true"
                      className="absolute -bottom-0.5 left-0 h-0.5 w-full rounded-full bg-brand"
                    />
                  ) : null}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={`hidden h-8.5 items-center gap-2 rounded-full border border-hairline px-3 text-[13px] text-text-muted transition-colors hover:border-hairline-strong hover:text-text-primary md:inline-flex ${focusRing}`}
            >
              <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 .5a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.4-1.4-1.8-1.4-1.8-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.7 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .5Z" />
              </svg>
              {/* No count rather than a guessed one when the API was
                  unreachable at build time, and none at zero either. See
                  `showStars`. The link still reaches the page with the real
                  figure. */}
              {showStars(stars) ? (
                <>
                  {formatStars(stars)}
                  <span className="sr-only">stars on GitHub</span>
                </>
              ) : (
                "GitHub"
              )}
            </a>

            <a
              href={SIGN_IN_URL}
              className={`cursor-pointer rounded-input text-[13px] text-text-muted transition-colors hover:text-text-primary ${focusRing}`}
            >
              Sign in
            </a>

            {/*
              THE BREAKPOINT LIVES ON A WRAPPER, NOT ON THE LINK, and it has to.
              `CommandCta` carries `inline-flex` in its own base class, and
              Tailwind orders utilities by property rather than by the order they
              appear in a class attribute, so a `hidden` passed in from here
              loses to it and the command renders 15px off the right edge of a
              375px screen. Measured in a browser at 375px, which is the only
              way this was ever going to be noticed.
            */}
            {cta ? (
              <span className="hidden sm:block">
                <CommandCta size="sm" />
              </span>
            ) : null}
          </div>
        </div>
      </div>
    </header>
  );
}
