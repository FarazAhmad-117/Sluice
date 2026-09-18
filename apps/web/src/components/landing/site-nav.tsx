"use client";

import { useEffect, useState } from "react";
import { focusRing, primaryAction } from "@/components/landing/primitives";
import { REPO_URL } from "@/components/landing/links";

/**
 * Site navigation.
 *
 * Full width and invisible over the hero; a detached glass island once the page
 * has moved. That is the one bit of state here, and the transition between the
 * two is the point: the sides draw in, the corners round, a hairline and a blur
 * appear, and the bar lifts off the top edge, all on one duration and one
 * easing so it reads as a single contraction rather than as five properties
 * animating.
 *
 * Both end states earn their place. A bar that is opaque from the first frame
 * puts a hard horizontal rule across the top of a hero whose whole job is to be
 * an unbroken field of black. A bar that stays transparent leaves the links
 * unreadable the moment a code block scrolls under them. Detaching solves both
 * and does one more thing: an island has edges, so it stops being part of the
 * page and starts being a control that floats above it.
 *
 * The `scrolled` threshold is deliberately small. Anything larger leaves a
 * window where the page has clearly moved and the bar has not reacted, which
 * reads as a dropped frame rather than as a considered delay.
 *
 * NO LOGO MARK. Just the wordmark. A generated glyph next to a four-letter name
 * is a placeholder pretending to be an identity, and it would be the only piece
 * of invented brand on a page that is otherwise careful to show nothing it
 * cannot back up.
 *
 * Below 980px the section links drop out rather than collapsing into a
 * hamburger: a disclosure menu needs state, stays open after an in-page anchor
 * click, and buys nothing on a page with four destinations that are all
 * reachable by scrolling.
 */

const LINKS = [
  { label: "Quickstart", href: "#quickstart" },
  { label: "Kill switch", href: "#revocation" },
  { label: "Threat model", href: "#threat-model" },
  { label: "Contribute", href: "#contributors" },
] as const;

const navLink = `cursor-pointer rounded-input text-text-muted transition-colors hover:text-text-primary ${focusRing}`;

export function SiteNav() {
  const [scrolled, setScrolled] = useState(false);

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
        <div className="relative flex h-16 items-center gap-8">
        <a
          href="#top"
          className={`text-[17px] font-semibold tracking-[-0.02em] text-text-primary ${focusRing}`}
        >
          Sluice
        </a>

        <nav aria-label="Sections" className="hidden items-center gap-6 text-sm lg:flex">
          {LINKS.map((link) => (
            <a key={link.label} href={link.href} className={navLink}>
              {link.label}
            </a>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-2.5">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer noopener"
            className={`hidden h-8.5 items-center gap-2 rounded-full border border-hairline px-3 text-[13px] text-text-muted transition-colors hover:border-hairline-strong hover:text-text-primary sm:inline-flex ${focusRing}`}
          >
            <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 .5a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.4-1.4-1.8-1.4-1.8-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17.3 4.7 18.3 5 18.3 5c.7 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .5Z" />
            </svg>
            GitHub
          </a>
          <a href="#quickstart" className={`${primaryAction} h-8.5 rounded-full px-4 text-[13px]`}>
            Get started
          </a>
        </div>
        </div>
      </div>
    </header>
  );
}
