import {
  Container,
  focusRing,
  primaryAction,
} from "@/components/landing/primitives";
import { IMPLEMENTATION_PLAN_URL, REPO_URL } from "@/components/landing/links";

/**
 * Site navigation.
 *
 * Desktop is one 64px line, inside the 72px budget. Below 768px the three
 * links drop to a second 40px strip rather than into a hamburger: a
 * disclosure menu would need state and would stay open after an in-page
 * anchor click, and two rows of 96px total is a smaller problem than a menu
 * that behaves badly. Nothing here needs JavaScript.
 *
 * "Docs" points at the implementation plan because that is the documentation
 * that exists. There is no docs site yet, so there is no link to one.
 */

const navLink = `cursor-pointer rounded-input text-text-muted transition-colors hover:text-text-primary ${focusRing}`;

const links = [
  { label: "Docs", href: IMPLEMENTATION_PLAN_URL, external: true },
  { label: "Threat model", href: "#threat-model", external: false },
  { label: "GitHub", href: REPO_URL, external: true },
];

function NavLinks({ label, className }: { label: string; className: string }) {
  return (
    <nav aria-label={label} className={className}>
      {links.map((link) => (
        <a
          key={link.label}
          href={link.href}
          className={navLink}
          {...(link.external
            ? { target: "_blank", rel: "noreferrer noopener" }
            : {})}
        >
          {link.label}
        </a>
      ))}
    </nav>
  );
}

export function SiteNav() {
  return (
    <header className="sticky top-0 z-50 border-b border-hairline bg-surface-base/85 backdrop-blur">
      <Container className="flex h-14 items-center justify-between gap-4 md:h-16">
        <a
          href="#top"
          className={`cursor-pointer rounded-input text-[1.0625rem] font-semibold tracking-[-0.02em] text-text-primary transition-colors hover:text-brand ${focusRing}`}
        >
          Sluice
        </a>

        <div className="flex items-center gap-6">
          <NavLinks
            label="Primary"
            className="hidden items-center gap-7 text-sm md:flex"
          />
          {/*
            Sign in is a plain text link immediately left of the primary
            button, which is what every reference site in the category does
            without exception. It is never styled as a button, because two
            buttons of equal weight make neither of them the call to action.

            This was missing entirely until 2026-09-18. The signup and login
            pages existed and worked, and nothing on the marketing site
            pointed at them, which is a broken product rather than a design
            preference.
          */}
          <a href="/login" className={`hidden text-sm md:inline ${navLink}`}>
            Sign in
          </a>
          <a href="/signup" className={primaryAction}>
            Get started
          </a>
        </div>
      </Container>

      <div className="border-t border-hairline md:hidden">
        <Container className="flex h-10 items-center justify-between gap-4">
          <NavLinks
            label="Primary, compact"
            className="flex items-center gap-6 text-base"
          />
          {/* Sign in follows the links into the compact strip rather than
              disappearing below 768px, where most first visits happen. */}
          <a href="/login" className={`text-base ${navLink}`}>
            Sign in
          </a>
        </Container>
      </div>
    </header>
  );
}
