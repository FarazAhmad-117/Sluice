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

        <div className="flex items-center gap-8">
          <NavLinks
            label="Primary"
            className="hidden items-center gap-7 text-sm md:flex"
          />
          <a href="#quickstart" className={primaryAction}>
            Quickstart
          </a>
        </div>
      </Container>

      <div className="border-t border-hairline md:hidden">
        <Container>
          <NavLinks
            label="Primary, compact"
            className="flex h-10 items-center gap-6 text-base"
          />
        </Container>
      </div>
    </header>
  );
}
