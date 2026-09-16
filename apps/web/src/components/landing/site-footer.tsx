import {
  CONTRIBUTING_URL,
  IMPLEMENTATION_PLAN_URL,
  LICENCE_URL,
  README_URL,
  REPO_URL,
  SECURITY_URL,
} from "@/components/landing/links";
import { Container, focusRing } from "@/components/landing/primitives";

/**
 * Footer.
 *
 * Layout family: a link grid, which nothing else on the page uses. No version
 * string, no locale or time strip, no status dot, no build hash. The only
 * things here are destinations and the licence.
 *
 * There is no sponsors section above this one. See the report: GitHub Sponsors
 * is not enabled for this account, there is no FUNDING.yml and no Open
 * Collective, so an invitation to sponsor would have had nowhere to point.
 */

type FooterLink = { label: string; href: string; external: boolean };

const GROUPS: { title: string; links: FooterLink[] }[] = [
  {
    title: "Project",
    links: [
      { label: "GitHub", href: REPO_URL, external: true },
      { label: "Readme", href: README_URL, external: true },
      {
        label: "Implementation plan",
        href: IMPLEMENTATION_PLAN_URL,
        external: true,
      },
    ],
  },
  {
    title: "Security",
    links: [
      { label: "Security policy", href: SECURITY_URL, external: true },
      { label: "Threat model", href: "#threat-model", external: false },
      { label: "Kill switch", href: "#revocation", external: false },
    ],
  },
  {
    title: "Contribute",
    links: [
      { label: "Contributing", href: CONTRIBUTING_URL, external: true },
      { label: "Issues", href: `${REPO_URL}/issues`, external: true },
      { label: "Licence", href: LICENCE_URL, external: true },
    ],
  },
];

const footerLink = `cursor-pointer rounded-input text-base text-text-muted transition-colors hover:text-brand ${focusRing}`;

export function SiteFooter() {
  return (
    <footer className="bg-surface-panel">
      <Container className="grid gap-12 py-16 sm:py-20 md:grid-cols-[minmax(0,1.3fr)_repeat(3,minmax(0,1fr))] md:gap-10">
        <div>
          <p className="text-[1.0625rem] font-semibold tracking-[-0.02em] text-text-primary">
            Sluice
          </p>
          <p className="mt-3 max-w-[34ch] text-base leading-relaxed text-text-muted">
            Zero-knowledge environment variable delivery, with cryptographically
            signed revocation of live processes. Pre-release.
          </p>
          <p className="mt-6 text-base text-text-muted">
            Apache-2.0. Copyright 2026 Faraz Ahmad.
          </p>
        </div>

        {GROUPS.map((group) => (
          <nav key={group.title} aria-label={group.title}>
            {/* A <p>, not a heading: these are nav group labels and the navs
                already carry aria-label, so promoting them to h2 would put
                "Project" in the document outline beside "Threat model". */}
            <p className="font-mono text-xs tracking-[0.14em] text-text-muted uppercase">
              {group.title}
            </p>
            <ul className="mt-4 space-y-3">
              {group.links.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className={footerLink}
                    {...(link.external
                      ? { target: "_blank", rel: "noreferrer noopener" }
                      : {})}
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        ))}
      </Container>
    </footer>
  );
}
