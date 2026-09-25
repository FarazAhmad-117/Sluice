import Link from "next/link";

import {
  CONTRIBUTING_URL,
  IMPLEMENTATION_PLAN_URL,
  ISSUES_URL,
  LICENCE_URL,
  README_URL,
  REPO_URL,
  ROUTES,
  SECURITY_CONTACT,
  SECURITY_URL,
} from "@/components/landing/links";
import { Container, focusRing } from "@/components/landing/primitives";
import { Parallax } from "@/components/landing/motion";
import { Wordmark } from "@/components/landing/wordmark";

/**
 * Footer.
 *
 * Layout family: a link grid, which nothing else on the site uses. No version
 * string, no locale or time strip, no status dot, no build hash. The only
 * things here are destinations and the licence.
 *
 * IT CARRIES WHAT THE HEADER DOES NOT. The navigation bar shows three
 * destinations; this shows eleven, including the contributor-facing ones. That
 * split is the whole reason a multi-page site can keep a four-item header: a
 * reader who wants `CONTRIBUTING.md` will look down here, and a reader
 * evaluating the product never has to walk past it.
 *
 * The security contact is written out rather than hidden behind a "contact us".
 * It is the only address on the site and it is the same one `SECURITY.md`
 * gives.
 *
 * ON THE GIANT WORDMARK. It is set in the display serif at up to 340px, clipped
 * to a gradient that fades out before the baseline, and pushed half off the
 * bottom of the document. It is the one purely expressive thing on the site and
 * it earns its place by being the LAST thing: a reader who reaches it has
 * finished, and a page that ends on a link grid ends on admin. It parallaxes
 * gently against the scroll, which is what stops it reading as a watermark.
 *
 * Moving a pointer across it wipes a bright copy of the letters into view under
 * the cursor. See `wordmark.tsx`; it is `aria-hidden`, because the brand name is
 * already in the nav, the first footer column and the copyright line, and a
 * screen reader announcing it a fourth time would be reading out decoration.
 */

type FooterLink = { label: string; href: string; external: boolean };

const GROUPS: { title: string; links: FooterLink[] }[] = [
  {
    title: "Product",
    links: [
      { label: "How it works", href: ROUTES.howItWorks, external: false },
      { label: "Security", href: ROUTES.security, external: false },
      { label: "Status", href: ROUTES.status, external: false },
    ],
  },
  {
    title: "Project",
    links: [
      { label: "Open source", href: ROUTES.openSource, external: false },
      { label: "GitHub", href: REPO_URL, external: true },
      { label: "Licence", href: LICENCE_URL, external: true },
      { label: "Contributing", href: CONTRIBUTING_URL, external: true },
    ],
  },
  {
    title: "Reference",
    links: [
      { label: "Security policy", href: SECURITY_URL, external: true },
      { label: "Implementation plan", href: IMPLEMENTATION_PLAN_URL, external: true },
      { label: "Readme", href: README_URL, external: true },
      { label: "Issues", href: ISSUES_URL, external: true },
    ],
  },
];

const footerLink = `cursor-pointer rounded-input text-sm text-text-muted transition-colors hover:text-text-primary ${focusRing}`;

export function SiteFooter() {
  return (
    <footer className="mt-24 overflow-hidden border-t border-hairline bg-surface-base pt-20">
      <Container className="grid gap-12 md:grid-cols-[minmax(0,1.6fr)_repeat(3,minmax(0,1fr))] md:gap-10">
        <div>
          <p className="text-[1.0625rem] font-semibold tracking-[-0.02em] text-text-primary">
            Sluice
          </p>
          <p className="mt-3 max-w-[34ch] text-base leading-relaxed text-text-muted">
            Zero-knowledge environment variable delivery, with cryptographically
            signed revocation of live processes. Pre-release.
          </p>
          <p className="mt-5 text-base leading-relaxed text-text-muted">
            Report a vulnerability:{" "}
            <a
              href={`mailto:${SECURITY_CONTACT}`}
              className={`cursor-pointer rounded-input text-brand underline underline-offset-4 transition-colors hover:text-brand-hover ${focusRing}`}
            >
              {SECURITY_CONTACT}
            </a>
          </p>
        </div>

        {GROUPS.map((group) => (
          <nav key={group.title} aria-label={group.title}>
            {/* A <p>, not a heading: these are nav group labels and the navs
                already carry aria-label, so promoting them to h2 would put
                "Project" in the document outline beside "Threat model". */}
            <p className="font-mono text-xs tracking-[0.14em] text-text-faint uppercase">
              {group.title}
            </p>
            <ul className="mt-4 space-y-3">
              {group.links.map((link) => (
                <li key={link.label}>
                  {link.external ? (
                    <a
                      href={link.href}
                      target="_blank"
                      rel="noreferrer noopener"
                      className={footerLink}
                    >
                      {link.label}
                    </a>
                  ) : (
                    <Link href={link.href} className={footerLink}>
                      {link.label}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </nav>
        ))}
        <div className="col-span-full mt-12 flex flex-wrap items-center justify-between gap-3 border-t border-hairline pt-8 font-mono text-[12.5px] text-text-faint">
          <span>Apache-2.0 &middot; &copy; 2026 Faraz Ahmad</span>
          <span>pre-release</span>
        </div>
      </Container>

      <Parallax speed={0.06}>
        <Wordmark />
      </Parallax>
    </footer>
  );
}
