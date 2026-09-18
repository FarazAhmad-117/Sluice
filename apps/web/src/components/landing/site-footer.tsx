import {
  CONTRIBUTING_URL,
  IMPLEMENTATION_PLAN_URL,
  LICENCE_URL,
  README_URL,
  REPO_URL,
  SECURITY_URL,
} from "@/components/landing/links";
import { Container, focusRing } from "@/components/landing/primitives";
import { Parallax } from "@/components/landing/motion";
import { Wordmark } from "@/components/landing/wordmark";

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
 *
 * ON THE GIANT WORDMARK. It is set in the display serif at up to 340px, clipped
 * to a gradient that fades out before the baseline, and pushed half off the
 * bottom of the document. It is the one purely expressive thing on the page and
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

const footerLink = `cursor-pointer rounded-input text-sm text-text-muted transition-colors hover:text-text-primary ${focusRing}`;

export function SiteFooter() {
  return (
    <footer className="mt-24 overflow-hidden border-t border-hairline bg-surface-base pt-20">
      <Container className="grid gap-12 md:grid-cols-[minmax(0,1.6fr)_repeat(3,minmax(0,1fr))] md:gap-10">
        <div>
          <p className="text-[1.0625rem] font-semibold tracking-[-0.02em] text-text-primary">
            Sluice
          </p>
          <p className="mt-3 max-w-[34ch] text-sm leading-relaxed text-text-muted">
            Zero-knowledge environment variable delivery, with cryptographically
            signed revocation of live processes. Pre-release.
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
