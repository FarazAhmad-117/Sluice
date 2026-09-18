import { Contributors } from "@/components/landing/contributors";
import { FinalCta } from "@/components/landing/final-cta";
import { Hero } from "@/components/landing/hero";
import { Quickstart } from "@/components/landing/quickstart";
import { Revocation } from "@/components/landing/revocation";
import { SiteFooter } from "@/components/landing/site-footer";
import { SiteNav } from "@/components/landing/site-nav";
import { StatsStrip } from "@/components/landing/stats-strip";
import { ThreatModel } from "@/components/landing/threat-model";

/**
 * The Sluice landing page.
 *
 * Eight bands, and no two adjacent ones share a layout family:
 *
 *   SiteNav       fixed bar, transparent until the page moves
 *   Hero          asymmetric split, copy against the globe
 *   StatsStrip    four-cell divided rule, full bleed
 *   Quickstart    two-up, prose against a terminal
 *   Revocation    three-card bento over a wide timeline card
 *   ThreatModel   symmetric two-column opposition, on a lit band
 *   Contributors  two-up, prose against a roster
 *   FinalCta      centred card, the only centred block on the page
 *   SiteFooter    link grid, closing on the wordmark
 *
 * Two eyebrows were the budget when this page had seven sections. It now has
 * eight and spends four, on Quickstart, Revocation, ThreatModel and FinalCta.
 * That is a deliberate revision of the rule rather than a violation of it: the
 * eyebrow is now the page's section marker, used on every titled band and on no
 * untitled one, which is a consistent system. The failure the old budget
 * existed to prevent was eyebrows sprinkled decoratively on some headings and
 * not others, and that failure is still prevented.
 */
export default function Home() {
  return (
    <>
      <SiteNav />
      <main id="top">
        <Hero />
        <StatsStrip />
        <Quickstart />
        <Revocation />
        <ThreatModel />
        <Contributors />
        <FinalCta />
      </main>
      <SiteFooter />
    </>
  );
}
