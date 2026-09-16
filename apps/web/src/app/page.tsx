import { Contributors } from "@/components/landing/contributors";
import { Hero } from "@/components/landing/hero";
import { Quickstart } from "@/components/landing/quickstart";
import { Revocation } from "@/components/landing/revocation";
import { SiteFooter } from "@/components/landing/site-footer";
import { SiteNav } from "@/components/landing/site-nav";
import { ThreatModel } from "@/components/landing/threat-model";

/**
 * The Sluice landing page.
 *
 * Seven sections, seven layout families, in this order:
 *
 *   SiteNav       horizontal bar, two rows below 768px
 *   Hero          asymmetric split, copy against the particle field slot
 *   Quickstart    centred single column around one mono block
 *   Revocation    three-row ledger, plus an empty recording slot
 *   ThreatModel   symmetric two-column opposition on a raised surface
 *   Contributors  hairline roster list
 *   SiteFooter    link grid
 *
 * No two of them share a family and no two consecutive ones are a split.
 * Two eyebrows are spent, on Revocation and ThreatModel, against a budget of
 * three.
 *
 * There is no sponsors section. GitHub Sponsors is not enabled for this
 * account, there is no FUNDING.yml and no Open Collective, so the section
 * would have been an invitation with nowhere to go, and the alternative,
 * placeholder avatars, is a worse lie than an absent section.
 */
export default function Home() {
  return (
    <>
      <SiteNav />
      <main>
        <Hero />
        <Quickstart />
        <Revocation />
        <ThreatModel />
        <Contributors />
      </main>
      <SiteFooter />
    </>
  );
}
