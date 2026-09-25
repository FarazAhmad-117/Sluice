import type { Metadata } from "next";

import { FinalCta } from "@/components/landing/final-cta";
import { Hero } from "@/components/landing/hero";
import { KillSwitch } from "@/components/landing/kill-switch";
import { MechanismSteps } from "@/components/landing/mechanism-steps";
import { OpenSourceProof } from "@/components/landing/open-source-proof";
import { Problem } from "@/components/landing/problem";
import { SiteFooter } from "@/components/landing/site-footer";
import { SiteHeader } from "@/components/landing/site-header";
import { StatsStrip } from "@/components/landing/stats-strip";
import { WhatsReal } from "@/components/landing/whats-real";

/**
 * The homepage.
 *
 * ITS READER is a senior developer with a live `.env` problem, arriving
 * sceptical and short of time. Its job is to win two concessions in this order:
 * this solves something I deal with, and this does one thing nobody else does.
 * Everything here serves "should I adopt this" and nothing serves "should I
 * contribute to this". Open source is one page, linked once, as evidence that
 * the project is alive.
 *
 * WHAT EACH BAND HAS TO PROVE, and the layout family it uses, none of which
 * repeats next to itself:
 *
 *   SiteNav          fixed bar        the shape they already know
 *   Hero             asymmetric split this is for me, and it is different
 *   StatsStrip       divided rule     the numbers are checkable in a minute
 *   Problem          card grid        these failures are real, not invented
 *   KillSwitch       split + bento    the difference, demonstrated live
 *   MechanismSteps   two-up ledger    simple to state, specific to check
 *   WhatsReal        two panels       we tell you the bad news first
 *   OpenSourceProof  single rule      the project is alive. One line.
 *   FinalCta         centred card     one honest next action
 *   SiteFooter       link grid        everything the header does not carry
 *
 * THE CALL TO ACTION APPEARS TWICE ON THIS PAGE, in the navigation and in the
 * hero, and a third time in the closing card. NOTHING BETWEEN THE HERO AND THAT
 * CARD ASKS FOR ANYTHING. Sections four and six carry text links to deeper
 * pages, which is not the same act: a link offers, a button asks. A page that
 * asks every screen is negotiating, and a reader who is being negotiated with
 * stops reading.
 */

export const metadata: Metadata = {
  title: "Sluice: secrets you can take back",
  description:
    "Zero-knowledge environment variables for Node, with signed revocation that reaches processes already running. Pre-release, Apache-2.0, not third-party audited yet.",
};

export default function Home() {
  return (
    <>
      <SiteHeader />
      <main id="top">
        <Hero />
        <StatsStrip />
        <Problem />
        <KillSwitch />
        <MechanismSteps />
        <WhatsReal />
        <OpenSourceProof />
        <FinalCta />
      </main>
      <SiteFooter />
    </>
  );
}
