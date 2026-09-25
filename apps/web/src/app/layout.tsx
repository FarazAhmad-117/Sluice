import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { Instrument_Serif } from "next/font/google";
import "./globals.css";

/**
 * The headline face.
 *
 * Every competitor in this category sets its headlines in the same UI sans it
 * sets its buttons in, and they are consequently indistinguishable from one
 * another at a glance. An editorial serif is the cheapest available way to not
 * be the seventh of those, and it carries the register the product needs
 * anyway: considered and institutional rather than another launch.
 *
 * One weight, 400, because the face has no others worth having and a faux-bold
 * display serif is worse than no display serif. `display: "swap"` so a slow
 * font never blocks the headline; the fallback is Georgia, which is metrically
 * close enough that the swap does not throw the hero around.
 */
const instrumentSerif = Instrument_Serif({
  subsets: ["latin"],
  weight: "400",
  display: "swap",
  variable: "--font-instrument-serif",
});

/**
 * Every page sets its own title, so the template here only catches a route
 * that forgets to. `default` is what a crawler gets for the root layout itself.
 * Nothing in this description is a claim the site does not make elsewhere.
 */
export const metadata: Metadata = {
  title: {
    default: "Sluice",
    template: "%s",
  },
  description:
    "Zero-knowledge environment variable delivery with signed revocation that reaches running processes. Pre-release, Apache-2.0, not third-party audited yet.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // This site is DARK LOCKED, so the server always emits `dark` and nothing
    // ever rewrites it. The dual-theme half of that decision moved out with the
    // dashboard: `apps/admin` follows the viewer's system preference and ships
    // the blocking pre-paint script that makes it possible.
    //
    // `suppressHydrationWarning` used to sit on this element because that script
    // mutated the attribute between the server render and hydration. There is no
    // such script here any more, so the suppression is gone with it -- if this
    // attribute ever disagrees between server and client again, that is
    // something worth being told about rather than something to hide.
    <html
      lang="en"
      data-theme="dark"
      className={`${GeistSans.variable} ${GeistMono.variable} ${instrumentSerif.variable} antialiased`}
    >
      {/*
        Also suppressed on <body>, because that is where extensions actually
        inject. BitDefender writes `bis_skin_checked` and `bis_register`,
        ColorZilla writes `cz-shortcut-listen`, and React reports every one as
        a hydration mismatch it "won't patch up". None of it is our markup and
        none of it reaches a user without that extension, but the warning
        buries real mismatches in dev, which is the actual cost.
      */}
      <body
        suppressHydrationWarning
        className="min-h-[100dvh] bg-surface-base text-text-body"
      >
        {children}
      </body>
    </html>
  );
}
