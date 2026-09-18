import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sluice",
  description:
    "Zero-knowledge environment variable delivery with instant signed revocation.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // The landing page is dark locked, so the server always emits `dark`. The
    // DASHBOARD is dual theme: `lib/theme.tsx` ships a blocking inline script
    // that rewrites this attribute from the viewer's system preference before
    // the first paint, which is the only way to avoid a dark flash on a light
    // machine. That mutation lands between the server render and hydration, so
    // React logs a mismatch on every dashboard load without the suppression
    // below. It covers this one element's attributes, not its subtree.
    <html
      lang="en"
      data-theme="dark"
      suppressHydrationWarning
      className={`${GeistSans.variable} ${GeistMono.variable} antialiased`}
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
        className="min-h-[100dvh] bg-surface-base text-text-primary"
      >
        {children}
      </body>
    </html>
  );
}
