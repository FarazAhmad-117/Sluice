import type { ReactNode } from "react";
import { Eyebrow, textLink } from "@/components/app/controls";
import { ThemeToggle } from "@/components/app/theme-toggle";
import { useAuth } from "@/lib/auth/auth-context";
import { CONVEX_URL_MISSING_MESSAGE } from "@/lib/convex-url";
import { SITE_URL } from "@/lib/site-url";

/**
 * The frame both credential pages share: one column, centred, with the theme
 * control in the corner and the footer note that the whole product rests on.
 *
 * `min-h-[100dvh]` rather than `h-screen`, because `100vh` on mobile Safari is
 * the height of the viewport WITHOUT the browser chrome, so a full-height page
 * is taller than the space it has and the bottom of the form ends up under the
 * address bar.
 */
export function AuthShell({
  title,
  lead,
  children,
  footer,
}: {
  title: string;
  lead: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  const { configured } = useAuth();

  return (
    <div className="flex min-h-[100dvh] flex-col bg-surface-base text-text-primary">
      <header className="flex items-center justify-between gap-4 border-b border-hairline px-5 py-4 sm:px-8">
        {/* The marketing site, which is a different application on a
            different origin. See `lib/site-url.ts`. */}
        <a href={SITE_URL} className={`font-mono text-base font-medium ${textLink}`}>
          sluice
        </a>
        <ThemeToggle />
      </header>

      <main className="flex flex-1 items-start justify-center px-5 py-10 sm:px-8 sm:py-14">
        <div className="flex w-full max-w-md flex-col gap-6">
          <div className="flex flex-col gap-3">
            <Eyebrow>Zero knowledge</Eyebrow>
            <h1 className="text-[1.75rem] leading-[1.15] font-medium tracking-[-0.02em] text-text-primary sm:text-4xl">
              {title}
            </h1>
            <p className="text-base text-text-muted">{lead}</p>
          </div>

          {configured ? null : (
            <p
              role="alert"
              className="rounded-input border border-status-danger/50 bg-status-danger/10 px-3 py-2.5 text-base text-text-primary"
            >
              {CONVEX_URL_MISSING_MESSAGE}
            </p>
          )}

          {children}

          <div className="border-t border-hairline pt-5 text-base text-text-muted">{footer}</div>
        </div>
      </main>
    </div>
  );
}
