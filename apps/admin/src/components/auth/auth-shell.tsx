import type { ReactNode } from "react";
import { Callout } from "@/components/ui/feedback";
import { focusRing } from "@/components/ui/styles";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { useAuth } from "@/lib/auth/auth-context";
import { CONVEX_URL_MISSING_MESSAGE } from "@/lib/convex-url";
import { SITE_URL } from "@/lib/site-url";

/**
 * The frame both credential pages share: the wordmark top left, a theme
 * control top right, and one 400px card in the middle with a heading, one
 * line of lead, the form, and a footer link to the other page.
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
  readonly title: string;
  readonly lead: string;
  readonly children: ReactNode;
  readonly footer: ReactNode;
}) {
  const { configured } = useAuth();

  return (
    <div className="flex min-h-[100dvh] flex-col bg-surface-base text-text-body">
      <header className="flex h-[60px] items-center justify-between gap-4 px-4 sm:px-6">
        {/* The marketing site, which is a different application on a
            different origin. See `lib/site-url.ts`. */}
        <a
          href={SITE_URL}
          className={`flex min-h-11 items-center rounded-input px-1 text-lg font-bold tracking-[-0.03em] text-text-primary no-underline ${focusRing}`}
        >
          sluice
        </a>
        <ThemeToggle />
      </header>

      <main className="flex flex-1 items-start justify-center px-4 pt-6 pb-12 sm:items-center sm:px-6 sm:pt-0">
        <div className="flex w-full max-w-[400px] flex-col gap-5">
          <div className="flex flex-col gap-6 rounded-card border border-hairline bg-surface-panel p-6 sm:p-8">
            <div className="flex flex-col gap-2">
              <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">{title}</h1>
              <p className="m-0 text-sm text-text-muted">{lead}</p>
            </div>

            {configured ? null : (
              <Callout tone="danger" role="alert" title="This build is not connected">
                {CONVEX_URL_MISSING_MESSAGE}
              </Callout>
            )}

            {children}
          </div>
          <div className="text-center text-sm text-text-muted">{footer}</div>
        </div>
      </main>
    </div>
  );
}
