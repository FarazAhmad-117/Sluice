import { AppShell } from "@/components/shell/app-shell";
import { useAuth } from "@/lib/auth/auth-context";
import { CONVEX_URL_MISSING_MESSAGE } from "@/lib/convex-url";
import { CurrentOrgContext, useCurrentOrgState } from "@/lib/orgs/use-current-org";
import { SITE_URL } from "@/lib/site-url";
import { focusRing } from "@/components/ui/styles";

/**
 * EVERY SIGNED-IN SCREEN, INSIDE THE APP SHELL (sidebar and page).
 *
 * The page goes through the unlock gate inside the shell, so no screen renders
 * while the vault is locked. The current org is held here, once, and read by
 * the sidebar and the pages through `useCurrentOrg`.
 *
 * A build with no Convex URL renders a sentence instead: every query would
 * otherwise reject, which reads as a broken product rather than as a missing
 * environment variable.
 */
export function AppLayout() {
  const { configured } = useAuth();
  if (!configured) {
    return (
      <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-5 bg-surface-base px-5 text-text-primary">
        <p role="alert" className="max-w-xl">
          {CONVEX_URL_MISSING_MESSAGE}
        </p>
        <a href={SITE_URL} className={`rounded-input text-brand underline underline-offset-4 ${focusRing}`}>
          Back to the site
        </a>
      </main>
    );
  }
  return <ConfiguredLayout />;
}

function ConfiguredLayout() {
  const currentOrg = useCurrentOrgState();
  return (
    <CurrentOrgContext.Provider value={currentOrg}>
      <AppShell />
    </CurrentOrgContext.Provider>
  );
}
