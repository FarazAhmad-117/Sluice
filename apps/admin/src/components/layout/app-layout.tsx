import { Outlet, useMatch } from "react-router";
import { useAuth } from "@/lib/auth/auth-context";
import { CONVEX_URL_MISSING_MESSAGE } from "@/lib/convex-url";
import { CurrentOrgContext, useCurrentOrgState } from "@/lib/orgs/use-current-org";
import { SITE_URL } from "@/lib/site-url";
import { focusRing } from "@/components/ui/styles";
import { AppHeader } from "./app-header";
import { OrgTabs, ProjectTabs } from "./project-tabs";
import { UnlockGate } from "./unlock-gate";

/**
 * EVERY SIGNED-IN SCREEN: HEADER, TABS, AND THE PAGE IN A 1120PX COLUMN.
 *
 * The page goes through {@link UnlockGate}, so no screen renders while the
 * vault is locked. The current org is held here, once, and read by the header
 * and the pages through `useCurrentOrg`.
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
  const home = useMatch("/projects");
  const project = useMatch("/projects/:projectSlug/*");
  const creating = useMatch("/projects/new");
  const slug = creating === null ? (project?.params.projectSlug ?? null) : null;

  return (
    <CurrentOrgContext.Provider value={currentOrg}>
      <div className="flex min-h-[100dvh] flex-col bg-surface-base text-text-body">
        <a
          href="#main"
          className={`sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-input focus:bg-surface-card focus:px-3 focus:py-2 focus:text-text-primary ${focusRing}`}
        >
          Skip to content
        </a>
        <AppHeader />
        {home !== null ? <OrgTabs /> : null}
        {slug !== null ? <ProjectTabs slug={slug} /> : null}
        {creating !== null ? <div className="border-b border-hairline" /> : null}
        <main
          id="main"
          tabIndex={-1}
          className="mx-auto box-border flex w-full max-w-[1120px] grow flex-col px-4 outline-none sm:px-6"
        >
          <UnlockGate>
            <Outlet />
          </UnlockGate>
        </main>
      </div>
    </CurrentOrgContext.Provider>
  );
}
