import { useMemo, useState } from "react";
import { Outlet, useLocation, useMatch } from "react-router";
import { Drawer } from "@/components/ui/drawer";
import { focusRing } from "@/components/ui/styles";
import { UnlockGate } from "@/components/layout/unlock-gate";
import { ProjectContext } from "@/lib/projects/project-context";
import type { ProjectScope } from "@/lib/projects/project-context";
import { useProjectSecrets } from "@/lib/secrets/use-project-secrets";
import { ShellContext, useAnnouncer } from "@/lib/shell/shell-context";
import type { Shell } from "@/lib/shell/shell-context";
import { DESKTOP, useMediaQuery } from "@/lib/use-media-query";
import { SidebarContent } from "./sidebar";

/**
 * EVERY SIGNED-IN PAGE: THE SIDEBAR, AND THE PAGE BESIDE IT.
 *
 * At 1024px and up the sidebar is a 240px column that stays put while the page
 * scrolls. Below that it is a 300px drawer from the left, opened by the menu
 * button in the page header; it closes on Escape, on the backdrop, and on any
 * navigation.
 *
 * On a project route the project's listings, keys and names are loaded here,
 * once, and shared through {@link ProjectContext} (see `project-context.ts`).
 *
 * The unlock gate covers the page, not the shell: the sidebar needs no key
 * (project and environment names and row counts are not secret), so a locked
 * vault still shows where you are.
 */
export function AppShell() {
  const project = useMatch("/projects/:projectSlug/*");
  const creating = useMatch("/projects/new");
  const slug = creating === null ? (project?.params.projectSlug ?? null) : null;
  const data = useProjectSecrets(slug);
  return <ShellFrame scope={slug === null ? null : { slug, data }} />;
}

/** The shell around a given project scope, with no queries of its own. */
export function ShellFrame({ scope }: { readonly scope: ProjectScope | null }) {
  const [announcement, announce] = useAnnouncer();
  const location = useLocation();
  const desktop = useMediaQuery(DESKTOP);
  // The drawer is open for the location it was opened at. Any navigation is a
  // new location, so following a link closes it with no effect to run; so does
  // growing past the breakpoint where the sidebar is a column again.
  const [navOpenAt, setNavOpenAt] = useState<string | null>(null);
  const navOpen = navOpenAt === location.key && !desktop;
  const locationKey = location.key;

  const shell = useMemo(
    (): Shell => ({ openNav: () => setNavOpenAt(locationKey), announce }),
    [announce, locationKey],
  );

  return (
    <ShellContext.Provider value={shell}>
      <ProjectContext.Provider value={scope}>
        <div className="flex min-h-[100dvh] bg-surface-base text-text-body">
          <a
            href="#main"
            className={`sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-input focus:bg-surface-card focus:px-3 focus:py-2 focus:text-text-primary ${focusRing}`}
          >
            Skip to content
          </a>
          <aside
            aria-label="Sidebar"
            className="sticky top-0 hidden h-[100dvh] w-60 shrink-0 flex-col overflow-y-auto border-r border-hairline bg-surface-panel px-2.5 py-3 lg:flex"
          >
            <SidebarContent placement="rail" />
          </aside>
          <main id="main" tabIndex={-1} className="flex min-w-0 grow flex-col outline-none">
            <UnlockGate>
              <Outlet />
            </UnlockGate>
          </main>
        </div>
        <Drawer side="left" open={navOpen} onClose={() => setNavOpenAt(null)} title="Navigation">
          <div className="flex grow flex-col overflow-y-auto px-2.5 py-3">
            <SidebarContent placement="drawer" />
          </div>
        </Drawer>
        {/* The app's one live region: the latest result only, cleared after a few seconds. */}
        <p role="status" aria-live="polite" className="sr-only">
          {announcement}
        </p>
      </ProjectContext.Provider>
    </ShellContext.Provider>
  );
}
