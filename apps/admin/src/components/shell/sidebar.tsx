import type { ReactNode } from "react";
import { NavLink, useLocation } from "react-router";
import {
  IconActivity,
  IconBook,
  IconColumns,
  IconExternal,
  IconFolder,
  IconKey,
  IconLayers,
  IconOverview,
  IconPlus,
  IconSearch,
  IconSettings,
  IconTicket,
  IconUsers,
} from "@/components/ui/icons";
import { compactHeight, focusRing } from "@/components/ui/styles";
import { useProjectScope } from "@/lib/projects/project-context";
import { countProjectSecrets } from "@/lib/projects/project-overview";
import type { ProjectSecrets } from "@/lib/secrets/use-project-secrets";
import { useShell } from "@/lib/shell/shell-context";
import { AccountMenu } from "./account-menu";
import { OrgSwitcher } from "./org-switcher";
import { ProjectSwitcher } from "./project-switcher";

/**
 * THE SIDEBAR, AS A 240PX COLUMN ON A DESKTOP AND INSIDE THE PHONE DRAWER.
 *
 * Top to bottom: the org switcher; (F6) search; on a project route the
 * project switcher, the project's pages, and its environments; at the bottom
 * Docs and the account.
 *
 * A page that does not exist yet is listed, muted, with a "Soon" badge, and
 * is not a link: `aria-disabled` on a link role with no `href`, so a screen
 * reader says it is unavailable and nothing navigates to a dead route.
 *
 * Every count is a count of rows the server listed, never a guess: while a
 * listing loads the count is absent, and a count that cannot be made (a
 * listing failed) is absent too rather than wrong.
 */

const DOCS_URL = "https://github.com/FarazAhmad-117/Sluice#readme";

const ROW = `flex ${compactHeight} items-center gap-2.5 rounded-input px-2.5 text-sm no-underline transition-colors ${focusRing}`;
const ROW_IDLE = "text-text-muted hover:bg-surface-card hover:text-text-primary";
const ROW_ACTIVE = "bg-surface-card font-medium text-text-primary";
const ENV_ROW = `flex min-h-11 items-center gap-2.5 rounded-input px-2.5 text-[13px] no-underline transition-colors lg:min-h-8 lg:pointer-coarse:min-h-11 ${focusRing}`;

function GroupLabel({ children, id, spaced = false }: { readonly children: ReactNode; readonly id: string; readonly spaced?: boolean }) {
  return (
    <span id={id} className={`block px-2.5 pb-1.5 text-xs font-medium text-text-muted ${spaced ? "pt-[18px]" : ""}`}>
      {children}
    </span>
  );
}

/** "⌘K" on a Mac, "Ctrl K" elsewhere: the shortcut the palette actually answers to here. */
function shortcutHint(): string {
  const platform = typeof navigator === "undefined" ? "" : navigator.platform || navigator.userAgent;
  return /Mac|iPhone|iPad/.test(platform) ? "⌘K" : "Ctrl K";
}

export function SearchButton() {
  const { openPalette } = useShell();
  return (
    <button
      type="button"
      onClick={openPalette}
      aria-keyshortcuts="Control+K Meta+K"
      className={`flex ${compactHeight} w-full cursor-pointer items-center gap-2 rounded-input border border-hairline bg-surface-base px-2.5 text-[13px] text-text-muted transition-colors hover:border-hairline-strong hover:text-text-primary ${focusRing}`}
    >
      <IconSearch className="size-3.5 shrink-0" />
      <span className="grow text-left">Search</span>
      <kbd aria-hidden="true" className="hidden font-mono text-[11px] lg:inline">
        {shortcutHint()}
      </kbd>
    </button>
  );
}

export function SoonBadge() {
  return (
    <span className="ml-auto inline-flex h-5 shrink-0 items-center rounded-[5px] border border-hairline px-1.5 text-[11px] font-normal text-text-faint">
      Soon
    </span>
  );
}

function Count({ value }: { readonly value: number | null | undefined }) {
  if (typeof value !== "number") return null;
  return <span className="ml-auto text-xs font-normal text-text-muted">{value}</span>;
}

interface NavEntry {
  readonly label: string;
  readonly icon: ReactNode;
  /** Absent for a page that is not built yet. */
  readonly to?: string;
  readonly end?: boolean;
  readonly count?: number | null | undefined;
}

function NavRow({ entry }: { readonly entry: NavEntry }) {
  if (entry.to === undefined) {
    return (
      <li>
        <span role="link" aria-disabled="true" className={`${ROW} cursor-default text-text-faint`}>
          {entry.icon}
          <span className="truncate">{entry.label}</span>
          <SoonBadge />
        </span>
      </li>
    );
  }
  return (
    <li>
      <NavLink
        to={entry.to}
        end={entry.end ?? false}
        className={({ isActive }) => `${ROW} ${isActive ? ROW_ACTIVE : ROW_IDLE}`}
      >
        {entry.icon}
        <span className="truncate">{entry.label}</span>
        <Count value={entry.count} />
      </NavLink>
    </li>
  );
}

const ICON = "size-4 shrink-0";

function projectSecretCount(data: ProjectSecrets): number | undefined {
  if (data.status !== "ready") return undefined;
  if (data.listings.some((listing) => listing.loading || listing.rows === null)) return undefined;
  return countProjectSecrets(data.listings.map((listing) => listing.rows ?? []));
}

function ProjectNav({ slug, data }: { readonly slug: string; readonly data: ProjectSecrets }) {
  const base = `/projects/${slug}`;
  const entries: NavEntry[] = [
    { label: "Overview", icon: <IconOverview className={ICON} />, to: base, end: true },
    { label: "Secrets", icon: <IconKey className={ICON} />, to: `${base}/secrets`, count: projectSecretCount(data) },
    { label: "Compare", icon: <IconColumns className={ICON} />, to: `${base}/compare` },
    { label: "Environments", icon: <IconLayers className={ICON} /> },
    { label: "Tokens", icon: <IconTicket className={ICON} /> },
    { label: "Activity", icon: <IconActivity className={ICON} />, to: `${base}/activity` },
    { label: "Settings", icon: <IconSettings className={ICON} /> },
  ];
  return (
    <nav aria-label="Project">
      <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
        {entries.map((entry) => (
          <NavRow key={entry.label} entry={entry} />
        ))}
      </ul>
    </nav>
  );
}

function EnvironmentNav({ slug, data }: { readonly slug: string; readonly data: ProjectSecrets }) {
  const location = useLocation();
  const onSecrets = location.pathname === `/projects/${slug}/secrets`;
  const selected = data.status === "ready" ? (data.environment?.environmentId ?? null) : null;

  return (
    <nav aria-labelledby="sidebar-environments">
      <GroupLabel id="sidebar-environments" spaced>
        Environments
      </GroupLabel>
      <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
        {data.status !== "ready"
          ? [0, 1].map((index) => (
              <li key={index} aria-hidden="true" className="flex h-8 items-center gap-2.5 px-2.5">
                <span className="size-1.5 rounded-[2px] bg-surface-card" />
                <span className="h-3 w-24 animate-pulse rounded-input bg-surface-card motion-reduce:animate-none" />
              </li>
            ))
          : data.environments.map((environment) => {
              // The selected environment is read off `?env` by the same hook the
              // page uses, so with no `?env` the default row is the active one.
              const active = onSecrets && selected === environment.environmentId;
              return (
                <li key={environment.environmentId}>
                  <NavLink
                    to={`/projects/${slug}/secrets?env=${encodeURIComponent(environment.name)}`}
                    aria-current={active ? "page" : undefined}
                    className={`${ENV_ROW} ${active ? "text-text-primary" : ROW_IDLE}`}
                  >
                    <span
                      aria-hidden="true"
                      className={`size-1.5 shrink-0 rounded-[2px] ${active ? "bg-brand" : "bg-text-faint"}`}
                    />
                    <span className="min-w-0 truncate">{environment.name}</span>
                    <Count value={data.counts.get(environment.environmentId)} />
                  </NavLink>
                </li>
              );
            })}
        <li>
          <span role="link" aria-disabled="true" className={`${ENV_ROW} cursor-default text-text-faint`}>
            <IconPlus className="size-3.5 shrink-0" strokeWidth={2} />
            <span className="truncate">Add environment</span>
            <SoonBadge />
          </span>
        </li>
      </ul>
    </nav>
  );
}

function OrgNav() {
  const entries: NavEntry[] = [
    { label: "Projects", icon: <IconFolder className={ICON} />, to: "/projects" },
    { label: "Activity", icon: <IconActivity className={ICON} /> },
    { label: "Members", icon: <IconUsers className={ICON} /> },
    { label: "Settings", icon: <IconSettings className={ICON} /> },
  ];
  return (
    <nav aria-label="Organisation">
      <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
        {entries.map((entry) => (
          <NavRow key={entry.label} entry={entry} />
        ))}
      </ul>
    </nav>
  );
}

/**
 * The sidebar's contents. `placement="drawer"` leaves room at the top right
 * for the drawer's close button.
 */
export function SidebarContent({ placement }: { readonly placement: "rail" | "drawer" }) {
  const scope = useProjectScope();

  return (
    <div className="flex min-h-full flex-col gap-0.5">
      <OrgSwitcher reserveEnd={placement === "drawer"} />
      <div className="mt-1 mb-3.5">
        <SearchButton />
      </div>

      {scope === null ? (
        <OrgNav />
      ) : (
        <>
          <GroupLabel id="sidebar-project">Project</GroupLabel>
          <div className="mb-2">
            <ProjectSwitcher slug={scope.slug} />
          </div>
          <ProjectNav slug={scope.slug} data={scope.data} />
          {scope.data.status === "not-found" ? null : <EnvironmentNav slug={scope.slug} data={scope.data} />}
        </>
      )}

      <div className="min-h-6 grow" />
      <a href={DOCS_URL} target="_blank" rel="noreferrer" className={`${ROW} ${ROW_IDLE}`}>
        <IconBook className={ICON} />
        <span className="truncate">Docs</span>
        <IconExternal className="ml-auto size-3.5 shrink-0" />
        <span className="sr-only">(opens in a new tab)</span>
      </a>
      <AccountMenu />
    </div>
  );
}
