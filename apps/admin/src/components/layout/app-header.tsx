import { useQuery } from "convex/react";
import { Link, useMatch, useNavigate } from "react-router";
import { api } from "@convex/_generated/api";
import { IconChevronUpDown, IconPlus } from "@/components/ui/icons";
import { Menu, MenuDivider, MenuItem, MenuLink, MenuNote, MenuRadio } from "@/components/ui/menu";
import { focusRing } from "@/components/ui/styles";
import { useAuth } from "@/lib/auth/auth-context";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";
import { useTheme } from "@/lib/theme";
import type { ThemeChoice } from "@/lib/theme";

/**
 * THE DASHBOARD HEADER: WHERE YOU ARE, AND WHO YOU ARE.
 *
 * Left, a breadcrumb that is also the navigation: the `sluice` wordmark (home),
 * the org switcher, and on a project route the project switcher. Right, the
 * account menu. No search box and no Docs link: neither exists yet, and a
 * control that goes nowhere is worse than no control.
 *
 * At phone width the org switcher steps aside on project routes, so the crumb
 * that matters (the project) keeps its room; every label truncates rather than
 * pushing the row wider than the screen.
 */

const SLASH = (
  <span aria-hidden="true" className="shrink-0 text-xl font-light text-text-faint">
    /
  </span>
);

const SWITCHER =
  "flex min-h-11 min-w-0 cursor-pointer items-center gap-2 rounded-input bg-transparent px-2 font-medium text-text-primary transition-colors hover:bg-surface-card";

function OrgTile({ name }: { readonly name: string }) {
  return (
    <span
      aria-hidden="true"
      className="flex size-5 shrink-0 items-center justify-center rounded-full bg-brand-solid text-[11px] font-bold text-text-on-brand-solid"
    >
      {name.slice(0, 1).toUpperCase()}
    </span>
  );
}

function OrgSwitcher({ hideOnPhone }: { readonly hideOnPhone: boolean }) {
  const { org, orgs, setOrg } = useCurrentOrg();
  const navigate = useNavigate();
  if (org === null || orgs === undefined) {
    return <span className="h-5 w-24 animate-pulse rounded-input bg-surface-card motion-reduce:animate-none" />;
  }
  return (
    <div className={`${hideOnPhone ? "hidden sm:flex" : "flex"} min-w-0 items-center gap-3`}>
      {SLASH}
      <Menu
        label={`Organisation: ${org.name}`}
        triggerClassName={SWITCHER}
        trigger={
          <>
            <OrgTile name={org.name} />
            <span className="truncate">{org.name}</span>
            <IconChevronUpDown className="size-3.5 shrink-0 text-text-muted" />
          </>
        }
      >
        <MenuNote>Organisations</MenuNote>
        {orgs.map((row) => (
          <MenuRadio
            key={row.orgId}
            checked={row.orgId === org.orgId}
            onSelect={() => {
              setOrg(row.orgId);
              void navigate("/projects");
            }}
          >
            <OrgTile name={row.name} />
            <span className="truncate">{row.name}</span>
          </MenuRadio>
        ))}
      </Menu>
    </div>
  );
}

function ProjectSwitcher({ slug }: { readonly slug: string }) {
  const { session } = useAuth();
  const { org } = useCurrentOrg();
  const navigate = useNavigate();
  const projects = useQuery(
    api.projects.listProjects,
    session === null || org === null ? "skip" : { sessionToken: session.sessionToken, orgId: org.orgId },
  );
  const current = projects?.find((project) => project.slug === slug);
  const label = current?.name ?? slug;

  return (
    <div className="flex min-w-0 items-center gap-3">
      {SLASH}
      <Menu
        label={`Project: ${label}`}
        triggerClassName={SWITCHER}
        trigger={
          <>
            <span className="truncate">{label}</span>
            <IconChevronUpDown className="size-3.5 shrink-0 text-text-muted" />
          </>
        }
      >
        <MenuNote>Projects</MenuNote>
        {(projects ?? []).map((project) => (
          <MenuRadio
            key={project.projectId}
            checked={project.slug === slug}
            onSelect={() => void navigate(`/projects/${project.slug}/secrets`)}
          >
            <span className="truncate">{project.name}</span>
          </MenuRadio>
        ))}
        <MenuDivider />
        <MenuLink to="/projects/new">
          <IconPlus className="size-3.5 text-text-muted" />
          New project
        </MenuLink>
      </Menu>
    </div>
  );
}

const THEMES: readonly { value: ThemeChoice; label: string }[] = [
  { value: "system", label: "System theme" },
  { value: "light", label: "Light theme" },
  { value: "dark", label: "Dark theme" },
];

function AccountMenu() {
  const { session, logout } = useAuth();
  const { choice, setChoice } = useTheme();
  const navigate = useNavigate();
  const email = session?.email ?? "";
  return (
    <Menu
      label="Account"
      align="end"
      triggerClassName="flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-full bg-transparent"
      trigger={
        <span className="flex size-8 items-center justify-center rounded-full border border-hairline-strong bg-surface-card font-semibold text-text-primary">
          {email.slice(0, 1).toUpperCase() || "?"}
        </span>
      }
    >
      <MenuNote>
        Signed in as <span className="text-text-primary">{email}</span>
      </MenuNote>
      <MenuDivider />
      {THEMES.map((theme) => (
        <MenuRadio
          key={theme.value}
          checked={choice === theme.value}
          onSelect={() => setChoice(theme.value)}
        >
          {theme.label}
        </MenuRadio>
      ))}
      <MenuDivider />
      <MenuItem
        onSelect={() => {
          void logout().then(() => navigate("/login", { replace: true }));
        }}
      >
        Sign out
      </MenuItem>
    </Menu>
  );
}

export function AppHeader() {
  const project = useMatch("/projects/:projectSlug/*");
  const creating = useMatch("/projects/new");
  const slug = creating === null ? (project?.params.projectSlug ?? null) : null;

  return (
    <header className="flex h-[60px] shrink-0 items-center justify-between gap-3 px-4 sm:px-6">
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1 sm:gap-2">
        <Link
          to="/projects"
          className={`flex min-h-11 shrink-0 items-center rounded-input px-1 text-lg font-bold tracking-[-0.03em] text-text-primary no-underline ${focusRing}`}
        >
          sluice
        </Link>
        <OrgSwitcher hideOnPhone={slug !== null} />
        {slug === null ? null : <ProjectSwitcher slug={slug} />}
        {creating === null ? null : (
          <div className="flex min-w-0 items-center gap-3">
            {SLASH}
            <span aria-current="page" className="truncate px-2 text-text-muted">
              New project
            </span>
          </div>
        )}
      </nav>
      <AccountMenu />
    </header>
  );
}
