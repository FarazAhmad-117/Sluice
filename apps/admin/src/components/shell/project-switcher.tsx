import { useQuery } from "convex/react";
import { useNavigate } from "react-router";
import { api } from "@convex/_generated/api";
import { IconChevronUpDown, IconPlus } from "@/components/ui/icons";
import { Menu, MenuDivider, MenuLink, MenuNote, MenuRadio } from "@/components/ui/menu";
import { useAuth } from "@/lib/auth/auth-context";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";

/**
 * THE PROJECT ON SCREEN, AND A MENU TO JUMP TO ANOTHER.
 *
 * Another project opens on its Overview. The label falls back to the slug in
 * the URL while the project list loads, so the row never jumps in height.
 */

export function ProjectTile({ name, size = "sm" }: { readonly name: string; readonly size?: "sm" | "lg" }) {
  return (
    <span
      aria-hidden="true"
      className={`flex shrink-0 items-center justify-center border border-hairline-strong bg-surface-base font-semibold text-text-primary ${
        size === "sm" ? "size-[22px] rounded-[6px] text-xs" : "size-12 rounded-card bg-surface-card text-xl"
      }`}
    >
      {name.slice(0, 1).toUpperCase()}
    </span>
  );
}

export function ProjectSwitcher({ slug }: { readonly slug: string }) {
  const { session } = useAuth();
  const { org } = useCurrentOrg();
  const navigate = useNavigate();
  const projects = useQuery(
    api.projects.listProjects,
    session === null || org === null ? "skip" : { sessionToken: session.sessionToken, orgId: org.orgId },
  );
  const label = projects?.find((project) => project.slug === slug)?.name ?? slug;

  return (
    <Menu
      label={`Project: ${label}`}
      triggerClassName="flex min-h-11 w-full cursor-pointer items-center gap-2.5 rounded-input border border-hairline bg-surface-card px-2 text-left text-text-primary transition-colors hover:border-hairline-strong lg:min-h-10 lg:pointer-coarse:min-h-11"
      trigger={
        <>
          <ProjectTile name={label} />
          <span className="min-w-0 grow truncate font-medium">{label}</span>
          <IconChevronUpDown className="size-3.5 shrink-0 text-text-muted" />
        </>
      }
    >
      <MenuNote>Projects</MenuNote>
      {(projects ?? []).map((project) => (
        <MenuRadio
          key={project.projectId}
          checked={project.slug === slug}
          onSelect={() => void navigate(`/projects/${project.slug}`)}
        >
          <ProjectTile name={project.name} />
          <span className="truncate">{project.name}</span>
        </MenuRadio>
      ))}
      <MenuDivider />
      <MenuLink to="/projects">All projects</MenuLink>
      <MenuLink to="/projects/new">
        <IconPlus className="size-3.5 text-text-muted" />
        New project
      </MenuLink>
    </Menu>
  );
}
