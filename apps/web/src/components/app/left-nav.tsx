"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { Id } from "@convex/_generated/dataModel";
import { Eyebrow, StatusPill, focusRing, quietButton, textLink } from "@/components/app/controls";
import {
  NewEnvironmentForm,
  NewOrgForm,
  NewProjectForm,
} from "@/components/app/create-forms";
import { ThemeToggle } from "@/components/app/theme-toggle";
import { useAuth } from "@/lib/auth/auth-context";

/**
 * THE LEFT PANE.
 *
 * From the approved dashboard reference: a filter at the top, grouped sections
 * in the middle, the profile pinned to the bottom. Environments are nested
 * BENEATH THE ACTIVE PROJECT and nowhere else, which is the part of the
 * reference that does the real work: a flat list of every environment in the
 * org tells you nothing about which project you are in, and a tree that expands
 * every project at once is a tree nobody can scan.
 *
 * THE FILTER IS A FILTER, NOT A COMMAND PALETTE. The design direction calls for
 * command-palette search. A palette that only filters the list already on
 * screen would be a palette in name, and one that actually jumps to actions
 * needs actions to jump to. This ships the honest half: a text filter over
 * projects and environments, with the keyboard focus behaviour of an ordinary
 * input. The palette is named in the report as not built.
 */

export interface OrgSummary {
  readonly orgId: Id<"orgs">;
  readonly name: string;
  readonly slug: string;
  readonly role: "owner" | "admin" | "member";
}

export interface ProjectSummary {
  readonly projectId: Id<"projects">;
  readonly name: string;
  readonly slug: string;
}

export interface EnvironmentSummary {
  readonly environmentId: Id<"environments">;
  readonly name: string;
  readonly pdkVersion: number;
  readonly epoch: number;
}

export interface LeftNavProps {
  readonly orgs: readonly OrgSummary[] | undefined;
  readonly projects: readonly ProjectSummary[] | undefined;
  readonly environments: readonly EnvironmentSummary[] | undefined;
  readonly activeOrgId: Id<"orgs"> | null;
  readonly activeProjectId: Id<"projects"> | null;
  readonly activeEnvironmentId: Id<"environments"> | null;
  onSelectOrg(orgId: Id<"orgs">): void;
  onSelectProject(projectId: Id<"projects">): void;
  onSelectEnvironment(environmentId: Id<"environments">): void;
}

/** Active nav uses `bg-brand-subtle` with `text-brand`, never `bg-brand-solid`. */
function rowClass(active: boolean): string {
  return `flex w-full cursor-pointer items-center justify-between gap-2 rounded-input px-2.5 py-2 text-left text-base transition-colors ${
    active
      ? "bg-brand-subtle text-brand"
      : "text-text-primary hover:bg-brand-subtle hover:text-brand"
  } ${focusRing}`;
}

export function LeftNav({
  orgs,
  projects,
  environments,
  activeOrgId,
  activeProjectId,
  activeEnvironmentId,
  onSelectOrg,
  onSelectProject,
  onSelectEnvironment,
}: LeftNavProps) {
  const { session, locked, logout } = useAuth();
  const [filter, setFilter] = useState("");

  const needle = filter.trim().toLowerCase();

  const visibleProjects = useMemo(() => {
    if (projects === undefined) return undefined;
    if (needle.length === 0) return projects;
    return projects.filter(
      (project) =>
        project.name.toLowerCase().includes(needle) || project.slug.toLowerCase().includes(needle),
    );
  }, [projects, needle]);

  const visibleEnvironments = useMemo(() => {
    if (environments === undefined) return undefined;
    if (needle.length === 0) return environments;
    return environments.filter((environment) => environment.name.toLowerCase().includes(needle));
  }, [environments, needle]);

  return (
    <nav
      aria-label="Projects and environments"
      className="flex h-full min-h-0 flex-col gap-4 border-hairline bg-surface-panel p-3 lg:border-r"
    >
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-2">
          <Link href="/" className={`font-mono text-base font-medium ${textLink}`}>
            sluice
          </Link>
          {locked ? <StatusPill tone="warning">locked</StatusPill> : null}
        </div>
        <input
          type="search"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder="Filter projects and environments"
          aria-label="Filter projects and environments"
          className={`w-full rounded-input border border-hairline bg-surface-base px-3 py-2.5 text-base text-text-primary placeholder:text-text-muted ${focusRing}`}
        />
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto">
        <section className="flex flex-col gap-2">
          <Eyebrow>Organisations</Eyebrow>
          {orgs === undefined ? (
            <p className="px-2.5 text-base text-text-muted">Loading</p>
          ) : orgs.length === 0 ? (
            <p className="px-2.5 text-base text-text-muted">
              No organisations yet. Create one below to get a project, an environment and a place
              to put a secret.
            </p>
          ) : (
            <ul className="flex flex-col gap-0.5">
              {orgs.map((org) => (
                <li key={org.orgId}>
                  <button
                    type="button"
                    onClick={() => onSelectOrg(org.orgId)}
                    className={rowClass(org.orgId === activeOrgId)}
                  >
                    <span className="truncate font-mono">{org.slug}</span>
                    <span className="shrink-0 font-mono text-xs text-text-muted">{org.role}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          {/* Always present, not only when the list is empty. A second org is
              an ordinary thing to want, and a control that appears only on an
              empty list is a control nobody finds again. */}
          {orgs === undefined ? null : <NewOrgForm onCreated={onSelectOrg} />}
        </section>

        <section className="flex flex-col gap-2">
          <Eyebrow>Projects</Eyebrow>
          {activeOrgId === null ? (
            <p className="px-2.5 text-base text-text-muted">Pick an organisation.</p>
          ) : visibleProjects === undefined ? (
            <p className="px-2.5 text-base text-text-muted">Loading</p>
          ) : visibleProjects.length === 0 ? (
            <p className="px-2.5 text-base text-text-muted">
              {needle.length > 0 ? "Nothing matches that filter." : "No projects in this org yet."}
            </p>
          ) : (
            <ul className="flex flex-col gap-0.5">
              {visibleProjects.map((project) => {
                const active = project.projectId === activeProjectId;
                return (
                  <li key={project.projectId} className="flex flex-col">
                    <button
                      type="button"
                      onClick={() => onSelectProject(project.projectId)}
                      className={rowClass(active)}
                      aria-expanded={active}
                    >
                      <span className="truncate font-mono">{project.slug}</span>
                    </button>

                    {/* Environments live here, under the ACTIVE project only.
                        A nested list under every project would be a tree that
                        cannot be scanned. */}
                    {active ? (
                      <ul className="mt-0.5 ml-3 flex flex-col gap-0.5 border-l border-hairline pl-2">
                        {visibleEnvironments === undefined ? (
                          <li className="px-2.5 py-1.5 text-base text-text-muted">Loading</li>
                        ) : visibleEnvironments.length === 0 ? (
                          <li className="px-2.5 py-1.5 text-base text-text-muted">
                            No environments yet.
                          </li>
                        ) : (
                          visibleEnvironments.map((environment) => (
                            <li key={environment.environmentId}>
                              <button
                                type="button"
                                onClick={() => onSelectEnvironment(environment.environmentId)}
                                className={rowClass(
                                  environment.environmentId === activeEnvironmentId,
                                )}
                              >
                                <span className="truncate font-mono">{environment.name}</span>
                                <span className="shrink-0 font-mono text-xs text-text-muted">
                                  pdk v{environment.pdkVersion}
                                </span>
                              </button>
                            </li>
                          ))
                        )}
                        {/* Under the active project and nowhere else, because
                            an environment belongs to one project and a control
                            that floats above the tree has to ask which. */}
                        <li className="pt-1">
                          <NewEnvironmentForm
                            projectId={project.projectId}
                            onCreated={onSelectEnvironment}
                          />
                        </li>
                      </ul>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}

          {activeOrgId === null ? null : (
            // Selecting the new project immediately is the point: creating
            // something and then having to find it in a list is a form that is
            // not finished.
            <NewProjectForm orgId={activeOrgId} onCreated={onSelectProject} />
          )}
        </section>
      </div>

      {/* Profile, pinned to the bottom, as the reference does. */}
      <div className="flex flex-col gap-3 border-t border-hairline pt-3">
        <ThemeToggle />
        <p className="truncate font-mono text-sm text-text-muted" title={session?.email ?? ""}>
          {session?.email ?? ""}
        </p>
        <button type="button" onClick={() => void logout()} className={quietButton}>
          Sign out
        </button>
      </div>
    </nav>
  );
}
