import { createContext, useContext } from "react";
import type { ProjectSecrets } from "@/lib/secrets/use-project-secrets";

/**
 * THE PROJECT ON SCREEN, LOADED ONCE FOR THE WHOLE SHELL.
 *
 * On a `/projects/:slug/...` route the shell calls `useProjectSecrets` once and
 * hands the result down: the sidebar (counts, environments), the command
 * palette (secret keys) and every project page read the same listings, the
 * same opened keys and the same opened names. Navigating between Overview,
 * Secrets and Compare therefore never re-opens a key or re-decrypts a name.
 *
 * `null` off a project route.
 */
export interface ProjectScope {
  readonly slug: string;
  readonly data: ProjectSecrets;
}

/** What "Add secret" opens with: a target environment and a key, for "Add here". */
export interface AddRequest {
  /** The environment the drawer treats as current. Defaults to the selected one. */
  readonly environmentId?: string;
  /** Prefills the key, and starts on "Only <environment>". */
  readonly name?: string;
}

/**
 * The one add-secret drawer, owned by the shell so every project page opens
 * the same one, and the rows it just wrote, for a page to mark.
 */
export interface ProjectActions {
  openAdd(request?: AddRequest): void;
  /** Secret ids written by the last add, for a few seconds. */
  readonly highlight: ReadonlySet<string>;
}

export const ProjectActionsContext = createContext<ProjectActions | null>(null);

export function useProjectActions(): ProjectActions {
  const value = useContext(ProjectActionsContext);
  if (value === null) throw new Error("useProjectActions must be used inside the app shell");
  return value;
}

export const ProjectContext = createContext<ProjectScope | null>(null);

export function useProjectScope(): ProjectScope | null {
  return useContext(ProjectContext);
}

/** For a page that only renders on a project route. */
export function useProject(): ProjectScope {
  const value = useContext(ProjectContext);
  if (value === null) throw new Error("useProject must be used on a project route");
  return value;
}
