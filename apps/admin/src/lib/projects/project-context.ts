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
