import { useMemo } from "react";
import { useQueries, useQuery } from "convex/react";
import type { RequestForQueries } from "convex/react";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";
import { countProjectSecrets } from "./project-overview";

/**
 * EVERY PROJECT OF THE CURRENT ORG, WITH ITS ENVIRONMENTS AND A SECRET COUNT.
 *
 * Counts come from `listSecrets` per environment, shared rows counted once
 * (see `countProjectSecrets`). Nothing is decrypted: a count needs no key.
 *
 * `useQueries` rather than `useQuery` in a loop, because the number of
 * projects and environments is data; it also reports a refused query as an
 * `Error` value instead of throwing during render, so one environment that
 * cannot be listed costs its project's count, not the whole page.
 */

export interface ProjectCard {
  readonly projectId: Id<"projects">;
  readonly name: string;
  readonly slug: string;
  /** `undefined` while loading. */
  readonly environments: readonly string[] | undefined;
  /** `undefined` while loading, `null` when it could not be counted. */
  readonly secretCount: number | null | undefined;
}

type EnvironmentRow = { environmentId: Id<"environments">; name: string };

export function useProjectOverview(): { readonly projects: readonly ProjectCard[] | undefined } {
  const { session } = useAuth();
  const { org } = useCurrentOrg();
  const sessionToken = session?.sessionToken ?? null;

  const projects = useQuery(
    api.projects.listProjects,
    sessionToken === null || org === null ? "skip" : { sessionToken, orgId: org.orgId },
  );

  const environmentQueries = useMemo(() => {
    const requests: RequestForQueries = {};
    if (sessionToken === null) return requests;
    for (const project of projects ?? []) {
      requests[project.projectId] = {
        query: api.environments.listEnvironments,
        args: { sessionToken, projectId: project.projectId },
      };
    }
    return requests;
  }, [projects, sessionToken]);
  const environmentResults = useQueries(environmentQueries);

  const secretQueries = useMemo(() => {
    const requests: RequestForQueries = {};
    if (sessionToken === null) return requests;
    for (const result of Object.values(environmentResults)) {
      if (!Array.isArray(result)) continue;
      for (const environment of result as EnvironmentRow[]) {
        requests[environment.environmentId] = {
          query: api.secrets.listSecrets,
          args: { sessionToken, environmentId: environment.environmentId },
        };
      }
    }
    return requests;
  }, [environmentResults, sessionToken]);
  const secretResults = useQueries(secretQueries);

  const cards = useMemo(() => {
    if (projects === undefined) return undefined;
    return projects.map((project): ProjectCard => {
      const environments: unknown = environmentResults[project.projectId];
      if (environments instanceof Error) {
        return { ...project, environments: [], secretCount: null };
      }
      if (!Array.isArray(environments)) {
        return { ...project, environments: undefined, secretCount: undefined };
      }
      const rows = environments as EnvironmentRow[];
      let secretCount: number | null | undefined;
      const lists: { shareUid?: string }[][] = [];
      for (const environment of rows) {
        const listed: unknown = secretResults[environment.environmentId];
        if (listed instanceof Error) {
          secretCount = null;
          break;
        }
        if (!Array.isArray(listed)) {
          secretCount = undefined;
          break;
        }
        lists.push(listed as { shareUid?: string }[]);
      }
      if (lists.length === rows.length) secretCount = countProjectSecrets(lists);
      return {
        projectId: project.projectId,
        name: project.name,
        slug: project.slug,
        environments: rows.map((environment) => environment.name),
        secretCount,
      };
    });
  }, [projects, environmentResults, secretResults]);

  return { projects: cards };
}
