import { useMemo } from "react";
import { useQueries } from "convex/react";
import type { RequestForQueries } from "convex/react";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { useAuth } from "@/lib/auth/auth-context";
import { useProjectScope } from "@/lib/projects/project-context";
import { describeActivity } from "./describe";
import type { ActivityEvent, ActivityLine } from "./describe";

export type { ActivityLine } from "./describe";

/**
 * A PROJECT'S RECENT ACTIVITY, AS LINES A PERSON READS.
 *
 * `activity.listProjectActivity` gives the events; `describe.ts` turns them
 * into sentences with names from the rows this browser has opened (the shell's
 * project scope). `useQueries` rather than `useQuery`, so a refusal comes back
 * as a value (`null` here) instead of throwing during render.
 *
 * `undefined` while loading, `null` when it failed, else newest first.
 */
export function useProjectActivity(request: {
  readonly projectId: string | null;
  readonly limit: number;
}): readonly ActivityLine[] | null | undefined {
  const { session } = useAuth();
  const scope = useProjectScope();
  const sessionToken = session?.sessionToken ?? null;

  const queries = useMemo((): RequestForQueries => {
    if (sessionToken === null || request.projectId === null) return {};
    return {
      activity: {
        query: api.activity.listProjectActivity,
        args: { sessionToken, projectId: request.projectId as Id<"projects">, limit: request.limit },
      },
    };
  }, [sessionToken, request.projectId, request.limit]);
  const result: unknown = useQueries(queries).activity;

  const data = scope?.data.status === "ready" ? scope.data : null;
  return useMemo(() => {
    if (result instanceof Error) return null;
    if (!Array.isArray(result) || data === null) return undefined;
    const secretNames = new Map<string, string>();
    for (const names of data.namesByEnvironment.values()) {
      for (const [secretId, name] of names) secretNames.set(secretId, name);
    }
    return describeActivity(result as ActivityEvent[], {
      secretNames,
      environmentNames: new Map(data.environments.map((environment) => [environment.environmentId, environment.name])),
      environmentCount: data.environments.length,
      projectName: data.project.name,
      selfEmail: session?.email ?? "",
    });
  }, [result, data, session?.email]);
}
