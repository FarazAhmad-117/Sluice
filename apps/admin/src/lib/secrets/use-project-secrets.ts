import { useEffect, useMemo, useRef, useState } from "react";
import { useQueries, useQuery } from "convex/react";
import type { RequestForQueries } from "convex/react";
import { useSearchParams } from "react-router";
import { api } from "@convex/_generated/api";
import type { FunctionReturnType } from "convex/server";
import { useAuth } from "@/lib/auth/auth-context";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";
import { openSecretName } from "./decrypt";
import type { ProjectDataKeyState } from "./environment-key";
import type { EnvironmentKey } from "./pdk";
import { labelRows, pickEnvironment } from "./project-secrets";
import type { LabelledRow, Listing } from "./project-secrets";
import { useEnvironmentKeys } from "./use-environment-keys";

/**
 * ONE PROJECT'S SECRETS, PER ENVIRONMENT, WITH THEIR NAMES OPENED.
 *
 * Every environment's listing and key is loaded, not only the selected one's:
 * the environment tabs show counts, a row's scope label depends on whether its
 * group covers every environment (see `scope.ts`), and the add-secret drawer
 * seals into all of them and checks names in all of them.
 *
 * Names are opened for every environment whose key is in hand. Values are
 * never opened here; the page opens one on demand.
 *
 * The project is found by slug in the current org's `listProjects`. The
 * selected environment is `?env=<name>`, default `development`.
 */

export type EnvironmentRow = FunctionReturnType<typeof api.environments.listEnvironments>[number];
export type ListedSecret = FunctionReturnType<typeof api.secrets.listSecrets>[number];
type ProjectRow = FunctionReturnType<typeof api.projects.listProjects>[number];

export type ProjectSecrets =
  | { readonly status: "loading" }
  | { readonly status: "not-found" }
  | {
      readonly status: "ready";
      readonly project: ProjectRow;
      readonly environments: readonly EnvironmentRow[];
      /** `null` only when the project has no environments. */
      readonly environment: EnvironmentRow | null;
      selectEnvironment(name: string): void;
      /** The selected environment's key. */
      readonly keyState: ProjectDataKeyState;
      /** Every environment's key, by environment id. */
      readonly keys: ReadonlyMap<string, ProjectDataKeyState>;
      /** The selected environment's rows, labelled; `undefined` while anything they depend on loads. */
      readonly rows: readonly LabelledRow<ListedSecret>[] | undefined;
      /** Live secret count per environment id; `undefined` loading, `null` failed. */
      readonly counts: ReadonlyMap<string, number | null | undefined>;
      /** Opened names per environment id, for environments whose names are open. */
      readonly namesByEnvironment: ReadonlyMap<string, ReadonlyMap<string, string>>;
      /** Environments whose listing failed, by name. */
      readonly failedListings: readonly string[];
    };

/** A stable small id per key object, so a key's identity can go into a string. */
const keyIds = new WeakMap<EnvironmentKey, number>();
let nextKeyId = 1;
function keyId(key: EnvironmentKey): number {
  let id = keyIds.get(key);
  if (id === undefined) {
    id = nextKeyId++;
    keyIds.set(key, id);
  }
  return id;
}

interface NameSource {
  readonly environmentId: string;
  readonly key: EnvironmentKey;
  readonly rows: readonly ListedSecret[];
}

/**
 * Opened names for each source, tagged with the signature they were opened
 * for and served only while it still matches, so a lock, a key change or new
 * rows can never pair old names with new rows (the same tagging as
 * `useSecretNames`). A row that does not open is absent: it renders sealed.
 */
function useNamesByEnvironment(sources: readonly NameSource[]): ReadonlyMap<string, ReadonlyMap<string, string>> {
  const signature = sources
    .map(
      (source) =>
        `${source.environmentId}@${keyId(source.key)}=${source.rows.map((row) => `${row.secretId}:${row.nameNonce}`).join(",")}`,
    )
    .join("|");
  // The sources behind the current signature, for the effect below. Updated in
  // an effect declared first, so it has run by the time that one reads it.
  const latest = useRef(sources);
  useEffect(() => {
    latest.current = sources;
  });
  const [opened, setOpened] = useState<{
    signature: string;
    names: ReadonlyMap<string, ReadonlyMap<string, string>>;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const current = latest.current;
    void (async () => {
      const result = new Map<string, ReadonlyMap<string, string>>();
      await Promise.all(
        current.map(async (source) => {
          const names = new Map<string, string>();
          await Promise.all(
            source.rows.map(async (row) => {
              try {
                names.set(row.secretId, await openSecretName(source.key, row));
              } catch {
                // Shown as sealed. `SecretOpenError` carries no detail, and
                // one unopenable row must not stop the others.
              }
            }),
          );
          result.set(source.environmentId, names);
        }),
      );
      if (!cancelled) setOpened({ signature, names: result });
    })();
    return () => {
      cancelled = true;
    };
  }, [signature]);

  return useMemo(
    () => (opened !== null && opened.signature === signature ? opened.names : new Map()),
    [opened, signature],
  );
}

const IDLE: ProjectDataKeyState = { status: "idle" };

export function useProjectSecrets(slug: string): ProjectSecrets {
  const { session } = useAuth();
  const { org } = useCurrentOrg();
  const sessionToken = session?.sessionToken ?? null;
  const [params, setParams] = useSearchParams();

  const projects = useQuery(
    api.projects.listProjects,
    sessionToken === null || org === null ? "skip" : { sessionToken, orgId: org.orgId },
  );
  const project = projects?.find((row) => row.slug === slug) ?? null;

  const environments = useQuery(
    api.environments.listEnvironments,
    sessionToken === null || project === null ? "skip" : { sessionToken, projectId: project.projectId },
  );

  const keys = useEnvironmentKeys(
    environments?.map((environment) => ({ environmentId: environment.environmentId, uid: environment.uid })),
  );

  const requests = useMemo(() => {
    const out: RequestForQueries = {};
    if (sessionToken === null) return out;
    for (const environment of environments ?? []) {
      out[environment.environmentId] = {
        query: api.secrets.listSecrets,
        args: { sessionToken, environmentId: environment.environmentId },
      };
    }
    return out;
  }, [environments, sessionToken]);
  const listed = useQueries(requests);

  const listings = useMemo((): (Listing<ListedSecret> & { loading: boolean })[] => {
    return (environments ?? []).map((environment) => {
      const result: unknown = listed[environment.environmentId];
      return {
        environmentId: environment.environmentId,
        environmentName: environment.name,
        rows: result instanceof Error ? null : Array.isArray(result) ? (result as ListedSecret[]) : null,
        loading: result === undefined,
      };
    });
  }, [environments, listed]);

  const sources = useMemo((): NameSource[] => {
    const out: NameSource[] = [];
    for (const listing of listings) {
      const state = keys?.get(listing.environmentId);
      if (state?.status === "ready" && listing.rows !== null) {
        out.push({ environmentId: listing.environmentId, key: state.key, rows: listing.rows });
      }
    }
    return out;
  }, [listings, keys]);
  const namesByEnvironment = useNamesByEnvironment(sources);

  const environment = environments === undefined ? null : pickEnvironment(environments, params.get("env"));

  if (projects === undefined || org === null) return { status: "loading" };
  if (project === null) return { status: "not-found" };
  if (environments === undefined || keys === null) return { status: "loading" };

  const keyState = environment === null ? IDLE : (keys.get(environment.environmentId) ?? IDLE);
  const selected = listings.find((listing) => listing.environmentId === environment?.environmentId);
  const names = environment === null ? undefined : namesByEnvironment.get(environment.environmentId);
  const ready =
    selected !== undefined &&
    !listings.some((listing) => listing.loading) &&
    keyState.status === "ready" &&
    names !== undefined;

  const counts = new Map<string, number | null | undefined>();
  for (const listing of listings) {
    counts.set(listing.environmentId, listing.loading ? undefined : (listing.rows?.length ?? null));
  }

  return {
    status: "ready",
    project,
    environments,
    environment,
    selectEnvironment: (name) =>
      setParams(
        (current) => {
          const next = new URLSearchParams(current);
          next.set("env", name);
          return next;
        },
        { replace: true },
      ),
    keyState,
    keys,
    rows: ready ? labelRows(selected, listings, names) : undefined,
    counts,
    namesByEnvironment,
    failedListings: listings
      .filter((listing) => !listing.loading && listing.rows === null)
      .map((listing) => listing.environmentName),
  };
}

