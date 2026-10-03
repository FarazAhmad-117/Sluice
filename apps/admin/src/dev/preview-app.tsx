import { useEffect, useMemo, useState } from "react";
import { Outlet, useMatch, useSearchParams } from "react-router";
import { newId } from "@sluice/crypto";
import type { Id } from "@convex/_generated/dataModel";
import { ShellFrame } from "@/components/shell/app-shell";
import { AuthProvider } from "@/lib/auth/auth-context";
import { ConvexProvider, ConvexReactClient } from "convex/react";
import { CurrentOrgContext } from "@/lib/orgs/use-current-org";
import type { CurrentOrg } from "@/lib/orgs/use-current-org";
import { createProjectDataKey } from "@/lib/secrets/pdk";
import type { EnvironmentKey } from "@/lib/secrets/pdk";
import { labelRows, pickEnvironment } from "@/lib/secrets/project-secrets";
import { sealSecret } from "@/lib/secrets/seal";
import type { ProjectDataKeyState } from "@/lib/secrets/environment-key";
import type { EnvironmentRow, ListedSecret, ProjectSecrets } from "@/lib/secrets/use-project-secrets";
import { ThemeProvider } from "@/lib/theme";
import { ProjectsView } from "@/routes/projects";

/**
 * A DEVELOPMENT-ONLY PREVIEW OF THE SIGNED-IN APP, OVER FIXTURE ROWS.
 *
 * Served by `vite dev` at `/preview.html#/projects/storefront-api`. It renders
 * the real shell and the real pages, with the project scope and the org
 * handed in instead of fetched, so the layout can be looked at without an
 * account on a shared deployment. The rows are sealed HERE, at load, under
 * keys made here, so revealing a value runs the real decrypt.
 *
 * Nothing is signed in, so every write is refused by the page's own "not
 * ready" guard: that is how the error states are previewed.
 *
 * `?mode=` before the `#` picks a state: `empty` (no secrets), `loading`,
 * `key-refused` (production's key not held), `listing-failed`.
 *
 * Not part of the product: `vite build` builds `index.html` only.
 */

const MODE = new URLSearchParams(window.location.search).get("mode") ?? "ready";

/**
 * Hooks need a client to exist; with nobody signed in every query is skipped,
 * so this one is never asked anything. A reserved `.invalid` host, so it can
 * never reach a real deployment, the shared dev one included.
 */
const PLACEHOLDER_CLIENT = new ConvexReactClient("https://preview.invalid", {
  skipConvexDeploymentUrlCheck: true,
  unsavedChangesWarning: false,
});

const ORG: CurrentOrg = {
  org: { orgId: "org_doc" as Id<"orgs">, uid: newId("org"), name: "Personal", slug: "personal" },
  orgs: [{ orgId: "org_doc" as Id<"orgs">, uid: newId("org"), name: "Personal", slug: "personal" }],
  setOrg: () => undefined,
  status: "ready",
  error: null,
  retry: () => undefined,
};

const PROJECT = {
  projectId: "prj_doc" as Id<"projects">,
  orgId: "org_doc" as Id<"orgs">,
  name: "storefront-api",
  slug: "storefront-api",
  createdAt: Date.now() - 3 * 3600_000,
};

const ENV_NAMES = ["development", "staging", "production"] as const;

interface FixtureSecret {
  readonly name: string;
  /** Value per environment; absent = not in that environment. */
  readonly values: Partial<Record<(typeof ENV_NAMES)[number], string>>;
  readonly shared?: boolean;
  /** Environments whose value is their own. */
  readonly own?: readonly string[];
  readonly version?: number;
}

const FIXTURES: readonly FixtureSecret[] = [
  { name: "DATABASE_URL", values: { development: "postgres://localhost:5432/store" } },
  { name: "REDIS_URL", values: { development: "redis://localhost:6379" } },
  { name: "EMPTY", values: { development: "" } },
  {
    name: "SENTRY_DSN",
    shared: true,
    values: {
      development: "https://dev-key@o1.ingest.sentry.io/42",
      staging: "https://dev-key@o1.ingest.sentry.io/42",
      production: "https://prod-key@o1.ingest.sentry.io/42",
    },
    own: ["production"],
    version: 3,
  },
  {
    name: "LOG_LEVEL",
    shared: true,
    values: { development: "debug", staging: "debug", production: "debug" },
  },
  { name: "STRIPE_KEY", values: { production: "sk_live_fixture" } },
];

interface Built {
  readonly environments: EnvironmentRow[];
  readonly keys: Map<string, EnvironmentKey>;
  readonly listings: Map<string, ListedSecret[]>;
  readonly names: Map<string, Map<string, string>>;
}

async function build(): Promise<Built> {
  const environments: EnvironmentRow[] = ENV_NAMES.map((name, index) => ({
    environmentId: `env_doc_${index}` as Id<"environments">,
    uid: newId("env"),
    projectId: PROJECT.projectId,
    name,
    pdkVersion: 1,
    epoch: 0,
  }));
  const keys = new Map<string, EnvironmentKey>();
  for (const environment of environments) {
    keys.set(environment.environmentId, { pdk: createProjectDataKey(), environmentUid: environment.uid, pdkVersion: 1 });
  }
  const listings = new Map<string, ListedSecret[]>();
  const names = new Map<string, Map<string, string>>();
  let at = Date.now() - 50 * 60_000;
  for (const fixture of FIXTURES) {
    const shareUid = fixture.shared === true ? newId("shr") : undefined;
    at += 7 * 60_000;
    for (const environment of environments) {
      const value = fixture.values[environment.name as (typeof ENV_NAMES)[number]];
      if (value === undefined) continue;
      const key = keys.get(environment.environmentId)!;
      const secretUid = newId("sec");
      const version = fixture.version ?? 1;
      const sealed = await sealSecret(key, { secretUid, version, name: fixture.name, value });
      const secretId = `sec_doc_${fixture.name}_${environment.name}`;
      const row = {
        secretId: secretId as Id<"secrets">,
        environmentId: environment.environmentId,
        secretUid,
        version,
        pdkVersion: 1,
        ...sealed,
        updatedAt: at,
        ...(shareUid === undefined ? {} : { shareUid, overridden: fixture.own?.includes(environment.name) === true }),
      } as ListedSecret;
      listings.set(environment.environmentId, [...(listings.get(environment.environmentId) ?? []), row]);
      const map = names.get(environment.environmentId) ?? new Map<string, string>();
      map.set(secretId, fixture.name);
      names.set(environment.environmentId, map);
    }
  }
  for (const environment of environments) {
    if (!listings.has(environment.environmentId)) listings.set(environment.environmentId, []);
    if (!names.has(environment.environmentId)) names.set(environment.environmentId, new Map());
  }
  return { environments, keys, listings, names };
}

function useFixtureProject(built: Built | null): ProjectSecrets {
  const [params, setParams] = useSearchParams();
  return useMemo((): ProjectSecrets => {
    if (built === null || MODE === "loading") return { status: "loading" };
    const empty = MODE === "empty";
    const keys = new Map<string, ProjectDataKeyState>();
    for (const [environmentId, key] of built.keys) {
      keys.set(environmentId, { status: "ready", key });
    }
    if (MODE === "key-refused") {
      keys.set(built.environments[2]!.environmentId, {
        status: "refused",
        message: "You have no key for this environment.",
      });
    }
    const listings = built.environments.map((environment) => ({
      environmentId: environment.environmentId,
      environmentName: environment.name,
      rows:
        MODE === "listing-failed" && environment.name === "staging"
          ? null
          : empty
            ? []
            : (built.listings.get(environment.environmentId) ?? []),
      loading: false,
    }));
    const namesByEnvironment = new Map<string, ReadonlyMap<string, string>>();
    for (const environment of built.environments) {
      if (keys.get(environment.environmentId)?.status === "ready") {
        namesByEnvironment.set(environment.environmentId, empty ? new Map() : built.names.get(environment.environmentId)!);
      }
    }
    const environment = pickEnvironment(built.environments, params.get("env"));
    const keyState = environment === null ? { status: "idle" as const } : keys.get(environment.environmentId)!;
    const selected = listings.find((listing) => listing.environmentId === environment?.environmentId);
    const names = environment === null ? undefined : namesByEnvironment.get(environment.environmentId);
    const counts = new Map<string, number | null | undefined>();
    for (const listing of listings) counts.set(listing.environmentId, listing.rows?.length ?? null);
    return {
      status: "ready",
      project: PROJECT,
      environments: built.environments,
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
      rows: selected !== undefined && keyState.status === "ready" && names !== undefined ? labelRows(selected, listings, names) : undefined,
      counts,
      namesByEnvironment,
      failedListings: listings.filter((listing) => listing.rows === null).map((listing) => listing.environmentName),
      listings,
    };
  }, [built, params, setParams]);
}

export function PreviewProjects() {
  return (
    <ProjectsView
      status="ready"
      error={null}
      retry={() => undefined}
      projects={
        MODE === "empty"
          ? []
          : [
              { projectId: PROJECT.projectId, name: PROJECT.name, slug: PROJECT.slug, environments: [...ENV_NAMES], secretCount: 6 },
              { projectId: "prj_doc2" as Id<"projects">, name: "marketing-site", slug: "marketing-site", environments: ["development"], secretCount: 2 },
            ]
      }
    />
  );
}

export function PreviewShell() {
  const [built, setBuilt] = useState<Built | null>(null);
  useEffect(() => {
    void build().then(setBuilt);
  }, []);
  const project = useMatch("/projects/:projectSlug/*");
  const creating = useMatch("/projects/new");
  const slug = creating === null ? (project?.params.projectSlug ?? null) : null;
  const data = useFixtureProject(built);
  return (
    <CurrentOrgContext.Provider value={ORG}>
      <ShellFrame scope={slug === null ? null : { slug, data }} />
    </CurrentOrgContext.Provider>
  );
}

export function PreviewProviders() {
  return (
    <ThemeProvider>
      <ConvexProvider client={PLACEHOLDER_CLIENT}>
        <AuthProvider>
          <Outlet />
        </AuthProvider>
      </ConvexProvider>
    </ThemeProvider>
  );
}
