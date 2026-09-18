"use client";

import { useMemo, useState } from "react";
import { useQuery } from "convex/react";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { focusRing, secondaryButton } from "@/components/app/controls";
import { LeftNav } from "@/components/app/left-nav";
import { RightPanel } from "@/components/app/right-panel";
import { SecretsPane } from "@/components/app/secrets-pane";
import { useAuth } from "@/lib/auth/auth-context";
import { useProjectDataKey } from "@/lib/secrets/use-project-data-key";
import { useSecretNames } from "@/lib/secrets/use-secret-names";

/**
 * THE THREE PANE SHELL.
 *
 * Left nav, dense centre, right panel, exactly as the approved dashboard
 * reference lays out. Below the `lg` breakpoint the three panes STACK rather
 * than shrink, and the nav collapses behind one control: three columns at 375px
 * would be three columns of nothing, and the alternative, letting the row
 * overflow, is the horizontal page scroll this product does not ship.
 *
 * `min-h-[100dvh]` and not `h-screen`. On mobile Safari `100vh` is the viewport
 * WITHOUT the browser chrome, so a `h-screen` shell is taller than the space it
 * has and its bottom row sits under the address bar.
 *
 * EVERY QUERY TAKES THE SESSION TOKEN AS AN ARGUMENT. That is the Convex
 * session design, argued at length in `convex/lib/session.ts`, and it is also
 * the reason the token cannot live in an httpOnly cookie. `"skip"` is passed
 * whenever a prerequisite is missing, which is what keeps this from firing a
 * query with an undefined id during the first render after a refresh.
 *
 * THE ONE READ THAT IS NOT A `useQuery` IS THE KEY. `useProjectDataKey` fetches
 * the caller's grant once per environment and opens it with the master unlock
 * key, because `useQuery` re-throws a refusal during render and "this member
 * holds no grant" is a normal state rather than a crash. Its own file has the
 * full argument.
 */
export function AppShell() {
  const { session, locked } = useAuth();
  const sessionToken = session?.sessionToken ?? null;

  /**
   * SELECTION IS "WHAT THE USER PICKED", AND THE DEFAULT IS DERIVED, NOT STORED.
   *
   * The shell has to land on real data rather than on three empty panes, so an
   * unset selection falls back to the first row of the list. That fallback is
   * COMPUTED DURING RENDER rather than written into state by an effect. Writing
   * it would mean three effects that each fire a second render pass, and it
   * would mean a stored id that can outlive the list it came from: switch org,
   * and the stored project id belongs to the previous org until an effect gets
   * round to clearing it, and the query in between asks for a project the new
   * org does not have.
   *
   * `null` in these three pieces of state means "no explicit choice", never
   * "nothing selected".
   */
  const [pickedOrgId, setPickedOrgId] = useState<Id<"orgs"> | null>(null);
  const [pickedProjectId, setPickedProjectId] = useState<Id<"projects"> | null>(null);
  const [pickedEnvironmentId, setPickedEnvironmentId] = useState<Id<"environments"> | null>(null);
  const [secretId, setSecretId] = useState<string | null>(null);
  const [navOpen, setNavOpen] = useState(false);

  const orgs = useQuery(api.orgs.listMyOrgs, sessionToken === null ? "skip" : { sessionToken });

  const orgId = pickedOrgId ?? orgs?.[0]?.orgId ?? null;

  const projects = useQuery(
    api.projects.listProjects,
    sessionToken === null || orgId === null ? "skip" : { sessionToken, orgId },
  );

  const projectId = pickedProjectId ?? projects?.[0]?.projectId ?? null;

  const environments = useQuery(
    api.environments.listEnvironments,
    sessionToken === null || projectId === null ? "skip" : { sessionToken, projectId },
  );

  const environmentId = pickedEnvironmentId ?? environments?.[0]?.environmentId ?? null;

  const secrets = useQuery(
    api.secrets.listSecrets,
    sessionToken === null || environmentId === null ? "skip" : { sessionToken, environmentId },
  );

  /**
   * THE PROJECT DATA KEY FOR THE SELECTED ENVIRONMENT.
   *
   * It is refetched and reopened whenever the selection changes, and it is
   * dropped when the vault locks. Nothing persists it.
   */
  const keyState = useProjectDataKey(environmentId);
  const pdk = keyState.status === "ready" ? keyState.pdk : null;

  // Names only. A value is decrypted at the moment somebody reveals it and not
  // before; see `secrets-pane.tsx`.
  const names = useSecretNames(pdk, secrets);

  const environmentName = useMemo(() => {
    if (environments === undefined || environmentId === null) return null;
    return environments.find((row) => row.environmentId === environmentId)?.name ?? null;
  }, [environments, environmentId]);

  const selectedSecret = useMemo(() => {
    if (secrets === undefined || secretId === null) return null;
    return secrets.find((row) => row.secretId === secretId) ?? null;
  }, [secrets, secretId]);

  return (
    <div className="flex min-h-[100dvh] flex-col bg-surface-base text-text-primary lg:h-[100dvh] lg:overflow-hidden">
      {/* First in the DOM, so it is first in tab order. `sr-only` until it
          takes focus, which is what stops a keyboard user being walked through
          the entire project tree on every page. */}
      <a
        href="#main-content"
        className={`sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-10 focus:rounded-input focus:border focus:border-hairline focus:bg-surface-card focus:px-3 focus:py-2 focus:text-base ${focusRing}`}
      >
        Skip to secrets
      </a>

      {/* The nav control exists only below `lg`, where the left pane is
          collapsed. Above it the pane is always present and this row is gone. */}
      <div className="flex items-center justify-between gap-3 border-b border-hairline px-4 py-2.5 lg:hidden">
        <button
          type="button"
          onClick={() => setNavOpen((open) => !open)}
          aria-expanded={navOpen}
          className={secondaryButton}
        >
          {navOpen ? "Hide projects" : "Projects"}
        </button>
        <span className="truncate font-mono text-base text-text-primary">
          {environmentName ?? "No environment"}
        </span>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[17rem_minmax(0,1fr)_21rem]">
        <div className={`${navOpen ? "block" : "hidden"} min-h-0 lg:block`}>
          <LeftNav
            orgs={orgs}
            projects={projects}
            environments={environments}
            activeOrgId={orgId}
            activeProjectId={projectId}
            activeEnvironmentId={environmentId}
            onSelectOrg={(next) => {
              // Clearing the two below is what makes each of them fall back to
              // the first row of the NEW list rather than keep pointing at a
              // row of the old one.
              setPickedOrgId(next);
              setPickedProjectId(null);
              setPickedEnvironmentId(null);
              setSecretId(null);
            }}
            onSelectProject={(next) => {
              setPickedProjectId(next);
              setPickedEnvironmentId(null);
              setSecretId(null);
            }}
            onSelectEnvironment={(next) => {
              setPickedEnvironmentId(next);
              setSecretId(null);
              setNavOpen(false);
            }}
          />
        </div>

        <div id="main-content" className="min-h-0">
          <SecretsPane
            environmentId={environmentId}
            environmentName={environmentName}
            rows={secrets}
            names={names}
            pdk={pdk}
            keyState={keyState}
            locked={locked}
            selectedSecretId={secretId}
            onSelect={setSecretId}
          />
        </div>

        <div className="min-h-0">
          <RightPanel secret={selectedSecret} keyState={keyState} />
        </div>
      </div>
    </div>
  );
}
