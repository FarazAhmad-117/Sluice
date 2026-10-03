import { useState } from "react";
import { PageHeader } from "@/components/shell/page-header";
import { ProjectNotFound } from "@/components/shell/project-states";
import { TokenList } from "@/components/tokens/token-list";
import { Button } from "@/components/ui/button";
import { Callout, Skeleton } from "@/components/ui/feedback";
import { IconPlus } from "@/components/ui/icons";
import { compactHeight, focusRing, pageGutter } from "@/components/ui/styles";
import { DEVELOPMENT } from "@/lib/projects/overview";
import { useProject } from "@/lib/projects/project-context";
import { useProjectTokens } from "@/lib/tokens/use-project-tokens";

/**
 * EVERY SERVICE TOKEN IN THE PROJECT.
 *
 * The same rows as the Environments page, across environments, with the
 * revoked ones too, filtered by environment and by whether they still work.
 */

type StatusFilter = "active" | "revoked" | "all";

const STATUS_FILTERS: readonly { value: StatusFilter; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "revoked", label: "Revoked" },
  { value: "all", label: "All" },
];

export default function ProjectTokensRoute() {
  const { slug, data } = useProject();
  const tokens = useProjectTokens();
  const [status, setStatus] = useState<StatusFilter>("active");
  const [environment, setEnvironment] = useState<string>("all");

  if (data.status === "not-found") return <ProjectNotFound slug={slug} title="Tokens" />;
  const name = data.status === "ready" ? data.project.name : slug;
  const environments = data.status === "ready" ? data.environments : [];
  const setupEnvironment =
    environments.find((candidate) => candidate.name === environment) ??
    environments.find((candidate) => candidate.name === DEVELOPMENT) ??
    environments[0];

  const inEnvironment = (tokens ?? []).filter((row) => environment === "all" || row.environmentName === environment);
  const shown = inEnvironment.filter((row) => status === "all" || row.status === status);
  const count = (filter: StatusFilter) => inEnvironment.filter((row) => filter === "all" || row.status === filter).length;

  const newButton =
    setupEnvironment === undefined ? undefined : (
      <Button
        size="sm"
        icon={<IconPlus className="size-3.5" />}
        to={`/projects/${slug}/environments/${encodeURIComponent(setupEnvironment.name)}/setup`}
      >
        New token
      </Button>
    );

  return (
    <>
      <PageHeader title="Tokens" crumbs={[{ label: name, to: `/projects/${slug}` }]} actions={newButton} />
      <div className={`flex max-w-[960px] flex-col gap-5 py-6 ${pageGutter}`}>
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">Tokens</h1>
          <p className="m-0 text-text-muted">
            One per place that reads secrets. Revoke one and only that place stops, within seconds.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div role="group" aria-label="Show" className="flex flex-wrap gap-2">
            {STATUS_FILTERS.map((filter) => {
              const on = status === filter.value;
              return (
                <button
                  key={filter.value}
                  type="button"
                  aria-pressed={on}
                  onClick={() => setStatus(filter.value)}
                  className={`inline-flex min-h-11 cursor-pointer items-center rounded-full lg:min-h-0 lg:pointer-coarse:min-h-11 ${focusRing}`}
                >
                  <span
                    className={`inline-flex h-[30px] items-center gap-1.5 rounded-full px-[11px] text-[13px] whitespace-nowrap transition-colors ${
                      on
                        ? "bg-text-primary font-medium text-surface-base"
                        : "border border-hairline-strong text-text-primary hover:bg-surface-card"
                    }`}
                  >
                    {filter.label}
                    {tokens === undefined || tokens === null ? null : (
                      <span className={on ? "" : "text-text-muted"}>{count(filter.value)}</span>
                    )}
                  </span>
                </button>
              );
            })}
          </div>
          {environments.length > 1 ? (
            <label className="flex items-center gap-2 text-[13px] text-text-muted">
              Environment
              <select
                value={environment}
                onChange={(event) => setEnvironment(event.target.value)}
                className={`${compactHeight} cursor-pointer rounded-input border border-hairline-strong bg-surface-panel px-2.5 text-[13px] text-text-primary ${focusRing}`}
              >
                <option value="all">All</option>
                {environments.map((candidate) => (
                  <option key={candidate.environmentId} value={candidate.name}>
                    {candidate.name}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </div>

        {tokens === null ? (
          <Callout tone="danger" role="alert" title="Tokens could not be loaded">
            Your secrets are unaffected. Reload to try again.
          </Callout>
        ) : tokens === undefined ? (
          <div className="flex flex-col gap-2 rounded-card border border-hairline p-4">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-3 w-32" />
          </div>
        ) : tokens.length === 0 ? (
          <div className="rounded-card border border-dashed border-hairline-strong px-6 py-14 text-center">
            <h2 className="m-0 text-lg font-semibold text-text-primary">No tokens yet</h2>
            <p className="m-0 mt-2 text-sm text-text-muted">
              Each place you connect gets one: your computer, a server, a CI pipeline, a container.
            </p>
            {newButton === undefined ? null : <div className="mt-5 flex justify-center">{newButton}</div>}
          </div>
        ) : (
          <div className="overflow-hidden rounded-card border border-hairline bg-surface-panel">
            <TokenList
              rows={shown}
              showEnvironment={environment === "all"}
              empty={status === "revoked" ? "Nothing has been revoked." : "No tokens match."}
            />
          </div>
        )}
      </div>
    </>
  );
}
