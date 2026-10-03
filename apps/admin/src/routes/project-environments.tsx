import { Link, useSearchParams } from "react-router";
import { AddEnvironmentDrawer } from "@/components/projects/add-environment-drawer";
import { PageHeader } from "@/components/shell/page-header";
import { ProjectNotFound } from "@/components/shell/project-states";
import { TokenList } from "@/components/tokens/token-list";
import { Button } from "@/components/ui/button";
import { Callout, Skeleton } from "@/components/ui/feedback";
import { IconPlus } from "@/components/ui/icons";
import { focusRing, pageGutter } from "@/components/ui/styles";
import { useProject } from "@/lib/projects/project-context";
import { useShell } from "@/lib/shell/shell-context";
import type { TokenRow } from "@/lib/tokens/use-project-tokens";
import { useProjectTokens } from "@/lib/tokens/use-project-tokens";

/**
 * ENVIRONMENTS AND WHAT IS CONNECTED TO EACH.
 *
 * The approved Round 2 "Environments" screen, in the sidebar shell: one card
 * per environment with its secret count, the places connected to it (each
 * with its own token, its status and Revoke), and Connect. Revoked tokens are
 * counted rather than listed, with a link to Tokens, so a card shows what is
 * live.
 */

export default function ProjectEnvironmentsRoute() {
  const { slug, data } = useProject();
  const tokens = useProjectTokens();
  const { announce } = useShell();
  const [search, setSearch] = useSearchParams();
  // `?add=1` is how the sidebar's "Add environment" opens the drawer here.
  const adding = search.get("add") === "1";
  const setAdding = (open: boolean) =>
    setSearch(
      (current) => {
        const next = new URLSearchParams(current);
        if (open) next.set("add", "1");
        else next.delete("add");
        return next;
      },
      { replace: true },
    );

  if (data.status === "not-found") return <ProjectNotFound slug={slug} title="Environments" />;
  const name = data.status === "ready" ? data.project.name : slug;

  const addButton =
    data.status === "ready" ? (
      <Button size="sm" icon={<IconPlus className="size-3.5" />} onClick={() => setAdding(true)}>
        Add environment
      </Button>
    ) : undefined;

  return (
    <>
      <PageHeader title="Environments" crumbs={[{ label: name, to: `/projects/${slug}` }]} actions={addButton} />
      <div className={`flex max-w-[960px] flex-col gap-5 py-6 ${pageGutter}`}>
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">Environments</h1>
          <p className="m-0 text-text-muted">
            Each environment has its own secrets and its own list of places allowed to read them.
          </p>
        </div>

        {tokens === null ? (
          <Callout tone="danger" role="alert" title="Connections could not be loaded">
            Your secrets are unaffected. Reload to try again.
          </Callout>
        ) : null}

        {data.status === "loading" ? (
          <div className="flex flex-col gap-4">
            <Skeleton className="h-40 rounded-card" />
            <Skeleton className="h-40 rounded-card" />
          </div>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-4 p-0">
            {data.environments.map((environment) => (
              <EnvironmentCard
                key={environment.environmentId}
                slug={slug}
                name={environment.name}
                secretCount={data.counts.get(environment.environmentId)}
                tokens={
                  tokens === undefined || tokens === null
                    ? undefined
                    : tokens.filter((row) => row.environmentId === environment.environmentId)
                }
              />
            ))}
          </ul>
        )}
      </div>
      {data.status === "ready" ? (
        <AddEnvironmentDrawer
          open={adding}
          onClose={() => setAdding(false)}
          projectId={data.project.projectId}
          existing={data.environments.map((environment) => environment.name)}
          onCreated={(created) => {
            setAdding(false);
            announce(`${created} was added.`);
          }}
        />
      ) : null}
    </>
  );
}

function EnvironmentCard({
  slug,
  name,
  secretCount,
  tokens,
}: {
  readonly slug: string;
  readonly name: string;
  readonly secretCount: number | null | undefined;
  /** `undefined` while loading. */
  readonly tokens: readonly TokenRow[] | undefined;
}) {
  const live = tokens?.filter((row) => row.status === "active") ?? [];
  const revoked = (tokens?.length ?? 0) - live.length;
  const setupTo = `/projects/${slug}/environments/${encodeURIComponent(name)}/setup`;
  const summary = [
    typeof secretCount === "number" ? `${secretCount} ${secretCount === 1 ? "secret" : "secrets"}` : null,
    tokens === undefined
      ? null
      : live.length === 0
        ? "not connected"
        : `${live.length} ${live.length === 1 ? "connection" : "connections"}`,
  ].filter((part): part is string => part !== null);

  return (
    <li className="overflow-hidden rounded-card border border-hairline bg-surface-panel">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-4 py-3.5">
        <div className="flex min-w-0 flex-col gap-0.5">
          <h2 className="m-0 truncate font-mono text-[15px] font-semibold text-text-primary">{name}</h2>
          <span className="min-h-5 text-[13px] text-text-muted">{summary.join(" · ")}</span>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to={`/projects/${slug}/secrets?env=${encodeURIComponent(name)}`}
            className={`inline-flex min-h-11 items-center rounded-input px-2.5 text-[13px] text-text-muted no-underline hover:text-text-primary lg:min-h-8 lg:pointer-coarse:min-h-11 ${focusRing}`}
          >
            Secrets<span className="sr-only"> in {name}</span>
          </Link>
          <Button size="sm" variant={live.length === 0 ? "primary" : "secondary"} to={setupTo}>
            {live.length === 0 ? `Set up ${name}` : "Connect"}
            {live.length === 0 ? null : <span className="sr-only"> to {name}</span>}
          </Button>
        </div>
      </div>
      {tokens === undefined ? (
        <div className="flex flex-col gap-2 px-4 py-4">
          <Skeleton className="h-4 w-48" />
          <Skeleton className="h-3 w-32" />
        </div>
      ) : live.length === 0 ? (
        <p className="m-0 px-4 py-4 text-sm text-text-muted">
          Nothing reads {name} yet. Connect your computer, a server, a CI pipeline or a container to it.
        </p>
      ) : (
        <TokenList rows={live} showEnvironment={false} />
      )}
      {revoked > 0 ? (
        <div className="border-t border-hairline px-4 py-2.5 text-[13px] text-text-muted">
          {revoked} revoked{" "}
          <Link
            to={`/projects/${slug}/tokens`}
            className={`rounded-sm text-brand no-underline hover:text-brand-hover ${focusRing}`}
          >
            {revoked === 1 ? "token" : "tokens"} in Tokens
          </Link>
        </div>
      ) : null}
    </li>
  );
}
