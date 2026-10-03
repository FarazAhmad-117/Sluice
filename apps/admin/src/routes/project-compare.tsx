import { useMemo } from "react";
import { Link } from "react-router";
import { CoverageCell } from "@/components/secrets/coverage";
import { PageHeader, PhoneActionBar } from "@/components/shell/page-header";
import { NoEnvironments, ProjectNotFound } from "@/components/shell/project-states";
import { Button } from "@/components/ui/button";
import { Callout, Skeleton } from "@/components/ui/feedback";
import { IconPlus } from "@/components/ui/icons";
import { focusRing, pageGutter } from "@/components/ui/styles";
import { listOf } from "@/lib/list-of";
import { useProject, useProjectActions } from "@/lib/projects/project-context";
import { buildMatrix } from "@/lib/secrets/compare";
import type { CompareMatrix } from "@/lib/secrets/compare";
import { linkForRow } from "@/lib/secrets/links";
import type { EnvironmentRow, ListedSecret, ProjectSecrets } from "@/lib/secrets/use-project-secrets";

/**
 * COMPARE ENVIRONMENTS: EVERY KEY, IN EVERY ENVIRONMENT.
 *
 * Values never appear here, masked or otherwise: the matrix is built from
 * names this browser opened and from the rows' grouping metadata (see
 * `lib/secrets/compare.ts`). A key opens on the Secrets page with its detail
 * panel; a missing cell is a real button that opens the add drawer for that
 * environment with the key filled in.
 */

type Ready = Extract<ProjectSecrets, { status: "ready" }>;

export default function ProjectCompareRoute() {
  const { slug, data } = useProject();
  if (data.status === "not-found") return <ProjectNotFound slug={slug} title="Compare" />;
  return <ComparePage key={slug} slug={slug} data={data.status === "ready" ? data : null} />;
}

function ComparePage({ slug, data }: { readonly slug: string; readonly data: Ready | null }) {
  const { openAdd } = useProjectActions();
  const matrix = useMemo(
    () => (data === null ? null : buildMatrix(data.listings, data.namesByEnvironment)),
    [data],
  );
  const loading = data === null || data.listings.some((listing) => listing.loading);
  const environments = data?.environments ?? [];
  const canAdd = data !== null && environments.length > 0;

  return (
    <>
      <PageHeader
        title="Compare"
        crumbs={[{ label: data?.project.name ?? slug, to: `/projects/${slug}` }]}
        actions={
          canAdd ? (
            <Button size="sm" icon={<IconPlus className="size-3.5" />} onClick={() => openAdd()}>
              Add secret
            </Button>
          ) : undefined
        }
      />
      <div className={`flex max-w-[1100px] flex-col gap-[18px] py-6 ${pageGutter}`}>
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">Compare environments</h1>
          <p className="m-0 text-text-muted">
            Every key, in every environment. Spot what production is missing before you deploy.
          </p>
        </div>

        {data !== null && environments.length === 0 ? (
          <NoEnvironments />
        ) : loading || matrix === null ? (
          <CompareLoading />
        ) : (
          <>
            <Summary matrix={matrix} environments={environments} />
            {matrix.uncertain.length > 0 ? (
              <Callout tone="warning" title={`Not everything in ${listOf(matrix.uncertain)} could be read`}>
                {matrix.sealed > 0
                  ? `${matrix.sealed} ${matrix.sealed === 1 ? "secret's name" : "secrets' names"} did not open with the key this browser holds. `
                  : "Its secrets could not be listed, or its key is not open. "}
                Where a key's presence cannot be confirmed, the cell says Unknown rather than Missing.
              </Callout>
            ) : null}
            {matrix.rows.length === 0 ? (
              <div className="flex flex-col items-center gap-4 rounded-card border border-dashed border-hairline-strong px-6 py-14 text-center">
                <div className="flex flex-col gap-2">
                  <h2 className="m-0 text-lg font-semibold text-text-primary">Nothing to compare yet</h2>
                  <p className="m-0 text-sm text-text-muted">Add a secret and it shows here, environment by environment.</p>
                </div>
                <Button icon={<IconPlus className="size-3.5" />} onClick={() => openAdd()}>
                  Add secret
                </Button>
              </div>
            ) : (
              <Matrix
                slug={slug}
                matrix={matrix}
                environments={environments}
                onAdd={(environmentId, name) => openAdd({ environmentId, name })}
              />
            )}
            <p className="m-0 text-[13px] text-text-muted">
              Values stay hidden here. Open a key to reveal or edit it in one environment.
            </p>
          </>
        )}
      </div>
      {canAdd ? (
        <PhoneActionBar>
          <Button size="lg" icon={<IconPlus className="size-4" />} className="w-full" onClick={() => openAdd()}>
            Add secret
          </Button>
        </PhoneActionBar>
      ) : null}
    </>
  );
}

function CompareLoading() {
  return (
    <div role="status" aria-label="Loading the comparison" className="flex flex-col gap-[18px]">
      <div aria-hidden="true" className="grid gap-3 sm:grid-cols-3">
        {[0, 1, 2].map((index) => (
          <Skeleton key={index} className="h-[74px] rounded-[10px]" />
        ))}
      </div>
      <Skeleton className="h-64 rounded-card" />
    </div>
  );
}

function Tile({ value, label, tone }: { readonly value: number; readonly label: string; readonly tone?: "danger" | "warning" }) {
  const shell =
    tone === "danger"
      ? "border-status-danger/35 bg-status-danger/6"
      : tone === "warning"
        ? "border-status-warning/35 bg-status-warning/6"
        : "border-hairline bg-surface-panel";
  const number =
    tone === "danger"
      ? "text-status-danger light:text-text-primary"
      : tone === "warning"
        ? "text-status-warning light:text-text-primary"
        : "text-text-primary";
  return (
    <div className={`flex flex-col gap-1 rounded-[10px] border px-4 py-3.5 ${shell}`}>
      <span className={`text-[22px] font-semibold ${number}`}>{value}</span>
      <span className="text-[13px] text-text-muted">{label}</span>
    </div>
  );
}

function Summary({
  matrix,
  environments,
}: {
  readonly matrix: CompareMatrix<ListedSecret>;
  readonly environments: readonly EnvironmentRow[];
}) {
  const missing = environments.filter((environment) => (matrix.missing.get(environment.environmentId) ?? 0) > 0);
  const own = environments.filter((environment) => (matrix.own.get(environment.environmentId) ?? 0) > 0);
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
      <Tile value={matrix.rows.length} label="keys across the project" />
      {missing.map((environment) => (
        <Tile
          key={`missing-${environment.environmentId}`}
          tone="danger"
          value={matrix.missing.get(environment.environmentId) ?? 0}
          label={`missing in ${environment.name}`}
        />
      ))}
      {own.map((environment) => (
        <Tile
          key={`own-${environment.environmentId}`}
          tone="warning"
          value={matrix.own.get(environment.environmentId) ?? 0}
          label={`with its own value in ${environment.name}`}
        />
      ))}
    </div>
  );
}

function Matrix({
  slug,
  matrix,
  environments,
  onAdd,
}: {
  readonly slug: string;
  readonly matrix: CompareMatrix<ListedSecret>;
  readonly environments: readonly EnvironmentRow[];
  readonly onAdd: (environmentId: string, name: string) => void;
}) {
  return (
    // Scrolls sideways inside its own frame on a narrow screen, with the key
    // column pinned, so the page itself never scrolls sideways. `relative`
    // so the visually hidden labels in the cells are positioned inside the
    // frame, not against the page, where they would widen it.
    <div className="relative overflow-x-auto rounded-card border border-hairline">
      <table className="w-full min-w-max border-collapse text-left">
        <caption className="sr-only">Every key and where it is set</caption>
        <thead>
          <tr className="h-10 bg-surface-panel text-xs font-medium text-text-muted">
            <th scope="col" className="sticky left-0 z-10 bg-surface-panel py-0 pr-4 pl-[18px] font-medium">
              Key
            </th>
            {environments.map((environment) => (
              <th key={environment.environmentId} scope="col" className="min-w-[150px] px-4 py-0 font-medium">
                {environment.name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.rows.map((row) => {
            // By opaque id: a name never goes into a URL.
            const to = linkForRow(slug, row);
            return (
              <tr key={row.name} className="h-[52px] border-t border-hairline">
                <th scope="row" className="sticky left-0 z-10 bg-surface-base py-1 pr-4 pl-[18px] font-normal">
                  <Link
                    to={to}
                    className={`inline-flex min-h-11 items-center rounded-input font-mono text-[13px] text-text-primary no-underline hover:underline lg:min-h-8 lg:pointer-coarse:min-h-11 ${focusRing}`}
                  >
                    {row.name}
                  </Link>
                </th>
                {row.cells.map((cell) => (
                  <td key={cell.environmentId} className="px-4 py-1">
                    {cell.kind === "missing" ? (
                      <button
                        type="button"
                        onClick={() => onAdd(cell.environmentId, row.name)}
                        className={`inline-flex min-h-11 cursor-pointer items-center rounded-[7px] transition-opacity hover:opacity-80 lg:min-h-8 lg:pointer-coarse:min-h-11 ${focusRing}`}
                      >
                        <CoverageCell kind="missing" suffix="Add" />
                        <span className="sr-only">
                          {" "}
                          {row.name} to {cell.environmentName}
                        </span>
                      </button>
                    ) : (
                      <CoverageCell kind={cell.kind} />
                    )}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
