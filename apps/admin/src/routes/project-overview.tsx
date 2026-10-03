import { useId, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { PageHeader, PhoneActionBar } from "@/components/shell/page-header";
import { NoEnvironments, ProjectNotFound } from "@/components/shell/project-states";
import { ProjectTile } from "@/components/shell/project-switcher";
import { SoonBadge } from "@/components/shell/sidebar";
import { Button } from "@/components/ui/button";
import { CommandBlock } from "@/components/ui/copy-button";
import { Skeleton } from "@/components/ui/feedback";
import { IconArrowRight, IconCheck, IconPlus } from "@/components/ui/icons";
import { focusRing, pageGutter } from "@/components/ui/styles";
import { ActivityRow, ActivitySkeletonRows } from "@/components/activity/activity-row";
import { CliSetupGuide } from "@/components/projects/cli-setup-guide";
import { CLI_RELEASED } from "@/lib/projects/install";
import { useProjectActivity } from "@/lib/activity/use-project-activity";
import { createdLabel } from "@/lib/format/time";
import { useNow } from "@/lib/format/use-now";
import { DEVELOPMENT, checklist, environmentStats, ranLocallyKey } from "@/lib/projects/overview";
import type { ChecklistStep, EnvironmentStats } from "@/lib/projects/overview";
import { useProject, useProjectActions } from "@/lib/projects/project-context";
import { countProjectSecrets, secretsLabel } from "@/lib/projects/project-overview";
import { runCommand } from "@/lib/projects/run-command";
import type { ProjectSecrets } from "@/lib/secrets/use-project-secrets";
import { useShell } from "@/lib/shell/shell-context";

/**
 * A PROJECT'S OVERVIEW: WHERE IT STANDS, AND THE NEXT STEP.
 *
 * Every number is counted from rows the server listed (see
 * `lib/projects/overview.ts`). The checklist detects its first two steps from
 * data, takes the person's word for the third ("Mark as done", remembered in
 * this browser), and marks the fourth "Soon" because service tokens do not
 * exist yet. Nothing here decrypts a value.
 */

type Ready = Extract<ProjectSecrets, { status: "ready" }>;

export default function ProjectOverviewRoute() {
  const { slug, data } = useProject();
  if (data.status === "not-found") return <ProjectNotFound slug={slug} title="Overview" />;
  if (data.status === "loading") return <OverviewLoading slug={slug} />;
  // Keyed by project, so the checklist's remembered state is read afresh on a switch.
  return <OverviewPage key={data.project.projectId} slug={slug} data={data} />;
}

function OverviewLoading({ slug }: { readonly slug: string }) {
  return (
    <>
      <PageHeader title="Overview" crumbs={[{ label: slug }]} />
      <div role="status" aria-label="Loading the project" className={`flex flex-col gap-6 py-6 ${pageGutter}`}>
        <div className="flex items-center gap-4">
          <Skeleton className="size-12 rounded-card" />
          <div className="flex flex-col gap-2">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-64" />
          </div>
        </div>
        <Skeleton className="h-64 w-full rounded-card" />
        <div className="grid gap-3 sm:grid-cols-2">
          <Skeleton className="h-32 rounded-card" />
          <Skeleton className="h-32 rounded-card" />
        </div>
      </div>
    </>
  );
}

function readRan(projectId: string): boolean {
  try {
    return localStorage.getItem(ranLocallyKey(projectId)) === "1";
  } catch {
    return false;
  }
}

function writeRan(projectId: string, done: boolean): void {
  try {
    if (done) localStorage.setItem(ranLocallyKey(projectId), "1");
    else localStorage.removeItem(ranLocallyKey(projectId));
  } catch {
    // Not remembered across reloads; the step still shows done for now.
  }
}

function OverviewPage({ slug, data }: { readonly slug: string; readonly data: Ready }) {
  const { openAdd } = useProjectActions();
  const now = useNow();
  const [ranLocally, setRanLocally] = useState(() => readRan(data.project.projectId));
  const [runOpen, setRunOpen] = useState(false);
  const allListed = !data.listings.some((listing) => listing.loading || listing.rows === null);
  const secretCount = allListed ? countProjectSecrets(data.listings.map((listing) => listing.rows ?? [])) : undefined;
  const createdAt = data.project.createdAt;
  const runEnvironment =
    data.environments.find((environment) => environment.name === DEVELOPMENT) ?? data.environments[0] ?? null;
  const stats = environmentStats(data.listings, data.namesByEnvironment);
  const noEnvironments = data.environments.length === 0;

  const meta = [
    `${data.environments.length} ${data.environments.length === 1 ? "environment" : "environments"}`,
    secretCount === undefined ? null : secretsLabel(secretCount),
    `created ${createdLabel(createdAt, now)}`,
  ].filter((part): part is string => part !== null);

  const addButton = noEnvironments ? undefined : (
    <Button size="sm" icon={<IconPlus className="size-3.5" />} onClick={() => openAdd()}>
      Add secret
    </Button>
  );

  return (
    <>
      <PageHeader title="Overview" crumbs={[{ label: data.project.name }]} actions={addButton} />
      <div className={`py-6 ${pageGutter}`}>
        <div className="grid items-start gap-7 xl:grid-cols-[minmax(0,1fr)_360px]">
          <div className="flex min-w-0 flex-col gap-[22px]">
            <div className="flex min-w-0 items-center gap-4">
              <ProjectTile name={data.project.name} size="lg" />
              <div className="flex min-w-0 flex-col gap-1">
                <h1 className="m-0 truncate text-2xl font-semibold tracking-[-0.02em] text-text-primary">
                  {data.project.name}
                </h1>
                <span className="text-sm text-text-muted">{meta.join(" · ")}</span>
              </div>
            </div>

            {noEnvironments ? (
              <NoEnvironments />
            ) : (
              <>
                <Checklist
                  projectName={data.project.name}
                  slug={slug}
                  environmentName={runEnvironment?.name ?? DEVELOPMENT}
                  secretCount={secretCount}
                  ranLocally={ranLocally}
                  runOpen={runOpen}
                  onRunOpen={setRunOpen}
                  onRanLocally={(done) => {
                    writeRan(data.project.projectId, done);
                    setRanLocally(done);
                  }}
                  onAddSecret={() => openAdd()}
                />
                <EnvironmentCards slug={slug} stats={stats} loading={data.listings.some((listing) => listing.loading)} />
              </>
            )}
          </div>

          <aside aria-label="Project details" className="flex min-w-0 flex-col gap-4">
            {runEnvironment === null ? null : (
              <RunLocally
                command={runCommand(slug, runEnvironment.name)}
                onShowSteps={() => {
                  setRunOpen(true);
                  requestAnimationFrame(() =>
                    document.getElementById(RUN_SETUP_ID)?.scrollIntoView({ behavior: "smooth", block: "start" }),
                  );
                }}
              />
            )}
            <RecentActivity projectId={data.project.projectId} slug={slug} />
          </aside>
        </div>
      </div>
      {addButton === undefined ? null : (
        <PhoneActionBar>
          <Button size="lg" icon={<IconPlus className="size-4" />} className="w-full" onClick={() => openAdd()}>
            Add secret
          </Button>
        </PhoneActionBar>
      )}
    </>
  );
}

/** The checklist's run step, which "Install and set up" scrolls to. */
const RUN_SETUP_ID = "overview-run-setup";

const CARD = "rounded-card border border-hairline bg-surface-panel";

function Checklist({
  projectName,
  slug,
  environmentName,
  secretCount,
  ranLocally,
  runOpen: expanded,
  onRunOpen: setExpanded,
  onRanLocally,
  onAddSecret,
}: {
  readonly projectName: string;
  readonly slug: string;
  readonly environmentName: string;
  readonly secretCount: number | undefined;
  readonly ranLocally: boolean;
  readonly runOpen: boolean;
  readonly onRunOpen: (open: boolean) => void;
  readonly onRanLocally: (done: boolean) => void;
  readonly onAddSecret: () => void;
}) {
  const { announce } = useShell();
  const state = checklist({ secretCount, ranLocally });
  const runId = useId();
  const order: ChecklistStep[] = ["create", "secrets", "run", "production"];
  const next = order.find((step) => step !== "production" && !state.done.has(step));
  const percent = (state.done.size / state.total) * 100;

  return (
    <section aria-labelledby={`${runId}-title`} className={`${CARD} overflow-hidden`}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-5 py-4">
        <h2 id={`${runId}-title`} className="m-0 text-[15px] font-semibold text-text-primary">
          Get {projectName} running on Sluice
        </h2>
        <span className="flex items-center gap-2.5 text-[13px] text-text-muted">
          {state.done.size} of {state.total} done
          <span
            role="progressbar"
            aria-label="Setup progress"
            aria-valuemin={0}
            aria-valuemax={state.total}
            aria-valuenow={state.done.size}
            className="relative inline-block h-1.5 w-20 overflow-hidden rounded-full bg-surface-card"
          >
            <span className="absolute inset-y-0 left-0 bg-status-healthy" style={{ width: `${percent}%` }} />
          </span>
        </span>
      </div>
      <ol className="m-0 list-none p-0">
        <Step done title="Create the project" current={false} />
        <Step
          done={state.done.has("secrets")}
          current={next === "secrets"}
          title="Add your secrets"
          description={secretCount === undefined ? undefined : "Paste a .env, or add them one at a time."}
          aside={
            secretCount === undefined ? (
              <Skeleton className="h-3.5 w-16" />
            ) : secretCount > 0 ? (
              <span className="text-[13px] text-text-muted">{secretCount} added</span>
            ) : (
              <Button size="sm" onClick={onAddSecret}>
                Add a secret
              </Button>
            )
          }
        />
        <Step
          id={RUN_SETUP_ID}
          done={ranLocally}
          current={next === "run"}
          title="Run your app with these secrets"
          description={`Install the CLI, connect this computer, and start ${environmentName} through Sluice. No .env file needed.`}
          aside={
            <Button
              size="sm"
              variant={next === "run" && !expanded ? "primary" : "secondary"}
              aria-expanded={expanded}
              aria-controls={`${runId}-run`}
              onClick={() => setExpanded(!expanded)}
            >
              {expanded ? "Hide" : ranLocally ? "Show steps" : `Set up ${environmentName}`}
            </Button>
          }
        >
          {expanded ? (
            <div id={`${runId}-run`} className="flex flex-col gap-4 pt-4">
              <CliSetupGuide runCommand={runCommand(slug, environmentName)} environmentName={environmentName} onAnnounce={announce} />
              {/* Nobody can have run it before the CLI ships, so there is nothing to mark. */}
              {CLI_RELEASED ? (
              <div>
                <button
                  type="button"
                  onClick={() => {
                    onRanLocally(!ranLocally);
                    announce(ranLocally ? "Marked as not done." : "Marked as done.");
                  }}
                  className={`-mx-1 inline-flex min-h-11 cursor-pointer items-center rounded-input px-1 text-sm font-medium text-brand hover:text-brand-hover lg:min-h-8 lg:pointer-coarse:min-h-11 ${focusRing}`}
                >
                  {ranLocally ? "Mark as not done" : "Mark as done"}
                </button>
              </div>
              ) : null}
            </div>
          ) : null}
        </Step>
        <Step
          done={false}
          current={false}
          title="Connect production"
          description="A server, a CI pipeline or a container, each with its own revocable token."
          aside={<SoonBadge />}
        />
      </ol>
    </section>
  );
}

function Step({
  id,
  done,
  current,
  title,
  description,
  aside,
  children,
}: {
  readonly id?: string;
  readonly done: boolean;
  readonly current: boolean;
  readonly title: string;
  readonly description?: string | undefined;
  readonly aside?: ReactNode;
  readonly children?: ReactNode;
}) {
  return (
    <li id={id} className={`scroll-mt-20 border-t border-hairline px-5 py-3.5 first:border-t-0 ${current ? "bg-surface-card" : ""}`}>
      <div className="flex items-center gap-3.5">
        {done ? (
          <span className="flex size-[22px] shrink-0 items-center justify-center rounded-full bg-status-healthy text-surface-base">
            <IconCheck className="size-3" strokeWidth={3} />
          </span>
        ) : (
          <span
            aria-hidden="true"
            className={`size-[22px] shrink-0 rounded-full border-[1.5px] ${current ? "border-text-primary" : "border-text-faint"}`}
          />
        )}
        <div className="flex min-w-0 grow flex-col gap-0.5">
          <span className={done ? "text-text-muted line-through" : `text-text-primary ${current ? "font-medium" : ""}`}>
            {title}
            <span className="sr-only">{done ? ", done" : ", not done"}</span>
          </span>
          {description === undefined || done ? null : (
            <span className="text-[13px] text-text-muted">{description}</span>
          )}
        </div>
        {aside === undefined ? null : <div className="flex shrink-0 items-center">{aside}</div>}
      </div>
      {children === undefined || children === null ? null : <div className="pl-9">{children}</div>}
    </li>
  );
}

function EnvironmentCards({
  slug,
  stats,
  loading,
}: {
  readonly slug: string;
  readonly stats: readonly EnvironmentStats[];
  readonly loading: boolean;
}) {
  return (
    <section aria-labelledby="overview-environments" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <h2 id="overview-environments" className="m-0 text-[15px] font-semibold text-text-primary">
          Environments
        </h2>
        <span aria-disabled="true" role="link" className="flex items-center gap-2 text-[13px] text-text-faint">
          Add environment <SoonBadge />
        </span>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {stats.map((row) => {
          const vsDevelopment = row.missingVsDevelopment !== undefined;
          return (
            <Link
              key={row.environmentId}
              to={`/projects/${slug}/secrets?env=${encodeURIComponent(row.name)}`}
              className={`group flex flex-col gap-3.5 ${CARD} p-[18px] text-inherit no-underline transition-colors hover:border-hairline-strong hover:bg-surface-card ${focusRing}`}
            >
              <div className="flex items-center justify-between gap-3">
                <span className="truncate font-semibold text-text-primary">{row.name}</span>
                <IconArrowRight className="size-4 shrink-0 text-text-faint transition-colors group-hover:text-text-primary" />
              </div>
              <dl className="m-0 grid grid-cols-3 gap-2">
                <Stat label="secrets" value={row.secrets} loading={loading} />
                {vsDevelopment ? (
                  <>
                    <Stat label="own value" value={row.own} loading={loading} tone={row.own !== null && row.own > 0 ? "warning" : undefined} />
                    <Stat label="missing vs dev" value={row.missingVsDevelopment ?? null} loading={loading} />
                  </>
                ) : (
                  <>
                    <Stat label="shared" value={row.shared} loading={loading} />
                    <Stat label="only here" value={row.only} loading={loading} />
                  </>
                )}
              </dl>
            </Link>
          );
        })}
      </div>
    </section>
  );
}

function Stat({
  label,
  value,
  loading,
  tone,
}: {
  readonly label: string;
  readonly value: number | null;
  readonly loading: boolean;
  readonly tone?: "warning" | undefined;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="order-last text-xs text-text-muted">{label}</dt>
      <dd className={`m-0 text-xl font-semibold ${tone === "warning" ? "text-status-warning light:text-text-primary" : "text-text-primary"}`}>
        {loading ? (
          <Skeleton className="my-1 h-5 w-6" />
        ) : value === null ? (
          <span title="Could not be counted">
            –<span className="sr-only">not known</span>
          </span>
        ) : (
          value
        )}
      </dd>
    </div>
  );
}

function RunLocally({ command, onShowSteps }: { readonly command: string; readonly onShowSteps: () => void }) {
  const { announce } = useShell();
  return (
    <section aria-labelledby="overview-run" className={`${CARD} flex flex-col gap-2.5 px-[18px] py-4`}>
      <h2 id="overview-run" className="m-0 text-[15px] font-semibold text-text-primary">
        Run locally
      </h2>
      <CommandBlock command={command} label="Copy the run command" onDone={announce} copyable={CLI_RELEASED} />
      <p className="m-0 text-[13px] text-text-muted">
        {CLI_RELEASED ? "Works with any command: python, go, rails, docker." : "The CLI isn’t released yet."}{" "}
        <button
          type="button"
          onClick={onShowSteps}
          className={`-mx-1 inline-flex min-h-11 cursor-pointer items-center rounded-input px-1 font-medium text-brand hover:text-brand-hover lg:min-h-0 lg:pointer-coarse:min-h-11 ${focusRing}`}
        >
          Install and set up
        </button>
      </p>
    </section>
  );
}

function RecentActivity({ projectId, slug }: { readonly projectId: string; readonly slug: string }) {
  const lines = useProjectActivity({ projectId, limit: 5 });
  return (
    <section aria-labelledby="overview-activity" className={`${CARD} overflow-hidden`}>
      <div className="flex items-center justify-between gap-3 py-2 pr-2 pl-[18px]">
        <h2 id="overview-activity" className="m-0 text-[15px] font-semibold text-text-primary">
          Recent activity
        </h2>
        <Link
          to={`/projects/${slug}/activity`}
          className={`inline-flex min-h-11 items-center rounded-input px-2.5 text-[13px] text-text-muted no-underline transition-colors hover:text-text-primary lg:min-h-8 lg:pointer-coarse:min-h-11 ${focusRing}`}
        >
          View all<span className="sr-only"> activity</span>
        </Link>
      </div>
      {lines === undefined ? (
        <ul role="status" aria-label="Loading recent activity" className="m-0 list-none p-0">
          <ActivitySkeletonRows count={5} className="px-[18px]" />
        </ul>
      ) : lines === null ? (
        <p className="m-0 border-t border-hairline px-[18px] py-4 text-[13px] text-text-muted">
          Activity could not be loaded. Reload to try again.
        </p>
      ) : lines.length === 0 ? (
        <p className="m-0 border-t border-hairline px-[18px] py-4 text-[13px] text-text-muted">
          Nothing has happened in this project yet.
        </p>
      ) : (
        <ul className="m-0 list-none p-0">
          {lines.map((line) => (
            <ActivityRow key={line.id} line={line} className="px-[18px]" />
          ))}
        </ul>
      )}
    </section>
  );
}

