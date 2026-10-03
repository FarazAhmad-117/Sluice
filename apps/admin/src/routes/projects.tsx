import { useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { Callout, Skeleton } from "@/components/ui/feedback";
import { IconPlus, IconSearch, IconUpload } from "@/components/ui/icons";
import { EnvPill } from "@/components/ui/pill";
import { PageHeader, PhoneActionBar } from "@/components/shell/page-header";
import { compactHeight, focusRing, pageGutter } from "@/components/ui/styles";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";
import type { CurrentOrgStatus } from "@/lib/orgs/use-current-org";
import { filterProjects, secretsLabel } from "@/lib/projects/project-overview";
import { useProjectOverview } from "@/lib/projects/use-project-overview";
import type { ProjectCard } from "@/lib/projects/use-project-overview";

/**
 * THE PROJECTS HOME: ONE CARD PER PROJECT, AND ONE WAY TO START A NEW ONE.
 *
 * A card shows what is known and nothing else: the name, a secret count, and
 * the environment names. There is no connection data in this slice, so there
 * are no status dots and no "connected" line.
 */

const IMPORT_TO = "/projects/new?start=import";

export default function ProjectsRoute() {
  const { status, error, retry, org } = useCurrentOrg();
  const { projects } = useProjectOverview();
  return (
    <ProjectsView
      status={org === null && status === "ready" ? "loading" : status}
      error={error}
      retry={retry}
      projects={projects}
    />
  );
}

/** The page from its data, with no queries of its own. */
export function ProjectsView({
  status,
  error,
  retry,
  projects,
}: {
  readonly status: CurrentOrgStatus;
  readonly error: string | null;
  readonly retry: () => void;
  readonly projects: readonly ProjectCard[] | undefined;
}) {
  const [query, setQuery] = useState("");

  if (status === "failed") {
    return (
      <Page>
        <Callout
          tone="danger"
          role="alert"
          title="Your workspace could not be set up"
          action={<Button onClick={retry}>Try again</Button>}
        >
          {error}
        </Callout>
      </Page>
    );
  }

  const loading = status !== "ready" || projects === undefined;
  if (loading) {
    return (
      <Page>
        <div role="status" aria-label={status === "creating" ? "Setting up your workspace" : "Loading projects"}>
          {status === "creating" ? (
            <p className="m-0 mb-6 text-sm text-text-muted">Setting up your Personal workspace…</p>
          ) : null}
          <CardGrid>
            {[0, 1, 2].map((index) => (
              <div key={index} className="flex flex-col gap-[18px] rounded-card border border-hairline bg-surface-panel p-[22px]">
                <div className="flex items-center gap-3">
                  <Skeleton className="size-9 rounded-[9px]" />
                  <div className="flex grow flex-col gap-2">
                    <Skeleton className="h-4 w-2/3" />
                    <Skeleton className="h-3 w-1/3" />
                  </div>
                </div>
                <Skeleton className="h-[26px] w-1/2 rounded-full" />
              </div>
            ))}
          </CardGrid>
        </div>
      </Page>
    );
  }

  if (projects.length === 0) {
    return (
      <Page>
        <div className="flex flex-col items-center gap-6 rounded-card border border-dashed border-hairline-strong px-6 py-16 text-center sm:py-20">
          <div className="flex max-w-md flex-col gap-2">
            <h2 className="m-0 text-xl font-semibold tracking-[-0.01em] text-text-primary">
              Create your first project
            </h2>
            <p className="m-0 text-sm text-text-muted">
              A project holds the secrets for one app. It starts with a development environment.
            </p>
          </div>
          <div className="flex w-full flex-col justify-center gap-3 sm:w-auto sm:flex-row">
            <Button to="/projects/new" size="lg" icon={<IconPlus className="size-3.5" />}>
              New project
            </Button>
            <Button to={IMPORT_TO} variant="secondary" size="lg" icon={<IconUpload className="size-4" />}>
              Import a .env
            </Button>
          </div>
        </div>
      </Page>
    );
  }

  const shown = filterProjects(projects, query);

  return (
    <Page withNew>
      <div className="flex flex-col gap-5">
        <label
          className={`flex ${compactHeight} w-full items-center gap-2 rounded-input border border-hairline-strong bg-surface-panel px-2.5 text-text-muted transition-colors focus-within:border-brand sm:w-[320px]`}
        >
          <IconSearch className="size-3.5 shrink-0" />
          <span className="sr-only">Search projects</span>
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search projects"
            className="h-full min-w-0 grow bg-transparent text-base text-text-primary outline-none placeholder:text-text-muted lg:text-[13px]"
          />
        </label>

        <p role="status" className="sr-only">
          {query.trim() === "" ? "" : `${shown.length} of ${projects.length} projects`}
        </p>

        {shown.length === 0 ? (
          <div className="flex flex-col items-center gap-3 rounded-card border border-hairline px-6 py-12 text-center">
            <p className="m-0 text-sm text-text-primary">No projects match “{query.trim()}”.</p>
            <Button variant="secondary" onClick={() => setQuery("")}>
              Clear search
            </Button>
          </div>
        ) : (
          <CardGrid>
            {shown.map((project) => (
              <ProjectCardLink key={project.projectId} project={project} />
            ))}
          </CardGrid>
        )}

        <div className="mt-2 flex flex-col gap-4 rounded-card border border-dashed border-hairline-strong p-5 sm:flex-row sm:items-center sm:justify-between sm:px-[22px]">
          <div className="flex flex-col gap-1">
            <span className="text-sm font-semibold text-text-primary">Moving off .env files?</span>
            <span className="text-sm text-text-muted">
              Drop a .env into a new project. Values are encrypted in this browser before they're saved.
            </span>
          </div>
          <Button to={IMPORT_TO} variant="secondary">
            Import a .env
          </Button>
        </div>
      </div>
    </Page>
  );
}

/** The page frame: the shell's header (with New project once there is a list), then the body. */
function Page({ children, withNew = false }: { readonly children: ReactNode; readonly withNew?: boolean }) {
  const { org } = useCurrentOrg();
  return (
    <>
      <PageHeader
        title="Projects"
        crumbs={org === null ? [] : [{ label: org.name }]}
        actions={
          withNew ? (
            <Button to="/projects/new" size="sm" icon={<IconPlus className="size-3.5" />}>
              New project
            </Button>
          ) : undefined
        }
      />
      <div className={`flex flex-col gap-5 py-6 ${pageGutter}`}>
        <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">Projects</h1>
        {children}
      </div>
      {withNew ? (
        // On a phone the primary action sits at the bottom, under the thumb.
        <PhoneActionBar>
          <Button to="/projects/new" size="lg" icon={<IconPlus className="size-4" />} className="w-full">
            New project
          </Button>
        </PhoneActionBar>
      ) : null}
    </>
  );
}

function CardGrid({ children }: { readonly children: ReactNode }) {
  return <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 sm:gap-4 lg:grid-cols-3">{children}</div>;
}

function ProjectCardLink({ project }: { readonly project: ProjectCard }) {
  const count =
    project.secretCount === undefined ? (
      <Skeleton className="h-3 w-16" />
    ) : project.secretCount === null ? (
      "Count unavailable"
    ) : (
      secretsLabel(project.secretCount)
    );

  return (
    <Link
      to={`/projects/${project.slug}`}
      className={`flex min-w-0 flex-col gap-2.5 rounded-card border border-hairline bg-surface-panel p-4 text-inherit no-underline transition-colors hover:border-hairline-strong hover:bg-surface-card sm:gap-[18px] sm:p-[22px] ${focusRing}`}
    >
      <div className="flex min-w-0 items-center gap-3">
        <span
          aria-hidden="true"
          className="hidden size-9 shrink-0 items-center justify-center rounded-[9px] border border-hairline-strong bg-surface-card font-semibold text-text-primary sm:flex"
        >
          {project.name.slice(0, 1).toUpperCase()}
        </span>
        <div className="flex min-w-0 grow items-center justify-between gap-3 sm:flex-col sm:items-start sm:gap-0.5">
          <span className="max-w-full min-w-0 truncate font-semibold text-text-primary sm:text-base">{project.name}</span>
          <span className="shrink-0 text-[13px] text-text-muted">{count}</span>
        </div>
      </div>
      {project.environments === undefined ? (
        <Skeleton className="h-[26px] w-1/2 rounded-full" />
      ) : (
        <>
          <span className="truncate text-sm text-text-muted sm:hidden">{project.environments.join(" · ")}</span>
          <div className="hidden flex-wrap gap-1.5 sm:flex">
            {project.environments.map((name) => (
              <EnvPill key={name} name={name} />
            ))}
          </div>
        </>
      )}
    </Link>
  );
}
