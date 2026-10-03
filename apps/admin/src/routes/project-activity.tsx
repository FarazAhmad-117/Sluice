import { ActivityRow, ActivitySkeletonRows } from "@/components/activity/activity-row";
import { PageHeader } from "@/components/shell/page-header";
import { ProjectNotFound } from "@/components/shell/project-states";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/feedback";
import { pageGutter } from "@/components/ui/styles";
import { groupByDay } from "@/lib/activity/describe";
import { useProjectActivity } from "@/lib/activity/use-project-activity";
import { useNow } from "@/lib/format/use-now";
import { useProject } from "@/lib/projects/project-context";

/**
 * WHAT HAPPENED IN THIS PROJECT, NEWEST FIRST, BY DAY.
 *
 * Sentences come from `lib/activity/describe.ts`: names from rows this browser
 * opened, "a secret" for one that is gone, one line per shared write. The
 * server keeps the full log; this page shows the latest hundred events.
 */

const LIMIT = 100;

export default function ProjectActivityRoute() {
  const { slug, data } = useProject();
  const projectId = data.status === "ready" ? data.project.projectId : null;
  const lines = useProjectActivity({ projectId, limit: LIMIT });
  const now = useNow();

  if (data.status === "not-found") return <ProjectNotFound slug={slug} title="Activity" />;
  const name = data.status === "ready" ? data.project.name : slug;
  const days = lines === undefined || lines === null ? [] : groupByDay(lines, now);

  return (
    <>
      <PageHeader title="Activity" crumbs={[{ label: name, to: `/projects/${slug}` }]} />
      <div className={`flex max-w-[760px] flex-col gap-5 py-6 ${pageGutter}`}>
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">Activity</h1>
          <p className="m-0 text-text-muted">Who changed what in {name}, newest first.</p>
        </div>

        {lines === undefined ? (
          <ul role="status" aria-label="Loading activity" className="m-0 list-none rounded-card border border-hairline p-0 px-4 [&>li:first-child]:border-t-0">
            <ActivitySkeletonRows count={8} />
          </ul>
        ) : lines === null ? (
          <Callout
            tone="danger"
            role="alert"
            title="Activity could not be loaded"
            action={
              <Button variant="secondary" onClick={() => window.location.reload()}>
                Reload
              </Button>
            }
          >
            Your secrets are unaffected. Reload to try again.
          </Callout>
        ) : lines.length === 0 ? (
          <div className="rounded-card border border-dashed border-hairline-strong px-6 py-14 text-center">
            <h2 className="m-0 text-lg font-semibold text-text-primary">Nothing has happened here yet</h2>
            <p className="m-0 mt-2 text-sm text-text-muted">Adding, changing and deleting secrets shows up here.</p>
          </div>
        ) : (
          <>
            {days.map((day, index) => (
              <section key={day.label} aria-labelledby={`activity-day-${index}`} className="flex flex-col gap-2">
                <h2 id={`activity-day-${index}`} className="m-0 text-xs font-medium text-text-muted">
                  {day.label}
                </h2>
                <ul className="m-0 list-none rounded-card border border-hairline bg-surface-panel p-0 px-4 [&>li:first-child]:border-t-0">
                  {day.lines.map((line) => (
                    <ActivityRow key={line.id} line={line} />
                  ))}
                </ul>
              </section>
            ))}
            {lines.length >= LIMIT ? (
              <p className="m-0 text-[13px] text-text-muted">Showing the latest {LIMIT} events.</p>
            ) : null}
          </>
        )}
      </div>
    </>
  );
}
