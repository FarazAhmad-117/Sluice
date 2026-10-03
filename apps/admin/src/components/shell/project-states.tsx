import { Button } from "@/components/ui/button";
import { pageGutter } from "@/components/ui/styles";
import { PageHeader } from "./page-header";

/**
 * THE TWO STATES EVERY PROJECT PAGE SHARES BEFORE IT HAS A PROJECT TO SHOW.
 *
 * One component each, so Overview, Secrets and Compare say the same thing in
 * the same place when a slug matches nothing.
 */

export function ProjectNotFound({ slug, title }: { readonly slug: string; readonly title: string }) {
  return (
    <>
      <PageHeader title={title} crumbs={[{ label: "Projects", to: "/projects" }]} />
      <div className={`py-6 ${pageGutter}`}>
        <div className="flex flex-col items-center gap-5 rounded-card border border-dashed border-hairline-strong px-6 py-16 text-center">
          <div className="flex flex-col gap-2">
            <h1 className="m-0 text-xl font-semibold text-text-primary">No project called “{slug}”</h1>
            <p className="m-0 text-sm text-text-muted">It may have been renamed, or it belongs to another organisation.</p>
          </div>
          <Button to="/projects" variant="secondary">
            Back to projects
          </Button>
        </div>
      </div>
    </>
  );
}

export function NoEnvironments() {
  return (
    <div className="rounded-card border border-dashed border-hairline-strong px-6 py-14 text-center">
      <h2 className="m-0 text-lg font-semibold text-text-primary">This project has no environments</h2>
      <p className="m-0 mt-2 text-sm text-text-muted">Secrets live in an environment, and this project has none.</p>
    </div>
  );
}
