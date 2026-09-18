import { Link } from "react-router";
import { primaryButton, textLink } from "@/components/app/controls";
import { SITE_URL } from "@/lib/site-url";

/**
 * The catch-all.
 *
 * It matters more here than it would on a server-rendered application. This is
 * a single-page build, so the host has to rewrite every unknown path to
 * `index.html` for client routing to work at all; the consequence is that a
 * genuine typo does not 404 at the edge, it loads the whole application and
 * arrives at this route. Without it the viewer gets a blank page and no reason.
 *
 * It says nothing about whether the path exists for somebody else. An admin
 * panel that answered "that organisation is not yours" rather than "no such
 * page" would be a membership oracle for anyone with a list of ids.
 */
export default function NotFoundRoute() {
  return (
    <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-5 bg-surface-base px-5 text-text-primary">
      <div className="flex w-full max-w-md flex-col gap-4">
        <h1 className="text-2xl font-medium">No such page</h1>
        <p className="text-base text-text-muted">
          That address is not part of the admin panel.
        </p>
        <div className="flex flex-wrap items-center gap-4">
          <Link to="/app" className={`${primaryButton} w-auto`}>
            Go to the dashboard
          </Link>
          <a href={SITE_URL} className={textLink}>
            Back to the site
          </a>
        </div>
      </div>
    </main>
  );
}
