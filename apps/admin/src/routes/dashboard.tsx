import { AppShell } from "@/components/app/shell";
import { textLink } from "@/components/app/controls";
import { useAuth } from "@/lib/auth/auth-context";
import { CONVEX_URL_MISSING_MESSAGE } from "@/lib/convex-url";
import { SITE_URL } from "@/lib/site-url";

/**
 * THE DASHBOARD ROUTE.
 *
 * There is no session check here. `RequireSession` is the parent route, so
 * nothing below it renders without one, and duplicating the check would only
 * create a second place for the two to disagree. What actually protects the
 * data is neither of them: every Convex query behind this refuses without a
 * valid token, and `requireSession` on the server is the access control.
 *
 * WHAT IS LEFT FOR THIS FILE IS THE UNCONFIGURED BUILD. A deployment with no
 * Convex URL renders a shell whose every query rejects, which reads as a broken
 * product rather than as a missing environment variable. `configured` is false
 * in exactly that case and the sentence below says what to do about it.
 */
export default function DashboardRoute() {
  const { configured } = useAuth();

  if (!configured) {
    return (
      <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-5 bg-surface-base px-5 text-text-primary">
        <p role="alert" className="max-w-xl text-base">
          {CONVEX_URL_MISSING_MESSAGE}
        </p>
        <a href={SITE_URL} className={textLink}>
          Back to the site
        </a>
      </main>
    );
  }

  return <AppShell />;
}
