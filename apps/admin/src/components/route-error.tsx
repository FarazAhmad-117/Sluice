import { isRouteErrorResponse, useRouteError } from "react-router";
import { SITE_URL } from "@/lib/site-url";

/**
 * THE LAST PAGE BEFORE A BLANK DOCUMENT.
 *
 * A throw from any route below the root lands here instead of unmounting the
 * tree and leaving the viewer looking at white. It is deliberately plain: this
 * renders when something in the application is already wrong, so it depends on
 * as little of the application as possible. No Convex, no auth context, no
 * hooks beyond the router's own.
 *
 * WHAT IT DOES NOT PRINT. Not the stack, and not the error's own message in
 * production. This surface holds an authenticated session and decrypted secret
 * names; an unhandled error's message can carry a fragment of whatever it was
 * handling, and an error page is exactly the screen people photograph and paste
 * into a chat. In development the message is shown, because there it is the
 * whole point.
 *
 * THE RELOAD IS A FULL DOCUMENT LOAD, not a router navigation. The React tree
 * that threw is still mounted; navigating within it would re-enter the same
 * broken state. Reloading also drops the in-memory vault, which is the correct
 * outcome after an unexplained failure.
 */
export function RouteError() {
  const error = useRouteError();

  const title = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : "Something went wrong";

  const detail =
    import.meta.env.DEV && error instanceof Error ? error.message : null;

  return (
    <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-5 bg-surface-base px-5 text-text-primary">
      <div className="flex w-full max-w-md flex-col gap-4">
        <h1 className="text-2xl font-medium">{title}</h1>
        <p className="text-base text-text-muted">
          The admin panel hit an error it could not recover from. Your secrets are unaffected: this
          browser holds the only key that opens them, and it was never sent anywhere.
        </p>
        {detail === null ? null : (
          <pre className="overflow-x-auto rounded-input border border-hairline bg-surface-deep p-3 font-mono text-sm text-text-muted">
            {detail}
          </pre>
        )}
        <div className="flex flex-wrap items-center gap-4 text-base">
          <button
            type="button"
            onClick={() => window.location.assign("/app")}
            className="cursor-pointer rounded-input bg-brand-solid px-4 py-3 font-medium text-text-on-brand-solid transition-colors hover:bg-brand-solid-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
          >
            Reload the dashboard
          </button>
          <a
            href={SITE_URL}
            className="cursor-pointer rounded-input text-brand underline underline-offset-4 transition-colors hover:text-brand-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
          >
            Back to the site
          </a>
        </div>
      </div>
    </main>
  );
}
