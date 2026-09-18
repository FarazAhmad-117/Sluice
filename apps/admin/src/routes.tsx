import { createBrowserRouter, Navigate } from "react-router";
import type { RouteObject } from "react-router";
import { Providers } from "@/components/providers";
import { RequireSession } from "@/components/require-session";
import { RouteError } from "@/components/route-error";
import DashboardRoute from "@/routes/dashboard";
import LoginRoute from "@/routes/login";
import NotFoundRoute from "@/routes/not-found";
import SignupRoute from "@/routes/signup";

/**
 * THE ROUTE TABLE.
 *
 * The URLs are the ones the Next application served -- `/login`, `/signup`,
 * `/app` -- because they are in people's bookmarks and in the marketing site's
 * "sign in" link. Changing them would have been free at the moment of the move
 * and expensive forever afterwards.
 *
 * ONE GUARD, ONE PLACE. `/app` and everything added under it sits inside
 * `RequireSession`, so a route added later is protected by where it is declared
 * rather than by somebody remembering to add a check inside it. The server
 * refuses without a token regardless; see `components/require-session.tsx` for
 * why this is a convenience and not the access control.
 *
 * ROUTES ARE IMPORTED EAGERLY, NOT LAZILY. The whole application is four
 * screens behind a login, and the person waiting for it has just spent 1.6
 * seconds deriving a key; splitting that into chunks would trade a measurable
 * delay mid-flow for a saving nobody can perceive on a first load that is
 * already small. The one exception is below, and it is about what ships rather
 * than about when it loads.
 */

/**
 * THE ARGON2 MEASUREMENT HARNESS, AND WHY IT IS LAZY.
 *
 * The page derives keys in the browser and prints one in full. The key it
 * prints is only ever the published known-answer vector, never user input, but
 * a route that renders a derived key is not a pattern that belongs on a
 * production deployment, and somebody will copy it.
 *
 * Under Next this was a layout that called `notFound()` when `NODE_ENV` was
 * production: the route was unreachable, but the component was still in the
 * build. Here the whole branch is behind `import.meta.env.DEV`, which Rollup
 * evaluates as a constant, so in a production build the array is empty and the
 * dynamic `import()` is dead code that is never emitted. The harness is not
 * hidden from the production bundle; it is absent from it.
 */
const devRoutes: RouteObject[] = import.meta.env.DEV
  ? [
      {
        path: "dev/argon2",
        lazy: async () => {
          const { default: Component } = await import("@/routes/dev-argon2");
          return { Component };
        },
      },
    ]
  : [];

export const router = createBrowserRouter([
  {
    element: <Providers />,
    // On the root route, so a throw from any screen below lands on a page
    // rather than unmounting the tree and leaving a blank document.
    errorElement: <RouteError />,
    children: [
      // The application has no landing page of its own; that is the marketing
      // site. Anyone who reaches the root is on their way to the dashboard, and
      // the guard sends them to sign in from there if they need to.
      { index: true, element: <Navigate to="/app" replace /> },
      { path: "login", element: <LoginRoute /> },
      { path: "signup", element: <SignupRoute /> },
      {
        element: <RequireSession />,
        children: [{ path: "app", element: <DashboardRoute /> }],
      },
      ...devRoutes,
      { path: "*", element: <NotFoundRoute /> },
    ],
  },
]);
