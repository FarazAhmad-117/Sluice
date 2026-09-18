import { Outlet } from "react-router";
import { AuthProvider } from "@/lib/auth/auth-context";
import { ConvexClientProvider } from "@/lib/convex-provider";
import { ThemeProvider } from "@/lib/theme";

/**
 * THE ROOT ROUTE. Every other route in this application is a child of it.
 *
 * It exists to put the three providers in exactly one place, which is what the
 * Next application's `(dash)` route group did. The reason for a route rather
 * than a wrapper around `<RouterProvider>` is that a route can carry an
 * `errorElement`, so a throw from anything below lands somewhere that renders a
 * page instead of a blank document.
 *
 * PROVIDER ORDER MATTERS. `AuthProvider` calls Convex, so it sits inside
 * `ConvexClientProvider`. `ThemeProvider` is outermost because it touches only
 * the document element and nothing else depends on it.
 *
 * There is no `ThemeScript` here. The pre-paint script is injected into
 * `index.html` by `vite.config.ts`; see `lib/theme-storage.ts` for why.
 */
export function Providers() {
  return (
    <ThemeProvider>
      <ConvexClientProvider>
        <AuthProvider>
          <Outlet />
        </AuthProvider>
      </ConvexClientProvider>
    </ThemeProvider>
  );
}
