import type { ReactNode } from "react";
import { AuthProvider } from "@/lib/auth/auth-context";
import { ConvexClientProvider } from "@/lib/convex-provider";
import { ThemeProvider, ThemeScript } from "@/lib/theme";

/**
 * THE PRODUCT SURFACE: sign up, sign in, and the dashboard shell.
 *
 * A route group, so the URLs stay `/signup`, `/login` and `/app`. It exists to
 * put the three providers in exactly one place and to keep them OFF the landing
 * page, which is dark locked, has no session, and must not open a Convex
 * WebSocket just to render a marketing page.
 *
 * `ThemeScript` is first, above every other element, because it has to set
 * `data-theme` before the browser paints. See `lib/theme.tsx`.
 *
 * Provider order matters: `AuthProvider` calls Convex, so it sits inside
 * `ConvexClientProvider`.
 */
export default function DashLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <ThemeScript />
      <ThemeProvider>
        <ConvexClientProvider>
          <AuthProvider>{children}</AuthProvider>
        </ConvexClientProvider>
      </ThemeProvider>
    </>
  );
}
