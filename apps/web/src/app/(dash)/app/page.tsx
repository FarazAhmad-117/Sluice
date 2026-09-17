"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { primaryButton, textLink } from "@/components/app/controls";
import { AppShell } from "@/components/app/shell";
import { useAuth } from "@/lib/auth/auth-context";
import { CONVEX_URL_MISSING_MESSAGE } from "@/lib/convex-url";

/**
 * THE DASHBOARD ROUTE.
 *
 * A client component with no server-side session check, and that is not a gap
 * to be fixed later: it is forced by the architecture. The session token is a
 * Convex function ARGUMENT held in this tab's `sessionStorage`, so a server
 * component cannot see it, cannot validate it, and has nothing to redirect on.
 * What protects the data is that every Convex query refuses without a valid
 * token. This redirect is a convenience so an unauthenticated visitor lands on
 * the sign-in page instead of on three empty panes, and it is NOT the access
 * control. The access control is `requireSession` on the server.
 *
 * THE HYDRATION GATE. `AuthProvider` reads `sessionStorage` in an effect,
 * because it does not exist during server rendering. So the first client render
 * always reports "no session", and redirecting on that render would bounce
 * every signed-in user to the login page on every refresh. `hydrated` holds the
 * redirect back until the stored session has actually been looked for.
 */
export default function DashboardPage() {
  const router = useRouter();
  const { session, configured, hydrated } = useAuth();

  useEffect(() => {
    if (hydrated && session === null) router.replace("/login");
  }, [hydrated, session, router]);

  if (!configured) {
    return (
      <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-5 bg-surface-base px-5 text-text-primary">
        <p role="alert" className="max-w-xl text-base">
          {CONVEX_URL_MISSING_MESSAGE}
        </p>
        <Link href="/" className={textLink}>
          Back to the home page
        </Link>
      </main>
    );
  }

  if (!hydrated || session === null) {
    return (
      <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-5 bg-surface-base px-5 text-text-primary">
        <p className="text-base text-text-muted">Checking for a session</p>
        <Link href="/login" className={primaryButton}>
          Sign in
        </Link>
      </main>
    );
  }

  return <AppShell />;
}
