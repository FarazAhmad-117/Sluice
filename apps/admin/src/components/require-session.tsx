import { Navigate, Outlet, useLocation } from "react-router";
import { useAuth } from "@/lib/auth/auth-context";

/**
 * THE ROUTE GUARD, AND WHAT IT IS NOT.
 *
 * THIS IS NOT THE ACCESS CONTROL. It cannot be. The session token is a Convex
 * function ARGUMENT held in this tab's `sessionStorage`, and every query and
 * mutation behind this guard refuses without a valid one -- `requireSession` on
 * the server is what actually protects the data, and it would still protect it
 * if this file were deleted. What this does is stop an unauthenticated visitor
 * landing on three empty panes and reading that as a broken product.
 *
 * Do not add anything here that the server does not also enforce. A check that
 * exists only in the browser is a check an attacker skips by not running the
 * browser.
 *
 * WHERE THE USER COMES BACK TO. The location is carried in the navigation state
 * so that signing in returns to the page that was asked for, rather than
 * dumping everyone on the dashboard root. `login.tsx` and `signup.tsx` read it
 * back through `redirectAfterAuth` in `lib/redirect.ts`.
 *
 * `replace` rather than a push, so the back button does not walk the user
 * straight into the guard again.
 *
 * THERE IS NO "STILL CHECKING" STATE HERE. The session is read synchronously
 * before the first render, because this application has no server render; see
 * the note above `AuthState` in `lib/auth/auth-context.tsx`. Under Next this
 * guard had to wait for a hydration flag or it bounced every signed-in user to
 * the sign-in page on every refresh.
 */
export function RequireSession() {
  const { session } = useAuth();
  const location = useLocation();

  if (session === null) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }

  return <Outlet />;
}
