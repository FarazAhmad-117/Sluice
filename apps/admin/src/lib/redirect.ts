/**
 * WHERE A SIGNED-IN USER LANDS, kept out of `require-session.tsx` so that file
 * exports a component and nothing else. A module that exports both a component
 * and a plain function loses React Fast Refresh: an edit to either one remounts
 * the tree instead of patching it, which in this application means losing the
 * in-memory vault and being asked for the password again on every save.
 */

/**
 * Where to send someone once they hold a session.
 *
 * `unknown` rather than a cast, because navigation state is whatever the last
 * caller put there and one of those callers is the browser restoring a history
 * entry from a previous build. An absolute in-app path is accepted and
 * everything else falls back to the dashboard.
 *
 * THE LEADING-SLASH-BUT-NOT-DOUBLE CHECK IS AN OPEN REDIRECT GUARD. `//evil.example`
 * is a protocol-relative URL: it starts with a slash, looks like an in-app
 * path, and sends the browser to another origin.
 */
export function redirectAfterAuth(state: unknown): string {
  if (typeof state === "object" && state !== null && "from" in state) {
    const from = (state as { from: unknown }).from;
    if (typeof from === "string" && from.startsWith("/") && !from.startsWith("//")) {
      return from;
    }
  }
  return "/app";
}
