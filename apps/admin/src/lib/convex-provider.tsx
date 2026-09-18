import { ConvexProvider, ConvexReactClient } from "convex/react";
import type { ReactNode } from "react";
import { CONVEX_URL } from "./convex-url";

/**
 * One Convex client for the whole application, created at module scope.
 *
 * It is created once rather than inside a component because the client owns a
 * WebSocket and a subscription registry: building a new one on every render, or
 * on every Fast Refresh, would drop every live query and reopen the socket.
 *
 * `null` when the deployment URL is missing. The constructor throws on an
 * undefined URL, and a module-scope throw in a client component blanks the
 * route with a stack trace that names this file rather than the cause, so the
 * failure is carried as a value and rendered as a sentence by
 * `RequireConvex` instead.
 */
export const convexClient: ConvexReactClient | null =
  CONVEX_URL === undefined ? null : new ConvexReactClient(CONVEX_URL);

export function ConvexClientProvider({ children }: { children: ReactNode }) {
  if (convexClient === null) return <>{children}</>;
  return <ConvexProvider client={convexClient}>{children}</ConvexProvider>;
}
