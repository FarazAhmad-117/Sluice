import type { TokenTarget } from "./token-crypto";

/**
 * WHAT THE DASHBOARD CAN HONESTLY SAY ABOUT A TOKEN'S CONNECTION.
 *
 * The only signal is `lastSeenAt`, written on every handshake. A running
 * `sluice run` re-handshakes at half its credential's five-minute lifetime
 * (`packages/cli/src/shell.ts`), so a live process is seen about every two and
 * a half minutes. "Live" allows one missed refresh before it says otherwise.
 * Nothing measures how many processes share a token, so nothing here claims to.
 */

export const LIVE_WINDOW_MS = 6 * 60 * 1000;

export type ConnectionState = "live" | "idle" | "never" | "revoked" | "expired";

export function connectionState(
  token: {
    readonly status: "active" | "revoked";
    readonly lastSeenAt: number | null;
    readonly expiresAt: number | null;
  },
  now: number,
): ConnectionState {
  if (token.status === "revoked") return "revoked";
  if (token.expiresAt !== null && token.expiresAt <= now) return "expired";
  if (token.lastSeenAt === null) return "never";
  return now - token.lastSeenAt < LIVE_WINDOW_MS ? "live" : "idle";
}

export const CONNECTION_LABEL: Record<ConnectionState, string> = {
  live: "Live",
  idle: "Idle",
  never: "Never connected",
  revoked: "Revoked",
  expired: "Expired",
};

/** A token that can still be revoked: anything not already revoked. */
export function canRevoke(state: ConnectionState): boolean {
  return state !== "revoked";
}

export const TARGET_LABEL: Record<TokenTarget, string> = {
  computer: "Computer",
  server: "Server",
  ci: "CI",
  docker: "Docker",
};
