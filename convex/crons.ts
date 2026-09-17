import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

const crons = cronJobs();

/**
 * Every fifteen minutes rather than daily.
 *
 * The interval is not about disk. It is the upper bound on how long a Convex
 * query subscription can keep serving results for a session that has already
 * expired: a query re-runs when a row it read changes, and for an expired
 * session the only change that will ever come is this deletion. See the long
 * note in `sessions.ts`. Fifteen minutes on a twelve hour session is a stale
 * window of about two tenths of one percent of the lifetime, at the cost of
 * one indexed range read that usually finds nothing.
 *
 * `handshakeNonces` needs the same treatment and does not have it yet. That is
 * recorded in the backend plan and is not this change.
 */
crons.interval(
  "prune expired sessions",
  { minutes: 15 },
  internal.sessions.pruneExpiredSessions,
  {},
);

export default crons;
