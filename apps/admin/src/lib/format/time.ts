/**
 * TIMES, AS A PERSON READS THEM. Pure: `now` is passed in, so tests do not
 * depend on the clock.
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function startOfDay(at: number): number {
  const date = new Date(at);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

const DATE = new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric" });
const DATE_TIME = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });

/** "Oct 2, 2026". */
export function formatDate(at: number): string {
  return DATE.format(at);
}

/** "Oct 2, 2026, 3:04 PM": for a `title` beside a relative time. */
export function formatDateTime(at: number): string {
  return DATE_TIME.format(at);
}

/** "just now", "1 minute ago", "3 hours ago", "yesterday", "4 days ago", then a date. */
export function timeAgo(at: number, now: number): string {
  const elapsed = Math.max(0, now - at);
  if (elapsed < 45_000) return "just now";
  if (elapsed < HOUR) {
    const minutes = Math.max(1, Math.round(elapsed / MINUTE));
    return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
  }
  if (startOfDay(at) === startOfDay(now) || elapsed < 6 * HOUR) {
    const hours = Math.max(1, Math.round(elapsed / HOUR));
    return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  }
  const days = Math.round((startOfDay(now) - startOfDay(at)) / DAY);
  if (days <= 1) return "yesterday";
  if (days < 7) return `${days} days ago`;
  return formatDate(at);
}

/** For "created …": "today", "yesterday", "4 days ago", else "on Oct 2, 2026". */
export function createdLabel(at: number, now: number): string {
  const days = Math.round((startOfDay(now) - startOfDay(at)) / DAY);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 7) return `${days} days ago`;
  return `on ${formatDate(at)}`;
}

/**
 * A numeric field that a newer backend adds to a row and an older one does
 * not send (`createdAt` on a project, `updatedAt` on a secret). Read without
 * claiming it in the type, and `undefined` unless it really is a number, so
 * nothing is ever shown for a time nobody recorded.
 */
export function optionalTime(row: object, field: "createdAt" | "updatedAt"): number | undefined {
  const value: unknown = (row as Record<string, unknown>)[field];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}
