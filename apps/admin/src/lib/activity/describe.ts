import { listOf } from "@/lib/list-of";

/**
 * A PROJECT'S AUDIT EVENTS, AS SENTENCES. Pure.
 *
 * The server sends what happened to which row (`activity.listProjectActivity`)
 * and never a name: secret names exist only as ciphertext. Names come from the
 * rows this browser has already opened. A secret whose row is no longer
 * listed (deleted, or an older version an edit replaced) has no name here and
 * is called "a secret"; nothing is guessed.
 *
 * ONE SHARED WRITE IS ONE LINE. Adding, changing or deleting a secret for
 * every environment writes one event per environment row, in one transaction.
 * Consecutive events with the same action and actor, about the same key (or
 * the same unnamed secret kind), in different environments, within two
 * seconds, read as one: "You added LOG_LEVEL to all environments".
 */

export interface ActivityEvent {
  readonly at: number;
  readonly action: string;
  readonly actorIsYou: boolean;
  readonly actorEmail: string | null;
  readonly targetKind: "secret" | "environment" | "project";
  readonly targetId: string;
  readonly environmentId: string | null;
}

export interface DescribeContext {
  /** Opened secret names, by secret row id, across every environment. */
  readonly secretNames: ReadonlyMap<string, string>;
  /** Environment names, by environment id. */
  readonly environmentNames: ReadonlyMap<string, string>;
  /** How many environments the project has: "all environments" means every one. */
  readonly environmentCount: number;
  readonly projectName: string;
  /** The signed-in person's email, for their own avatar initial. */
  readonly selfEmail: string;
}

export interface ActivityLine {
  /** Stable across renders, for React keys. */
  readonly id: string;
  readonly at: number;
  readonly sentence: string;
  /** One character for the avatar. */
  readonly initial: string;
}

const COLLAPSE_MS = 2_000;

function actorOf(event: ActivityEvent): string {
  if (event.actorIsYou) return "You";
  // No email means a service token, or somebody no longer in the org: the
  // server does not say which, so neither does this.
  return event.actorEmail ?? "Someone";
}

function initialOf(event: ActivityEvent, context: DescribeContext): string {
  const source = event.actorIsYou ? context.selfEmail : event.actorEmail;
  return (source ?? "?").slice(0, 1).toUpperCase() || "?";
}

function placeOf(environmentIds: readonly string[], context: DescribeContext): string {
  const distinct = [...new Set(environmentIds)];
  if (distinct.length > 1 && distinct.length >= context.environmentCount) return "all environments";
  return listOf(distinct.map((id) => context.environmentNames.get(id) ?? "an environment"));
}

const SECRET_VERB: Record<string, { verb: string; preposition: string }> = {
  "secret.create": { verb: "added", preposition: "to" },
  "secret.update": { verb: "changed", preposition: "in" },
  "secret.delete": { verb: "deleted", preposition: "from" },
};

function sentenceFor(group: readonly ActivityEvent[], context: DescribeContext): string {
  const first = group[0]!;
  const actor = actorOf(first);
  if (first.targetKind === "secret") {
    const name = context.secretNames.get(first.targetId) ?? "a secret";
    const place = placeOf(
      group.map((event) => event.environmentId).filter((id): id is string => id !== null),
      context,
    );
    const words = SECRET_VERB[first.action];
    if (words !== undefined) return `${actor} ${words.verb} ${name} ${words.preposition} ${place}`;
    return `${actor} changed ${name} in ${place}`;
  }
  if (first.targetKind === "environment") {
    const environment = context.environmentNames.get(first.targetId) ?? "an environment";
    return first.action === "environment.create"
      ? `${actor} created ${environment}`
      : `${actor} changed ${environment}`;
  }
  return first.action === "project.create"
    ? `${actor} created ${context.projectName}`
    : `${actor} changed ${context.projectName}`;
}

/** Whether `next` is another row of the same shared write as `group`. */
function belongs(group: readonly ActivityEvent[], next: ActivityEvent, context: DescribeContext): boolean {
  const first = group[0]!;
  if (first.targetKind !== "secret" || next.targetKind !== "secret") return false;
  if (next.action !== first.action || next.actorIsYou !== first.actorIsYou || next.actorEmail !== first.actorEmail) {
    return false;
  }
  if (Math.abs(first.at - next.at) > COLLAPSE_MS) return false;
  if (group.some((event) => event.environmentId === next.environmentId)) return false;
  return context.secretNames.get(first.targetId) === context.secretNames.get(next.targetId);
}

/** Newest first in, newest first out. */
export function describeActivity(events: readonly ActivityEvent[], context: DescribeContext): ActivityLine[] {
  const groups: ActivityEvent[][] = [];
  for (const event of events) {
    const last = groups[groups.length - 1];
    if (last !== undefined && belongs(last, event, context)) last.push(event);
    else groups.push([event]);
  }
  return groups.map((group) => {
    const first = group[0]!;
    return {
      id: `${first.at}-${first.action}-${first.targetId}`,
      at: first.at,
      sentence: sentenceFor(group, context),
      initial: initialOf(first, context),
    };
  });
}

export interface ActivityDay {
  /** "Today", "Yesterday", or "Oct 2, 2026". */
  readonly label: string;
  readonly lines: readonly ActivityLine[];
}

const DAY_LABEL = new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric" });

function dayStart(at: number): number {
  const date = new Date(at);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

/** Lines grouped by local day, keeping their order. */
export function groupByDay(lines: readonly ActivityLine[], now: number): ActivityDay[] {
  const today = dayStart(now);
  const yesterday = dayStart(today - 1);
  const days: { start: number; label: string; lines: ActivityLine[] }[] = [];
  for (const line of lines) {
    const start = dayStart(line.at);
    const last = days[days.length - 1];
    if (last !== undefined && last.start === start) {
      last.lines.push(line);
      continue;
    }
    const label = start === today ? "Today" : start === yesterday ? "Yesterday" : DAY_LABEL.format(start);
    days.push({ start, label, lines: [line] });
  }
  return days.map(({ label, lines: dayLines }) => ({ label, lines: dayLines }));
}
