/**
 * A PROJECT'S RECENT ACTIVITY, AS LINES A PERSON READS.
 *
 * STUB. The audit query (`activity.listProjectActivity`, plan task B2) and the
 * sentence builder (`lib/activity/describe.ts`, task F5) are not merged yet,
 * so this returns `undefined`, which every caller renders as loading. Nothing
 * is invented in the meantime: no placeholder events, no sample sentences.
 *
 * TODO(F5): wrap `api.activity.listProjectActivity` and map its events through
 * `describe.ts`. `null` is reserved for "could not be loaded".
 */

export interface ActivityLine {
  /** Stable across renders, for React keys. */
  readonly id: string;
  readonly at: number;
  /** "You added LOG_LEVEL to all environments". Names come from rows this browser opened. */
  readonly sentence: string;
  /** One character for the avatar: the actor's initial. */
  readonly initial: string;
}

/** `undefined` while loading, `null` when it failed, else newest first. */
export function useProjectActivity(request: {
  readonly projectId: string | null;
  readonly limit: number;
}): readonly ActivityLine[] | null | undefined {
  void request;
  return undefined;
}
