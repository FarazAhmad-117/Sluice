/**
 * THE PROJECT OVERVIEW'S NUMBERS, PURE.
 *
 * Every number is a count of rows the server listed, or of names this browser
 * opened. Where a number cannot be made honestly (a listing failed, or a name
 * did not open, so a comparison by name could be wrong) it is `null` and the
 * page shows nothing in its place rather than a guess.
 */

import type { ScopedRow } from "@/lib/secrets/scope";

export interface OverviewListing<T extends ScopedRow & { readonly secretId: string }> {
  readonly environmentId: string;
  readonly environmentName: string;
  /** `null` when the listing failed. */
  readonly rows: readonly T[] | null;
}

export interface EnvironmentStats {
  readonly environmentId: string;
  readonly name: string;
  /** `null` when the listing failed; every count below is then `null` too. */
  readonly secrets: number | null;
  /** Rows of a shared secret that use the shared value. */
  readonly shared: number | null;
  /** Rows of a shared secret that keep their own value here. */
  readonly own: number | null;
  /** Rows that exist in this environment only. */
  readonly only: number | null;
  /**
   * Keys development has and this environment does not, by opened name.
   * `undefined` for development itself, and for every environment when the
   * project has no development. `null` when it cannot be known: a listing
   * failed, or either side has names that are not open.
   */
  readonly missingVsDevelopment: number | null | undefined;
}

export const DEVELOPMENT = "development";

export function environmentStats<T extends ScopedRow & { readonly secretId: string }>(
  listings: readonly OverviewListing<T>[],
  namesByEnvironment: ReadonlyMap<string, ReadonlyMap<string, string>>,
): EnvironmentStats[] {
  const development = listings.find((listing) => listing.environmentName === DEVELOPMENT);

  /** Opened names of a listing, or `null` if any row's name is not open. */
  const openedNames = (listing: OverviewListing<T>): Set<string> | null => {
    if (listing.rows === null) return null;
    const names = namesByEnvironment.get(listing.environmentId);
    if (names === undefined) return null;
    const out = new Set<string>();
    for (const row of listing.rows) {
      const name = names.get(row.secretId);
      if (name === undefined) return null;
      out.add(name);
    }
    return out;
  };
  const developmentNames = development === undefined ? null : openedNames(development);

  return listings.map((listing): EnvironmentStats => {
    const base = { environmentId: listing.environmentId, name: listing.environmentName };
    const isDevelopment = listing === development;
    const missing = (): number | null | undefined => {
      if (development === undefined || isDevelopment) return undefined;
      const here = openedNames(listing);
      if (here === null || developmentNames === null) return null;
      let count = 0;
      for (const name of developmentNames) if (!here.has(name)) count += 1;
      return count;
    };
    if (listing.rows === null) {
      return { ...base, secrets: null, shared: null, own: null, only: null, missingVsDevelopment: missing() };
    }
    let shared = 0;
    let own = 0;
    let only = 0;
    for (const row of listing.rows) {
      if (row.shareUid === undefined) only += 1;
      else if (row.overridden === true) own += 1;
      else shared += 1;
    }
    return { ...base, secrets: listing.rows.length, shared, own, only, missingVsDevelopment: missing() };
  });
}

export type ChecklistStep = "create" | "secrets" | "run" | "production";

export interface Checklist {
  readonly done: ReadonlySet<ChecklistStep>;
  /** Out of four, always: every step is listed, built or not. */
  readonly total: 4;
}

/**
 * "Create the project" is done by being here. "Add your secrets" is done when
 * the project holds one. "Run your app" is done when a development token has
 * connected, or on the person's own claim ("Mark as done", remembered in this
 * browser). "Connect production" is done when a token outside development has
 * connected: made is not enough, because a token nobody has used yet proves
 * nothing is running.
 */
export function checklist(input: {
  readonly secretCount: number | undefined;
  readonly ranLocally: boolean;
  /** One entry per service token: its environment, and whether it has ever connected. */
  readonly connections: readonly { readonly environmentName: string; readonly connected: boolean }[];
}): Checklist {
  const done = new Set<ChecklistStep>(["create"]);
  if (input.secretCount !== undefined && input.secretCount > 0) done.add("secrets");
  const connected = input.connections.filter((connection) => connection.connected);
  if (input.ranLocally || connected.some((connection) => connection.environmentName === DEVELOPMENT)) done.add("run");
  if (connected.some((connection) => connection.environmentName !== DEVELOPMENT)) done.add("production");
  return { done, total: 4 };
}

/** Where "Mark as done" is remembered: per project, in this browser only. */
export function ranLocallyKey(projectId: string): string {
  return `sluice.ran-locally.${projectId}`;
}
