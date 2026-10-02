import type { ScopedRow } from "./scope";

/**
 * EVERY KEY IN EVERY ENVIRONMENT, GROUPED BY ITS OPENED NAME. Pure.
 *
 * The Compare page, each row's environment chips on the Secrets page, and the
 * detail panel's "value in each environment" all read this one matrix, so the
 * three can never disagree about where a key exists.
 *
 * GROUPED BY NAME, NOT BY SHARE ID. A person compares environments by key: a
 * `DATABASE_URL` added to development alone and another added to production
 * alone are the same key to them, set separately. Names are opened in this
 * browser, so the server cannot see this grouping and cannot fake it; it can
 * only withhold rows, which then show as missing.
 *
 * "Missing" IS ONLY SAID WHEN IT IS KNOWN. An environment whose listing
 * failed, whose names are not open, or that has a row whose name did not open
 * (it might be this key) shows "unknown" for every key rather than "missing".
 */

export type CellKind =
  /** A row of its own here, not part of a shared secret. */
  | "set"
  /** A row of a shared secret, using the shared value. */
  | "shared"
  /** A row of a shared secret, keeping its own value here. */
  | "own"
  | "missing"
  | "unknown";

export interface CompareCell<T> {
  readonly environmentId: string;
  readonly environmentName: string;
  readonly kind: CellKind;
  /** The row, for every kind but `missing` and `unknown`. */
  readonly secret?: T;
}

export interface CompareRow<T> {
  readonly name: string;
  /** One per environment, in environment order. */
  readonly cells: readonly CompareCell<T>[];
}

export interface CompareListing<T> {
  readonly environmentId: string;
  readonly environmentName: string;
  /** `null` when the listing failed. */
  readonly rows: readonly T[] | null;
}

export interface CompareMatrix<T> {
  /** Sorted by key. */
  readonly rows: readonly CompareRow<T>[];
  /** Rows whose name did not open, so they are in no row of the matrix. */
  readonly sealed: number;
  /** Environments where "missing" cannot be said, by name. */
  readonly uncertain: readonly string[];
  /** Per environment id: keys missing there, and keys with their own value there. */
  readonly missing: ReadonlyMap<string, number>;
  readonly own: ReadonlyMap<string, number>;
}

export function kindOf(row: ScopedRow): Exclude<CellKind, "missing" | "unknown"> {
  if (row.shareUid === undefined) return "set";
  return row.overridden === true ? "own" : "shared";
}

export function buildMatrix<T extends ScopedRow & { readonly secretId: string }>(
  listings: readonly CompareListing<T>[],
  namesByEnvironment: ReadonlyMap<string, ReadonlyMap<string, string>>,
): CompareMatrix<T> {
  const byName = new Map<string, Map<string, T>>();
  const uncertain = new Set<string>();
  let sealed = 0;

  for (const listing of listings) {
    const names = namesByEnvironment.get(listing.environmentId);
    if (listing.rows === null || names === undefined) {
      uncertain.add(listing.environmentId);
      continue;
    }
    for (const row of listing.rows) {
      const name = names.get(row.secretId);
      if (name === undefined) {
        sealed += 1;
        uncertain.add(listing.environmentId);
        continue;
      }
      const cells = byName.get(name) ?? new Map<string, T>();
      // One live row per name per environment is the normal case; if there
      // are two, the first listed stands for the key.
      if (!cells.has(listing.environmentId)) cells.set(listing.environmentId, row);
      byName.set(name, cells);
    }
  }

  const missing = new Map<string, number>(listings.map((listing) => [listing.environmentId, 0]));
  const own = new Map<string, number>(listings.map((listing) => [listing.environmentId, 0]));
  const rows = [...byName.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, present]): CompareRow<T> => ({
      name,
      cells: listings.map((listing): CompareCell<T> => {
        const base = { environmentId: listing.environmentId, environmentName: listing.environmentName };
        const secret = present.get(listing.environmentId);
        if (secret !== undefined) {
          const kind = kindOf(secret);
          if (kind === "own") own.set(listing.environmentId, (own.get(listing.environmentId) ?? 0) + 1);
          return { ...base, kind, secret };
        }
        if (uncertain.has(listing.environmentId)) return { ...base, kind: "unknown" };
        missing.set(listing.environmentId, (missing.get(listing.environmentId) ?? 0) + 1);
        return { ...base, kind: "missing" };
      }),
    }));

  return {
    rows,
    sealed,
    uncertain: listings.filter((listing) => uncertain.has(listing.environmentId)).map((listing) => listing.environmentName),
    missing,
    own,
  };
}

/** The matrix row for one key, if any environment has it. */
export function rowFor<T>(matrix: CompareMatrix<T>, name: string | undefined): CompareRow<T> | undefined {
  if (name === undefined) return undefined;
  return matrix.rows.find((row) => row.name === name);
}
