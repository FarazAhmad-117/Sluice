/**
 * WHERE A SECRET APPLIES, READ OFF ITS ROW.
 *
 * A secret set for "All environments" is stored as one independently sealed
 * row per environment, linked by a `shr_` share id. A row that keeps its own
 * value in one environment carries `overridden: true`. A secret that lives in
 * one environment only carries neither.
 *
 * BOTH FIELDS ARE PLAINTEXT METADATA, bound into no ciphertext (see `shr_` in
 * `packages/crypto/src/ids.ts`). A label computed here is the server's account
 * of how rows are grouped, not something a decrypt proved: a hostile server can
 * mislabel a row's scope, and cannot make it open under another environment.
 */

/*
 * A LABEL IS A CLAIM, SO IT IS COMPUTED FROM THE GROUP, NOT THE ROW.
 *
 * "All environments" says every environment of the project has this secret.
 * The server checks that the rows of a share cover every environment only at
 * the moment they are created; an environment added later has no row for any
 * existing share, and a hostile server can hide one. So a row is labelled
 * shared or overridden only when its group's live rows cover every current
 * environment, and otherwise "partial": "Shared, missing in <list>". An
 * environment whose listing could not be fetched counts as missing, because
 * nothing confirms it holds the secret.
 */

export type SecretScope = "shared" | "overridden" | "only" | "partial";

export interface ScopedRow {
  readonly shareUid?: string;
  readonly overridden?: boolean;
}

/**
 * `coversAllEnvironments` is whether this row's group has a live row in every
 * current environment (see {@link missingFromShare}). It only matters for a
 * row with a share id; it defaults to true for callers that hold one listing.
 */
export function scopeOf(row: ScopedRow, coversAllEnvironments = true): SecretScope {
  if (row.shareUid === undefined) return "only";
  if (!coversAllEnvironments) return "partial";
  return row.overridden === true ? "overridden" : "shared";
}

/** "a", "a and b", "a, b and c". */
function listOf(names: readonly string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

export function scopeLabel(
  scope: SecretScope,
  environmentName: string,
  missingIn: readonly string[] = [],
): string {
  switch (scope) {
    case "shared":
      return "All environments";
    case "overridden":
      return `Overridden in ${environmentName}`;
    case "only":
      return `Only ${environmentName}`;
    case "partial":
      return missingIn.length === 0 ? "Shared" : `Shared, missing in ${listOf(missingIn)}`;
  }
}

/**
 * The environments, in listing order, with no live row of `shareUid`. `rows`
 * is `null` for an environment whose listing failed; it counts as missing.
 */
export function missingFromShare(
  shareUid: string,
  listings: readonly { readonly environmentName: string; readonly rows: readonly ScopedRow[] | null }[],
): string[] {
  return listings
    .filter((listing) => listing.rows === null || !listing.rows.some((row) => row.shareUid === shareUid))
    .map((listing) => listing.environmentName);
}

export function countScopes<T extends ScopedRow>(
  rows: readonly T[],
  coversAllEnvironments: (row: T) => boolean = () => true,
): Record<SecretScope | "all", number> {
  const counts = { all: 0, shared: 0, overridden: 0, only: 0, partial: 0 };
  for (const row of rows) {
    counts.all += 1;
    counts[scopeOf(row, coversAllEnvironments(row))] += 1;
  }
  return counts;
}
