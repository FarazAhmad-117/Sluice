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

export type SecretScope = "shared" | "overridden" | "only";

export interface ScopedRow {
  readonly shareUid?: string;
  readonly overridden?: boolean;
}

export function scopeOf(row: ScopedRow): SecretScope {
  if (row.shareUid === undefined) return "only";
  return row.overridden === true ? "overridden" : "shared";
}

export function scopeLabel(scope: SecretScope, environmentName: string): string {
  switch (scope) {
    case "shared":
      return "All environments";
    case "overridden":
      return `Overridden in ${environmentName}`;
    case "only":
      return `Only ${environmentName}`;
  }
}

export function countScopes(rows: readonly ScopedRow[]): Record<SecretScope | "all", number> {
  const counts = { all: 0, shared: 0, overridden: 0, only: 0 };
  for (const row of rows) {
    counts.all += 1;
    counts[scopeOf(row)] += 1;
  }
  return counts;
}
