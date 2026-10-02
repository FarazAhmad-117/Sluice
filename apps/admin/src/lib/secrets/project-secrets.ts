import { missingFromShare, scopeOf } from "./scope";
import type { ScopedRow, SecretScope } from "./scope";

/**
 * THE SECRETS PAGE'S DATA, SHAPED FOR THE SCREEN. Pure: the hook in
 * `use-project-secrets.ts` fetches and decrypts, these decide.
 */

/** The environment in `?env=` when it exists, else `development`, else the first. */
export function pickEnvironment<T extends { readonly name: string }>(
  environments: readonly T[],
  requested: string | null,
): T | null {
  return (
    environments.find((environment) => environment.name === requested) ??
    environments.find((environment) => environment.name === "development") ??
    environments[0] ??
    null
  );
}

export interface Listing<T extends ScopedRow> {
  readonly environmentId: string;
  readonly environmentName: string;
  /** `null` when this environment's listing failed. */
  readonly rows: readonly T[] | null;
}

export interface LabelledRow<T> {
  readonly secret: T;
  /** The opened name, or `undefined` for a row that did not open. */
  readonly name: string | undefined;
  readonly scope: SecretScope;
  /** For `partial`: where the group has no row. */
  readonly missingIn: readonly string[];
}

/**
 * Every row of `selected`, with its scope computed from its group's coverage
 * across `listings` (see the note in `scope.ts`), sorted by name with rows
 * that did not open last.
 */
export function labelRows<T extends ScopedRow & { readonly secretId: string }>(
  selected: Listing<T>,
  listings: readonly Listing<T>[],
  names: ReadonlyMap<string, string>,
): LabelledRow<T>[] {
  const rows = (selected.rows ?? []).map((secret): LabelledRow<T> => {
    const missingIn = secret.shareUid === undefined ? [] : missingFromShare(secret.shareUid, listings);
    return {
      secret,
      name: names.get(secret.secretId),
      scope: scopeOf(secret, missingIn.length === 0),
      missingIn,
    };
  });
  return rows.sort((a, b) => {
    if (a.name === undefined || b.name === undefined) {
      return a.name === b.name ? 0 : a.name === undefined ? 1 : -1;
    }
    return a.name.localeCompare(b.name);
  });
}

/**
 * The names of the environments where a live secret is already called `name`.
 * Compared on opened names only: a row that did not open cannot be checked,
 * and the server cannot check at all (it never sees a name).
 */
export function environmentsWithName(
  name: string,
  environments: readonly { readonly environmentId: string; readonly name: string }[],
  namesByEnvironment: ReadonlyMap<string, ReadonlyMap<string, string>>,
): string[] {
  return environments
    .filter((environment) => {
      const names = namesByEnvironment.get(environment.environmentId);
      return names !== undefined && [...names.values()].includes(name);
    })
    .map((environment) => environment.name);
}
