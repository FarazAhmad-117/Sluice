import type { CompareMatrix, CompareRow } from "./compare";

/**
 * LINKS TO ONE SECRET, WITHOUT ITS NAME.
 *
 * A secret's name is ciphertext to the server, so it must never travel in a
 * URL: a reload sends the URL to the static host, it sits in history, and a
 * shared link hands it to whoever receives it. A link names the secret by an
 * id the server already holds instead, `shr_...` for a shared secret (one id
 * for every environment's row) or the row's permanent `sec_...` otherwise,
 * and this browser resolves it against the rows it listed.
 */

export interface Referable {
  readonly secretUid: string;
  readonly shareUid?: string;
}

/** The opaque id a link carries for this row. */
export function secretRef(secret: Referable): string {
  return secret.shareUid ?? secret.secretUid;
}

/** `/projects/<slug>/secrets?env=<environment>&secret=<shr_ or sec_ id>`. */
export function secretLink(slug: string, environmentName: string, secret: Referable): string {
  const params = new URLSearchParams({ env: environmentName, secret: secretRef(secret) });
  return `/projects/${encodeURIComponent(slug)}/secrets?${params.toString()}`;
}

/** The key a link's `?secret=` names, if this browser has a row for it. */
export function rowForRef<T extends Referable>(matrix: CompareMatrix<T>, ref: string | null): CompareRow<T> | undefined {
  if (ref === null || ref === "") return undefined;
  return matrix.rows.find((row) =>
    row.cells.some((cell) => cell.secret !== undefined && secretRef(cell.secret) === ref),
  );
}

/** A link to `row`, in the first environment that has it. */
export function linkForRow<T extends Referable>(slug: string, row: CompareRow<T>): string {
  const first = row.cells.find((cell) => cell.secret !== undefined);
  if (first?.secret === undefined) return `/projects/${encodeURIComponent(slug)}/secrets`;
  return secretLink(slug, first.environmentName, first.secret);
}
