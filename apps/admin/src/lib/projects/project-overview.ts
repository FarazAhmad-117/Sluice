/**
 * HOW MANY SECRETS A PROJECT HOLDS, AS A PERSON COUNTS THEM.
 *
 * A secret set for "All environments" is one row per environment, linked by a
 * share id, and a person thinks of it as one secret. So rows that carry a
 * share id count once per share id across the whole project, and every other
 * row counts once. Read off plaintext grouping metadata, so this is the
 * server's account of the grouping, which is all a count on a card needs.
 */
export function countProjectSecrets(
  rowsByEnvironment: readonly (readonly { readonly shareUid?: string }[])[],
): number {
  const shared = new Set<string>();
  let count = 0;
  for (const rows of rowsByEnvironment) {
    for (const row of rows) {
      if (row.shareUid === undefined) count += 1;
      else shared.add(row.shareUid);
    }
  }
  return count + shared.size;
}

/** "1 secret", "3 secrets". */
export function secretsLabel(count: number): string {
  return `${count} ${count === 1 ? "secret" : "secrets"}`;
}

/** Projects whose name or slug contains the query, ignoring case and surrounding space. */
export function filterProjects<T extends { readonly name: string; readonly slug: string }>(
  projects: readonly T[],
  query: string,
): T[] {
  const needle = query.trim().toLowerCase();
  if (needle === "") return [...projects];
  return projects.filter(
    (project) =>
      project.name.toLowerCase().includes(needle) || project.slug.toLowerCase().includes(needle),
  );
}
