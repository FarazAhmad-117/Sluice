/**
 * Which org the dashboard shows: the remembered one when it is still listed,
 * else the first. `null` for no orgs. The remembered id is a convenience the
 * server re-checks on every call, so a stale or edited value falls back.
 */
export function pickOrg<T extends { readonly orgId: string }>(
  orgs: readonly T[],
  storedId: string | null,
): T | null {
  return orgs.find((org) => org.orgId === storedId) ?? orgs[0] ?? null;
}
