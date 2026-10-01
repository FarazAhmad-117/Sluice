import { scopeLabel } from "@/lib/secrets/scope";
import type { SecretScope } from "@/lib/secrets/scope";

/**
 * PILLS: A SECRET'S SCOPE, AND AN ENVIRONMENT'S NAME.
 *
 * The scope pill is tinted by scope, as in the mocks: shared is a plain
 * hairline, overridden is the warning tint, only-here is the brand tint. On
 * the light theme the tinted text drops to `text-text-primary` (the tint
 * stays), because amber and the brand blue as 13px text on white fall below
 * AA contrast. The label is always the full sentence from `scopeLabel`, so the
 * colour is never the only thing carrying the meaning.
 */

const PILL =
  "inline-flex h-[26px] items-center gap-1.5 rounded-full px-2.5 text-[13px] whitespace-nowrap";

const SCOPE_CLASS: Record<SecretScope, string> = {
  shared: "border border-hairline-strong text-text-primary",
  overridden: "bg-status-warning/12 text-status-warning light:text-text-primary",
  only: "bg-brand-subtle text-brand-hover light:text-text-primary",
};

export function ScopePill({
  scope,
  environmentName,
}: {
  readonly scope: SecretScope;
  readonly environmentName: string;
}) {
  return <span className={`${PILL} ${SCOPE_CLASS[scope]}`}>{scopeLabel(scope, environmentName)}</span>;
}

/**
 * An environment's name. No status dot: this slice has no connection data,
 * and a dot would claim a state nobody measured.
 */
export function EnvPill({ name }: { readonly name: string }) {
  return <span className={`${PILL} border border-hairline-strong text-text-primary`}>{name}</span>;
}
