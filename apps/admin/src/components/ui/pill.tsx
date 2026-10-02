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
  // A group that does not cover every environment: the warning tint, and the
  // label says where it is missing.
  partial:
    "border border-status-warning/50 text-status-warning light:text-text-primary",
};

export function ScopePill({
  scope,
  environmentName,
  missingIn,
}: {
  readonly scope: SecretScope;
  readonly environmentName: string;
  /** For a `partial` scope: the environments the group has no row in. */
  readonly missingIn?: readonly string[];
}) {
  const label = scopeLabel(scope, environmentName, missingIn);
  // A partial label names environments and can be long: it wraps rather than
  // being cut, because the cut-off part is the part that matters.
  const shape =
    scope === "partial"
      ? "inline-flex min-h-[26px] items-center rounded-[13px] px-2.5 py-1 text-[13px] leading-tight"
      : PILL;
  return <span className={`${shape} max-w-full ${SCOPE_CLASS[scope]}`}>{label}</span>;
}

/**
 * An environment's name. No status dot: this slice has no connection data,
 * and a dot would claim a state nobody measured.
 */
export function EnvPill({ name }: { readonly name: string }) {
  return <span className={`${PILL} border border-hairline-strong text-text-primary`}>{name}</span>;
}
