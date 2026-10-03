import type { CellKind } from "@/lib/secrets/compare";

/**
 * WHERE A KEY EXISTS, DRAWN THE SAME WAY EVERYWHERE.
 *
 * Two shapes over one vocabulary from `lib/secrets/compare.ts`: the Compare
 * page's labelled cell, and the Secrets table's one-letter chip. Colour is
 * never the only carrier: the cell is a sentence, the chip has the sentence as
 * its tooltip and as screen-reader text.
 *
 * On the light theme tinted text goes near-black (the tint stays), because the
 * brand blue, amber and red as 13px text on white fall below AA.
 */

const CELL_TEXT: Record<CellKind, string> = {
  set: "Set here",
  shared: "Shared value",
  own: "Own value",
  missing: "Missing",
  unknown: "Unknown",
};

const CELL_CLASS: Record<CellKind, string> = {
  set: "bg-brand-subtle text-brand-hover light:text-text-primary",
  shared: "border border-hairline-strong text-text-primary",
  own: "bg-status-warning/12 text-status-warning light:text-text-primary",
  missing: "border border-dashed border-status-danger/50 text-status-danger light:text-text-primary",
  unknown: "border border-dashed border-hairline-strong text-text-faint",
};

/** The Compare cell. `suffix` adds " · Add" to a missing cell that is a button. */
export function CoverageCell({ kind, suffix }: { readonly kind: CellKind; readonly suffix?: string }) {
  return (
    <span
      className={`inline-flex h-7 items-center gap-2 rounded-[7px] px-2.5 text-[13px] whitespace-nowrap ${CELL_CLASS[kind]}`}
    >
      {suffix === undefined ? CELL_TEXT[kind] : `${CELL_TEXT[kind]} · ${suffix}`}
    </span>
  );
}

const CHIP_CLASS: Record<CellKind, string> = {
  // A key that is in this environment, with the value this environment uses
  // for everyone: filled brand, whether set here alone or shared.
  set: "bg-brand text-surface-base",
  shared: "bg-brand text-surface-base",
  own: "bg-status-warning text-surface-base",
  missing: "border border-dashed border-hairline-strong text-text-faint",
  unknown: "border border-dashed border-hairline text-text-faint opacity-60",
};

const CHIP_MEANING: Record<CellKind, string> = {
  set: "set here",
  shared: "shared value",
  own: "own value",
  missing: "does not have it",
  unknown: "not known",
};

/** The Secrets table's environment chip: the environment's initial, coloured by kind. */
export function EnvironmentChip({ kind, environmentName }: { readonly kind: CellKind; readonly environmentName: string }) {
  const meaning = `${environmentName}: ${CHIP_MEANING[kind]}`;
  return (
    <span
      title={meaning}
      className={`inline-flex size-5 shrink-0 items-center justify-center rounded-[5px] text-[10px] font-bold ${CHIP_CLASS[kind]}`}
    >
      <span aria-hidden="true">{environmentName.slice(0, 1).toUpperCase()}</span>
      <span className="sr-only">{meaning}</span>
    </span>
  );
}
