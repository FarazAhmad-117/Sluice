import { useEffect, useRef } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { focusRing } from "./styles";

/**
 * A SEGMENTED CONTROL, BUILT AS A TABLIST.
 *
 * Used for the environment switcher on the secrets page. It follows the ARIA
 * tabs pattern with automatic activation: one tab is in the tab order (the
 * selected one), and the arrow keys, Home and End move focus AND selection
 * along the row. Pass `panelId` when the tabs control a `role="tabpanel"`.
 *
 * Each tab is 44px tall, the touch-target floor, a little taller than the
 * 34px in the mock.
 */

export interface SegmentedOption<T extends string> {
  readonly value: T;
  readonly label: ReactNode;
  /** Shown after the label in mono, as the mock shows each environment's count. */
  readonly count?: number;
}

export function Segmented<T extends string>({
  label,
  options,
  value,
  onChange,
  panelId,
  idPrefix,
  variant = "boxed",
}: {
  /**
   * `boxed` is the pill-in-a-tray switcher; `underline` is the Round 3 tab
   * row: tabs on a hairline, the selected one underlined, counts in bubbles.
   */
  readonly variant?: "boxed" | "underline";
  /** The accessible name of the group, e.g. "Environment". */
  readonly label: string;
  readonly options: readonly SegmentedOption<T>[];
  readonly value: T;
  readonly onChange: (value: T) => void;
  readonly panelId?: string;
  /** Prefix for each tab's id, so a tabpanel can name its tab with `aria-labelledby`. */
  readonly idPrefix?: string;
}) {
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const hasSelection = options.some((option) => option.value === value);

  // On a narrow screen the row scrolls; keep the selected tab in view.
  const selectedIndex = options.findIndex((option) => option.value === value);
  useEffect(() => {
    tabs.current[selectedIndex]?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [selectedIndex]);

  const move = (event: KeyboardEvent<HTMLDivElement>) => {
    const current = options.findIndex((option) => option.value === value);
    const last = options.length - 1;
    let next: number;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        next = current >= last ? 0 : current + 1;
        break;
      case "ArrowLeft":
      case "ArrowUp":
        next = current <= 0 ? last : current - 1;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = last;
        break;
      default:
        return;
    }
    event.preventDefault();
    const option = options[next];
    if (option === undefined) return;
    onChange(option.value);
    tabs.current[next]?.focus();
  };

  return (
    <div
      role="tablist"
      aria-label={label}
      onKeyDown={move}
      className={
        variant === "underline"
          ? "flex max-w-full gap-5 overflow-x-auto overflow-y-hidden border-b border-hairline sm:gap-[22px]"
          : "inline-flex max-w-full gap-1 overflow-x-auto rounded-[10px] border border-hairline bg-surface-panel p-1"
      }
    >
      {options.map((option, index) => {
        const selected = option.value === value;
        // With no option matching `value`, the first tab takes the tab stop,
        // so the group is never unreachable by keyboard.
        const tabbable = selected || (index === 0 && !hasSelection);
        return (
          <button
            key={option.value}
            ref={(element) => {
              tabs.current[index] = element;
            }}
            id={idPrefix === undefined ? undefined : `${idPrefix}-${option.value}`}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={panelId}
            tabIndex={tabbable ? 0 : -1}
            onClick={() => onChange(option.value)}
            className={
              variant === "underline"
                ? `-mb-px inline-flex min-h-11 shrink-0 cursor-pointer items-center gap-2 border-0 border-b-2 bg-transparent px-0 text-sm transition-colors lg:min-h-10 lg:pointer-coarse:min-h-11 ${focusRing} ${
                    selected
                      ? "border-text-primary font-medium text-text-primary"
                      : "border-transparent text-text-muted hover:text-text-primary"
                  }`
                : `inline-flex min-h-11 shrink-0 cursor-pointer items-center gap-2 rounded-[7px] border px-3.5 text-sm transition-colors ${focusRing} ${
                    selected
                      ? "border-hairline-strong bg-surface-card font-medium text-text-primary"
                      : "border-transparent bg-transparent text-text-muted hover:text-text-primary"
                  }`
            }
          >
            {option.label}
            {option.count === undefined ? null : variant === "underline" ? (
              <span
                className={`inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-surface-card px-1.5 text-xs font-normal ${
                  selected ? "text-text-primary" : "text-text-muted"
                }`}
              >
                {option.count}
              </span>
            ) : (
              <span className="font-mono text-xs text-text-muted">{option.count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
