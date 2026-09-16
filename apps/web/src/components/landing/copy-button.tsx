"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { focusRing } from "@/components/landing/primitives";

type CopyState = "idle" | "copied" | "failed";

const LABELS: Record<CopyState, string> = {
  idle: "Copy",
  copied: "Copied",
  failed: "Copy failed",
};

/**
 * Copy-to-clipboard button.
 *
 * A real `<button>`, so it is in the tab order, fires on Enter and Space, and
 * takes the page's one focus ring for free. The confirmation is announced as
 * well as shown: a sighted user sees the label flip to "Copied", a screen
 * reader user gets the same string through a polite live region, because a
 * label that only changes visually confirms nothing to someone who cannot see
 * it.
 *
 * Failure is surfaced rather than swallowed. `navigator.clipboard` is absent
 * on insecure origins and can be refused by permissions policy, and a button
 * that silently does nothing is worse than one that says so.
 *
 * `min-w` is fixed across all three labels so the flip cannot reflow the row.
 */
export function CopyButton({
  value,
  describes,
}: {
  /** The exact text placed on the clipboard. */
  value: string;
  /** What is being copied, for the accessible name. */
  describes: string;
}) {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, []);

  const copy = useCallback(async () => {
    let next: CopyState = "failed";
    try {
      await navigator.clipboard.writeText(value);
      next = "copied";
    } catch {
      next = "failed";
    }
    setState(next);
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), 2400);
  }, [value]);

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={`Copy ${describes}`}
      className={`inline-flex min-w-[8.5rem] cursor-pointer items-center justify-center rounded-input border border-hairline bg-surface-card px-3 py-2 font-mono text-base text-text-muted transition-colors hover:border-brand hover:text-brand md:min-w-[7.5rem] md:text-sm ${focusRing}`}
    >
      <span aria-hidden="true">{LABELS[state]}</span>
      <span role="status" aria-live="polite" className="sr-only">
        {state === "idle" ? "" : `${LABELS[state]}: ${describes}`}
      </span>
    </button>
  );
}
