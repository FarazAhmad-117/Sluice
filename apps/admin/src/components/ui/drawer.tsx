import { useEffect, useId, useRef } from "react";
import type { KeyboardEvent, ReactNode, RefObject } from "react";
import { createPortal } from "react-dom";
import { IconButton } from "./button";
import { IconClose } from "./icons";

/**
 * A MODAL DRAWER: FROM THE RIGHT AT 768PX AND UP, A BOTTOM SHEET BELOW.
 *
 * What makes it a real modal rather than a panel that looks like one:
 *   - `role="dialog"`, `aria-modal`, named by its own heading;
 *   - focus moves in when it opens (to `initialFocus`, else the first control)
 *     and is trapped: Tab and Shift+Tab cycle inside it;
 *   - Escape and a click on the backdrop close it;
 *   - focus returns to whatever opened it when it closes;
 *   - the page behind does not scroll while it is open;
 *   - the slide-in is skipped under `prefers-reduced-motion` (see `app.css`).
 *
 * Rendered into `document.body`, so no ancestor's overflow or stacking context
 * can clip it. Closing is the caller's state: `onClose` asks, `open` decides.
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (element) => !element.hasAttribute("inert") && element.getClientRects().length > 0,
  );
}

export function Drawer({
  open,
  onClose,
  title,
  children,
  footer,
  initialFocus,
}: {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly title: ReactNode;
  readonly children: ReactNode;
  /** Pinned below the scrolling body: the note and the actions. */
  readonly footer?: ReactNode;
  readonly initialFocus?: RefObject<HTMLElement | null>;
}) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);

  // `initialFocus` should be a stable `useRef`; a new object each render would
  // re-run this and pull focus back on every keystroke.
  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const root = panel.current;
    if (root !== null) {
      const target = initialFocus?.current ?? focusables(root)[0] ?? root;
      target.focus();
    }
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = overflow;
      // Back to the control that opened it, if that control is still there.
      if (opener !== null && opener.isConnected) opener.focus();
    };
  }, [open, initialFocus]);

  if (!open) return null;

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== "Tab" || panel.current === null) return;
    const items = focusables(panel.current);
    const first = items[0];
    const last = items[items.length - 1];
    if (first === undefined || last === undefined) {
      event.preventDefault();
      return;
    }
    const active = document.activeElement;
    if (event.shiftKey && (active === first || active === panel.current)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div className="fixed inset-0 z-50">
      {/* Decorative: the close button and Escape are the accessible ways out. */}
      <div
        aria-hidden="true"
        onClick={onClose}
        className="sluice-backdrop absolute inset-0 bg-surface-base/70 light:bg-text-primary/40"
      />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="sluice-drawer absolute inset-x-0 bottom-0 flex max-h-[92dvh] flex-col rounded-t-modal border-t border-hairline-strong bg-surface-panel outline-none md:inset-y-0 md:right-0 md:left-auto md:max-h-none md:w-[520px] md:max-w-full md:rounded-none md:border-t-0 md:border-l"
      >
        <div className="flex min-h-16 shrink-0 items-center justify-between gap-4 border-b border-hairline py-2 pr-3 pl-6">
          <h2 id={titleId} className="m-0 text-[17px] font-semibold text-text-primary">
            {title}
          </h2>
          <IconButton label="Close" onClick={onClose}>
            <IconClose className="size-[18px]" />
          </IconButton>
        </div>
        <div className="flex grow flex-col gap-[22px] overflow-y-auto p-6">{children}</div>
        {footer === undefined ? null : (
          <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-hairline px-6 py-4">
            {footer}
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
}
