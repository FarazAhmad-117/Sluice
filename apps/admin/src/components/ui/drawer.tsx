import { useEffect, useId, useRef } from "react";
import type { ReactNode, RefObject } from "react";
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
 *   - the page behind is `inert` and does not scroll while it is open;
 *   - the slide-in is skipped under `prefers-reduced-motion` (see `app.css`).
 *
 * THE KEYBOARD IS HANDLED ON THE DOCUMENT, NOT ON THE PANEL. A handler on the
 * panel only hears keys while focus is inside it, and focus can fall out
 * without anybody pressing Tab: when the focused control is removed or
 * disabled, the browser drops focus to `<body>`, and a panel-level handler
 * then never sees Escape or Tab again. A capture-phase listener on the
 * document hears every key wherever focus is, and pulls a stray Tab back
 * inside. `inert` on the app root is the second half: nothing behind the
 * drawer can take focus or a click, so there is nowhere for focus to go but
 * the drawer.
 *
 * Rendered into `document.body`, beside `#root` rather than inside it, which
 * is what lets `#root` go inert without taking the drawer with it, and means
 * no ancestor's overflow or stacking context can clip it. Closing is the
 * caller's state: `onClose` asks, `open` decides.
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * The drawers open right now, oldest first. One token per opening; the last
 * is the one on top. Module-level because the drawers that stack (the detail
 * sheet, then the edit drawer over it) are separate components.
 */
const openDrawers: object[] = [];

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (element) => !element.hasAttribute("inert") && element.getClientRects().length > 0,
  );
}

/**
 * `side="left"` is the phone navigation drawer: 300px from the left edge, full
 * height, its title read to a screen reader but not drawn (the sidebar inside
 * is its own heading), and the close button floated top-right over the body
 * rather than in a title bar. The body is the caller's, unpadded.
 */
export function Drawer({
  open,
  onClose,
  title,
  children,
  footer,
  initialFocus,
  side = "right",
}: {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly title: ReactNode;
  readonly children: ReactNode;
  /** Pinned below the scrolling body: the note and the actions. */
  readonly footer?: ReactNode;
  readonly initialFocus?: RefObject<HTMLElement | null>;
  readonly side?: "right" | "left";
}) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);

  // The latest `onClose`, for the document listener, which is attached once
  // per opening rather than once per render.
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  });

  // `initialFocus` should be a stable `useRef`; a new object each render would
  // re-run this and pull focus back on every keystroke.
  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const app = document.getElementById("root");
    const wasInert = app?.inert ?? false;
    if (app !== null) app.inert = true;

    const root = panel.current;
    if (root !== null) {
      const target = initialFocus?.current ?? focusables(root)[0] ?? root;
      target.focus();
    }
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const token: object = {};
    openDrawers.push(token);

    const onKeyDown = (event: KeyboardEvent) => {
      const current = panel.current;
      if (current === null) return;
      // Only the topmost open drawer owns Escape and Tab. Every open drawer
      // hears every key (the listener is on the document), so without this
      // the one underneath would close too, or pull focus that fell to
      // <body> into itself instead of into the drawer on top.
      if (openDrawers[openDrawers.length - 1] !== token) return;
      // A menu opened from inside the drawer (the org switcher in the phone
      // navigation) renders in its own portal and handles its own Escape,
      // arrows and Tab; Escape there closes the menu, not the drawer.
      if (event.target instanceof Element && event.target.closest('[role="menu"]') !== null) return;
      // Likewise a native dialog opened over the top drawer (a delete
      // confirmation, the command palette): its keys are its own.
      if (
        event.target instanceof Element &&
        !current.contains(event.target) &&
        event.target.closest('[role="dialog"], dialog') !== null
      ) {
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        close.current();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusables(current);
      const first = items[0];
      const last = items[items.length - 1];
      if (first === undefined || last === undefined) {
        event.preventDefault();
        current.focus();
        return;
      }
      const active = document.activeElement;
      const inside = active instanceof Node && current.contains(active);
      if (!inside) {
        // Focus fell out (to `<body>`, usually). Bring it back in, at the end
        // the person was heading for.
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && (active === first || active === current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown, true);

    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      const at = openDrawers.indexOf(token);
      if (at !== -1) openDrawers.splice(at, 1);
      document.body.style.overflow = overflow;
      // Un-inert BEFORE restoring focus: an inert element cannot take it.
      if (app !== null) app.inert = wasInert;
      // Back to the control that opened it, if that control is still there.
      if (opener !== null && opener.isConnected) opener.focus();
    };
  }, [open, initialFocus]);

  if (!open) return null;

  if (side === "left") {
    return createPortal(
      <div className="fixed inset-0 z-50">
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
          className="sluice-drawer-left absolute inset-y-0 left-0 flex w-[300px] max-w-[85vw] flex-col border-r border-hairline-strong bg-surface-panel pt-[env(safe-area-inset-top)] pb-[env(safe-area-inset-bottom)] outline-none"
        >
          <h2 id={titleId} className="sr-only">
            {title}
          </h2>
          {/* Level with the org switcher, the sidebar's first 44px row. */}
          <div className="absolute top-[calc(env(safe-area-inset-top)+12px)] right-1.5 z-10">
            <IconButton label="Close" onClick={onClose}>
              <IconClose className="size-[18px]" />
            </IconButton>
          </div>
          {children}
        </div>
      </div>,
      document.body,
    );
  }

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
        className="sluice-drawer absolute inset-x-0 bottom-0 flex max-h-[92dvh] flex-col rounded-t-modal border-t border-hairline-strong bg-surface-panel pb-[env(safe-area-inset-bottom)] outline-none md:inset-y-0 md:right-0 md:left-auto md:max-h-none md:w-[520px] md:max-w-full md:rounded-none md:border-t-0 md:border-l md:pb-0"
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
