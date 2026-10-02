import { createContext, useContext, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { KeyboardEvent, ReactNode } from "react";
import { Link } from "react-router";
import type { LinkProps } from "react-router";
import { IconCheck } from "./icons";
import { placeMenu } from "./place-menu";
import type { Placement } from "./place-menu";
import { focusRing } from "./styles";

/**
 * A MENU BUTTON AND ITS MENU, KEYBOARD FIRST.
 *
 * The ARIA menu button pattern: the trigger carries `aria-haspopup="menu"` and
 * `aria-expanded`; opening moves focus to the first item; ArrowUp/ArrowDown,
 * Home and End move between items; Escape closes and returns focus to the
 * trigger; Tab closes and lets focus move on; a click outside closes.
 *
 * Items are real buttons and links (`role="menuitem"` on them, not on a
 * wrapper), each at least 44px tall. A `MenuNote` is a non-interactive line
 * (the signed-in email) and is skipped by the arrow keys.
 *
 * THE MENU RENDERS IN A PORTAL ON `document.body`, positioned `fixed` against
 * the trigger. A menu rendered beside its trigger is clipped by any ancestor
 * with `overflow: hidden` (the secrets table's rounded container is one) and
 * can be painted under the content that follows it. From the body it sits
 * above the page, and the trigger's own row never changes layout when it
 * opens. It opens below the trigger, or above when there is not enough room
 * below; it is kept inside the viewport horizontally; and it follows the
 * trigger on scroll and resize. Because it is no longer next to the trigger in
 * the DOM, Tab from inside the menu first returns focus to the trigger and
 * then lets the browser move on, so Tab still continues from where the menu
 * was opened.
 */

const ITEM_SELECTOR = '[role="menuitem"], [role="menuitemradio"]';

interface MenuApi {
  close(returnFocus: boolean): void;
}

const MenuContext = createContext<MenuApi | null>(null);

function useMenu(): MenuApi {
  const value = useContext(MenuContext);
  if (value === null) throw new Error("Menu items must be rendered inside <Menu>");
  return value;
}

function items(root: HTMLElement | null): HTMLElement[] {
  if (root === null) return [];
  return Array.from(root.querySelectorAll<HTMLElement>(ITEM_SELECTOR));
}

export function Menu({
  label,
  trigger,
  triggerClassName = "",
  align = "start",
  children,
}: {
  /** The accessible name of the trigger, when its visible content is not enough. */
  readonly label?: string;
  readonly trigger: ReactNode;
  readonly triggerClassName?: string;
  readonly align?: "start" | "end";
  readonly children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const menuId = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  /** Which item takes focus on opening: the first, or (opened with ArrowUp) the last. */
  const focusOnOpen = useRef<"first" | "last">("first");
  const [placement, setPlacement] = useState<Placement | null>(null);

  const close = (returnFocus: boolean) => {
    setOpen(false);
    setPlacement(null);
    if (returnFocus) button.current?.focus();
  };

  // Measure and place before paint, then follow the trigger. Until placed the
  // menu is invisible, so it never flashes at the wrong spot.
  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const trigger = button.current;
      const menu = list.current;
      if (trigger === null || menu === null) return;
      // Natural height, not the height a previous max-height capped it at.
      const previous = menu.style.maxHeight;
      menu.style.maxHeight = "none";
      const size = { width: menu.offsetWidth, height: menu.scrollHeight };
      menu.style.maxHeight = previous;
      setPlacement(
        placeMenu(
          trigger.getBoundingClientRect(),
          size,
          { width: window.innerWidth, height: window.innerHeight },
          align,
        ),
      );
    };
    place();
    window.addEventListener("resize", place);
    // Capture, so a scroll inside any scrolling ancestor moves it too.
    window.addEventListener("scroll", place, true);
    return () => {
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [open, align]);

  useEffect(() => {
    if (!open) return;
    const all = items(list.current);
    const target = focusOnOpen.current === "last" ? all[all.length - 1] : all[0];
    (target ?? list.current)?.focus();

    const onPointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (
        target instanceof Node &&
        (root.current?.contains(target) === true || list.current?.contains(target) === true)
      ) {
        return;
      }
      setOpen(false);
      setPlacement(null);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  const onTriggerKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      focusOnOpen.current = event.key === "ArrowUp" ? "last" : "first";
      setOpen(true);
    }
  };

  const onMenuKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const all = items(list.current);
    const index = all.indexOf(document.activeElement as HTMLElement);
    let next: HTMLElement | undefined;
    switch (event.key) {
      case "ArrowDown":
        next = all[index < 0 || index >= all.length - 1 ? 0 : index + 1];
        break;
      case "ArrowUp":
        next = all[index <= 0 ? all.length - 1 : index - 1];
        break;
      case "Home":
        next = all[0];
        break;
      case "End":
        next = all[all.length - 1];
        break;
      case "Escape":
        event.preventDefault();
        event.stopPropagation();
        close(true);
        return;
      case "Tab":
        // Back to the trigger first, synchronously, and NOT prevented: the
        // browser's Tab then moves on from the trigger, as it did when the
        // menu sat beside it in the DOM.
        button.current?.focus();
        setOpen(false);
        setPlacement(null);
        return;
      default:
        return;
    }
    event.preventDefault();
    next?.focus();
  };

  return (
    <MenuContext.Provider value={{ close }}>
      <div ref={root} className="relative min-w-0">
        <button
          ref={button}
          type="button"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-controls={open ? menuId : undefined}
          aria-label={label}
          onClick={() => {
            focusOnOpen.current = "first";
            if (open) close(false);
            else setOpen(true);
          }}
          onKeyDown={onTriggerKeyDown}
          className={`${focusRing} ${triggerClassName}`}
        >
          {trigger}
        </button>
        {open
          ? createPortal(
              <div
                ref={list}
                id={menuId}
                role="menu"
                aria-label={label}
                tabIndex={-1}
                onKeyDown={onMenuKeyDown}
                style={
                  placement === null
                    ? // Transparent, not `visibility: hidden`: the first item takes focus
                      // in the same tick, and a hidden element cannot.
                      { top: 0, left: 0, opacity: 0, pointerEvents: "none" }
                    : { top: placement.top, left: placement.left, maxHeight: placement.maxHeight }
                }
                className="fixed z-50 flex w-64 max-w-[calc(100vw-16px)] flex-col overflow-y-auto rounded-card border border-hairline-strong bg-surface-card p-1.5 outline-none"
              >
                {children}
              </div>,
              document.body,
            )
          : null}
      </div>
    </MenuContext.Provider>
  );
}

const ITEM =
  "flex min-h-11 w-full cursor-pointer items-center gap-2.5 rounded-input px-3 text-left text-sm text-text-primary no-underline outline-none transition-colors hover:bg-surface-panel focus-visible:bg-surface-panel focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-brand";

export function MenuItem({
  onSelect,
  children,
  tone = "default",
}: {
  readonly onSelect: () => void;
  readonly children: ReactNode;
  readonly tone?: "default" | "danger";
}) {
  const menu = useMenu();
  return (
    <button
      type="button"
      role="menuitem"
      tabIndex={-1}
      onClick={() => {
        menu.close(true);
        onSelect();
      }}
      className={`${ITEM} ${tone === "danger" ? "text-status-danger" : ""}`}
    >
      {children}
    </button>
  );
}

/** A choice of one: a check beside the selected item, and `aria-checked` on it. */
export function MenuRadio({
  checked,
  onSelect,
  children,
}: {
  readonly checked: boolean;
  readonly onSelect: () => void;
  readonly children: ReactNode;
}) {
  const menu = useMenu();
  return (
    <button
      type="button"
      role="menuitemradio"
      aria-checked={checked}
      tabIndex={-1}
      onClick={() => {
        menu.close(true);
        onSelect();
      }}
      className={ITEM}
    >
      <span className="flex min-w-0 grow items-center gap-2.5">{children}</span>
      {checked ? <IconCheck className="size-4 shrink-0 text-text-muted" /> : null}
    </button>
  );
}

/** A navigation item: a real link, so it opens in a new tab and reads as a link. */
export function MenuLink({
  children,
  ...link
}: Omit<LinkProps, "role" | "tabIndex" | "className"> & { readonly children: ReactNode }) {
  const menu = useMenu();
  return (
    <Link
      {...link}
      role="menuitem"
      tabIndex={-1}
      onClick={(event) => {
        link.onClick?.(event);
        menu.close(false);
      }}
      className={ITEM}
    >
      {children}
    </Link>
  );
}

/** A non-interactive line, or a group heading. Skipped by the arrow keys. */
export function MenuNote({ children }: { readonly children: ReactNode }) {
  return (
    <div role="none" className="truncate px-3 pt-2 pb-1.5 text-[13px] text-text-muted">
      {children}
    </div>
  );
}

export function MenuDivider() {
  return <div role="separator" className="my-1.5 h-px bg-hairline" />;
}
