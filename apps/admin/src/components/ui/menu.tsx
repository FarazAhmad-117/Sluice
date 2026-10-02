import { createContext, useContext, useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { Link } from "react-router";
import type { LinkProps } from "react-router";
import { IconCheck } from "./icons";
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

  const close = (returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) button.current?.focus();
  };

  useEffect(() => {
    if (!open) return;
    const all = items(list.current);
    const target = focusOnOpen.current === "last" ? all[all.length - 1] : all[0];
    (target ?? list.current)?.focus();

    const onPointerDown = (event: PointerEvent) => {
      if (event.target instanceof Node && root.current?.contains(event.target) === true) return;
      setOpen(false);
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
        setOpen(false);
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
            setOpen((value) => !value);
          }}
          onKeyDown={onTriggerKeyDown}
          className={`${focusRing} ${triggerClassName}`}
        >
          {trigger}
        </button>
        {open ? (
          <div
            ref={list}
            id={menuId}
            role="menu"
            aria-label={label}
            tabIndex={-1}
            onKeyDown={onMenuKeyDown}
            className={`absolute top-full z-40 mt-2 flex max-h-[70dvh] w-64 max-w-[calc(100vw-32px)] flex-col overflow-y-auto rounded-card border border-hairline-strong bg-surface-card p-1.5 outline-none ${
              align === "end" ? "right-0" : "left-0"
            }`}
          >
            {children}
          </div>
        ) : null}
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
