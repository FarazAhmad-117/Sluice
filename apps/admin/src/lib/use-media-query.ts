import { useSyncExternalStore } from "react";

/**
 * Whether a media query matches, kept in step with the viewport.
 *
 * For the few places a breakpoint changes WHAT renders rather than how it
 * looks: the detail panel is an inline column at 1280px and up and a modal
 * sheet below, and a modal makes the page behind it inert, so the two must
 * never both be mounted. Everywhere else a breakpoint is a Tailwind prefix.
 */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const list = window.matchMedia(query);
      list.addEventListener("change", onChange);
      return () => list.removeEventListener("change", onChange);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}

/** Tailwind's `lg`: the sidebar is a column here and a drawer below. */
export const DESKTOP = "(min-width: 64rem)";
/** Tailwind's `xl`: the secret detail panel sits beside the list here and is a sheet below. */
export const WIDE = "(min-width: 80rem)";
