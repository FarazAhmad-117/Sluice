"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

/**
 * THE DASHBOARD IS DUAL THEME. THE LANDING PAGE IS NOT.
 *
 * `globals.css` declares the dark token values on `:root` and re-points them
 * under `[data-theme="light"]`, and the root layout ships `data-theme="dark"`
 * in the server HTML. That is correct for the landing page, which the design
 * direction locks to dark so that marketing gets one controlled brand moment.
 *
 * The dashboard is the other half of that decision: it follows the operating
 * system preference by default, because it is a surface people live in. This
 * provider is mounted ONLY under the dashboard routes, so the landing page is
 * untouched and stays dark whatever the viewer's system says.
 *
 * THE FLASH, AND WHY THE INLINE SCRIPT IS NOT OPTIONAL. Server HTML says dark.
 * A viewer whose system is light would see a dark page paint, then flip, if the
 * preference were applied in a React effect: effects run after the first paint.
 * {@link ThemeScript} is a synchronous, blocking `<script>` emitted above the
 * dashboard markup, so the attribute is already correct when the browser paints
 * for the first time. It is the only inline script in this application and it
 * contains no user data.
 *
 * `suppressHydrationWarning` on `<html>` in the root layout is what makes this
 * legal: the script mutates an attribute React put there, and without the
 * suppression React logs a hydration mismatch on every dashboard load.
 *
 * STORAGE. The choice is a per-viewer convenience, so it lives in
 * `localStorage` and every access is wrapped: a private window, blocked site
 * data or a disabled store must degrade to "follow the system", never throw.
 */

export type ThemeChoice = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "sluice.theme";

/**
 * The script text, kept in one place so the inline copy and the React copy
 * cannot drift. It is deliberately tiny and defensive: anything that throws in
 * here runs before the page has painted.
 */
const INLINE_SCRIPT = `
(function(){try{
var c=localStorage.getItem(${JSON.stringify(STORAGE_KEY)});
if(c!=="light"&&c!=="dark"){c=window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}
document.documentElement.setAttribute("data-theme",c);
}catch(e){}})();
`.trim();

/**
 * Emit this as the FIRST child of the dashboard layout, above any markup.
 *
 * Next renders it inline and the browser executes it synchronously at that
 * point in the document, which is before the dashboard's own elements exist and
 * therefore before anything using a theme token has been painted.
 */
export function ThemeScript() {
  // The content is a fixed string literal built above from a constant. No user
  // input reaches it, which is the only condition under which this API is safe.
  return <script dangerouslySetInnerHTML={{ __html: INLINE_SCRIPT }} />;
}

interface ThemeState {
  readonly choice: ThemeChoice;
  readonly resolved: ResolvedTheme;
  setChoice(choice: ThemeChoice): void;
}

const ThemeContext = createContext<ThemeState | null>(null);

function readChoice(): ThemeChoice {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // Blocked or unavailable storage means "follow the system", which is the
    // default anyway.
  }
  return "system";
}

function systemTheme(): ResolvedTheme {
  try {
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  // Both start at the server's value so the first client render matches the
  // server's HTML exactly. The effect below corrects them after hydration; the
  // inline script has already corrected the DOM, so nothing flashes.
  const [choice, setChoiceState] = useState<ThemeChoice>("system");
  const [resolved, setResolved] = useState<ResolvedTheme>("dark");

  // The stored choice is read after mount for the same reason the session is:
  // `localStorage` does not exist during server rendering, and reading it in a
  // state initialiser would make the first client render disagree with the
  // server's HTML. The inline script has already corrected the DOM by this
  // point, so this render costs nothing visible.
  //
  // The lint rule below is suppressed for the same reason as the session read
  // in `auth-context.tsx`: there is no render-time form of a browser-storage
  // read that does not break hydration.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setChoiceState(readChoice());
  }, []);

  // Apply, and follow the system while the choice is "system". The listener is
  // what makes a preference change in the OS move this page without a reload.
  useEffect(() => {
    const apply = () => {
      const next: ResolvedTheme = choice === "system" ? systemTheme() : choice;
      setResolved(next);
      document.documentElement.setAttribute("data-theme", next);
    };
    apply();

    if (choice !== "system") return;
    let media: MediaQueryList;
    try {
      media = window.matchMedia("(prefers-color-scheme: light)");
    } catch {
      return;
    }
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [choice]);

  // On leaving the dashboard, put the document back to the landing page's
  // locked dark. Without this a client-side navigation from a light dashboard
  // to the landing page would render the landing page in light tokens, which
  // the design direction does not allow.
  useEffect(() => {
    return () => {
      document.documentElement.setAttribute("data-theme", "dark");
    };
  }, []);

  const setChoice = useCallback((next: ThemeChoice) => {
    setChoiceState(next);
    try {
      if (next === "system") localStorage.removeItem(STORAGE_KEY);
      else localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // The choice still applies for this page. It just will not be remembered.
    }
  }, []);

  const value = useMemo<ThemeState>(
    () => ({ choice, resolved, setChoice }),
    [choice, resolved, setChoice],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeState {
  const value = useContext(ThemeContext);
  if (value === null) throw new Error("useTheme must be used inside <ThemeProvider>");
  return value;
}
