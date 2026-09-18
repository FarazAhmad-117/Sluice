import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { THEME_STORAGE_KEY } from "./theme-storage";

/**
 * THIS APPLICATION IS DUAL THEME THROUGHOUT.
 *
 * That is the half of a decision whose other half lives on the marketing site.
 * The landing page is dark-locked, so that marketing gets one controlled brand
 * moment; the admin panel follows the operating system preference by default,
 * because it is a surface people live in. `app.css` declares the dark token
 * values on `:root` and re-points them under `[data-theme="light"]`, and this
 * provider decides which of those is in force.
 *
 * WHAT MOVED WHEN THIS LEFT NEXT, AND WHY IT GOT SIMPLER.
 *
 * 1. `ThemeScript` IS GONE FROM THIS FILE. The pre-paint script is still
 *    mandatory -- `index.html` is a static file, so the server always sends
 *    `data-theme="dark"` and a viewer on a light machine would watch the page
 *    flip if the preference were applied in an effect. What changed is where it
 *    is emitted: `vite.config.ts` injects it into `<head>` from
 *    `theme-storage.ts`, so the script and this module read the same constant
 *    and cannot drift.
 *
 * 2. THE STORED CHOICE IS READ SYNCHRONOUSLY, in the `useState` initialiser
 *    below. Under Next that was illegal: `localStorage` does not exist during
 *    server rendering, and reading it in an initialiser made the first client
 *    render disagree with the server's HTML, so it had to happen in an effect
 *    and cost an extra render. There is no server render here, so the honest
 *    form is also the correct one.
 *
 * 3. THE "PUT IT BACK TO DARK ON UNMOUNT" EFFECT IS GONE. It existed because a
 *    client-side navigation out of the dashboard and onto the landing page
 *    would otherwise have rendered the dark-locked landing page in light
 *    tokens. The landing page is a different application on a different origin
 *    now, so leaving this one is a full page load and there is nothing left to
 *    restore.
 *
 * STORAGE. The choice is a per-viewer convenience, so it lives in
 * `localStorage` and every access is wrapped: a private window, blocked site
 * data or a disabled store must degrade to "follow the system", never throw.
 */

export type ThemeChoice = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

interface ThemeState {
  readonly choice: ThemeChoice;
  readonly resolved: ResolvedTheme;
  setChoice(choice: ThemeChoice): void;
}

const ThemeContext = createContext<ThemeState | null>(null);

function readChoice(): ThemeChoice {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
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
  const [choice, setChoiceState] = useState<ThemeChoice>(readChoice);
  // Seeded from the same reading the injected script made, so the first render
  // already agrees with the attribute that is on the document.
  const [resolved, setResolved] = useState<ResolvedTheme>(() => {
    const stored = readChoice();
    return stored === "system" ? systemTheme() : stored;
  });

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

  const setChoice = useCallback((next: ThemeChoice) => {
    setChoiceState(next);
    try {
      if (next === "system") localStorage.removeItem(THEME_STORAGE_KEY);
      else localStorage.setItem(THEME_STORAGE_KEY, next);
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
