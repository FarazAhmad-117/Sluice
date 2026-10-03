import { createContext, useCallback, useContext, useEffect, useState } from "react";

/**
 * WHAT ANY PAGE CAN ASK OF THE APP SHELL.
 *
 * Opening the phone navigation drawer (the page header's menu button lives in
 * the page, the drawer in the shell) and saying a result out loud through the
 * app's ONE polite live region. One region rather than one per page, so a
 * result announced just before a navigation is not cut off by the next page
 * mounting its own.
 */
export interface Shell {
  openNav(): void;
  /** The command palette; also ⌘K / Ctrl+K anywhere. */
  openPalette(): void;
  /** Says `message` once, politely. A repeat of the same message is said again. */
  announce(message: string): void;
}

export const ShellContext = createContext<Shell | null>(null);

export function useShell(): Shell {
  const value = useContext(ShellContext);
  if (value === null) throw new Error("useShell must be used inside the app shell");
  return value;
}

/** How long an announcement stays in the live region. */
const ANNOUNCE_MS = 5_000;

/**
 * The latest message only, cleared after a few seconds so an old result is
 * never read out again after a newer action. A repeat of the same message is
 * cleared first, so it is announced again.
 */
export function useAnnouncer(): [string, (message: string) => void] {
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (message === "") return;
    const timer = setTimeout(() => setMessage(""), ANNOUNCE_MS);
    return () => clearTimeout(timer);
  }, [message]);
  const announce = useCallback((next: string) => {
    setMessage("");
    requestAnimationFrame(() => setMessage(next));
  }, []);
  return [message, announce];
}
