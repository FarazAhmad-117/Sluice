import { useSyncExternalStore } from "react";

/**
 * The current time for rendering "3 minutes ago", refreshed every 30 seconds.
 *
 * One shared clock for every component, read through `useSyncExternalStore`
 * so render stays pure (no `Date.now()` during render) and every relative time
 * on screen moves on the same tick.
 */

const TICK_MS = 30_000;
let now = Date.now();
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | null = null;

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange);
  if (timer === null) {
    now = Date.now();
    timer = setInterval(() => {
      now = Date.now();
      for (const listener of listeners) listener();
    }, TICK_MS);
  }
  return () => {
    listeners.delete(onChange);
    if (listeners.size === 0 && timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };
}

export function useNow(): number {
  return useSyncExternalStore(
    subscribe,
    () => now,
    () => now,
  );
}
