import { useCallback, useEffect, useRef, useState } from "react";

/**
 * REVEALED PLAINTEXT, AND THE ONLY PLACE ANY OF IT LIVES ON THE SECRETS PAGE.
 *
 * Held by secret id and TAGGED with a context (the environment on screen and
 * the key whose detail panel is open). The tag is checked during render, so
 * switching environment or selecting another key shows everything masked at
 * once, with no frame of the old values; and a reveal that resolves after the
 * context changed is dropped.
 *
 * Each value masks itself again after 30 seconds, and on a second press.
 */

const REVEAL_MS = 30_000;

interface Store {
  readonly context: string;
  readonly values: ReadonlyMap<string, string>;
  readonly failed: ReadonlySet<string>;
}

const EMPTY_VALUES: ReadonlyMap<string, string> = new Map();
const EMPTY_FAILED: ReadonlySet<string> = new Set();

export interface Reveals {
  /** The plaintext, or `undefined` while masked. */
  value(secretId: string): string | undefined;
  failed(secretId: string): boolean;
  reveal(secretId: string, open: () => Promise<string>): Promise<void>;
  hide(secretId: string): void;
}

export function useReveals(context: string): Reveals {
  const [store, setStore] = useState<Store | null>(null);
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const latest = useRef(context);
  useEffect(() => {
    latest.current = context;
  });
  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const timer of pending.values()) clearTimeout(timer);
      pending.clear();
    };
  }, []);

  const current = store !== null && store.context === context ? store : null;
  const values = current?.values ?? EMPTY_VALUES;
  const failedSet = current?.failed ?? EMPTY_FAILED;

  const change = useCallback(
    (at: string, apply: (values: Map<string, string>, failed: Set<string>) => void) =>
      setStore((previous) => {
        const base = previous !== null && previous.context === at ? previous : null;
        const nextValues = new Map(base?.values ?? []);
        const nextFailed = new Set(base?.failed ?? []);
        apply(nextValues, nextFailed);
        return { context: at, values: nextValues, failed: nextFailed };
      }),
    [],
  );

  const hide = useCallback(
    (secretId: string) => {
      const timer = timers.current.get(secretId);
      if (timer !== undefined) clearTimeout(timer);
      timers.current.delete(secretId);
      change(latest.current, (v) => v.delete(secretId));
    },
    [change],
  );

  const reveal = useCallback(
    async (secretId: string, open: () => Promise<string>) => {
      const at = latest.current;
      try {
        const plaintext = await open();
        if (latest.current !== at) return;
        change(at, (v, f) => {
          v.set(secretId, plaintext);
          f.delete(secretId);
        });
        const previous = timers.current.get(secretId);
        if (previous !== undefined) clearTimeout(previous);
        timers.current.set(
          secretId,
          setTimeout(() => hide(secretId), REVEAL_MS),
        );
      } catch {
        if (latest.current === at) change(at, (_v, f) => f.add(secretId));
      }
    },
    [change, hide],
  );

  return {
    value: (secretId) => values.get(secretId),
    failed: (secretId) => failedSet.has(secretId),
    reveal,
    hide,
  };
}
