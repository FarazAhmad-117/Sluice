"use client";

import { useEffect, useState } from "react";
import { openSecretName } from "./decrypt";
import type { SealedSecretRow } from "./decrypt";

/**
 * THE OPENED NAME OF EVERY ROW ON SCREEN, AND NOT ONE VALUE.
 *
 * Names are shown; values are revealed one at a time, on request, by the pane.
 * That split is the reason `decrypt.ts` has `openSecretName` beside
 * `openSecret`: opening the whole row to render a list would decrypt every
 * value in the environment into memory to draw a table nobody asked to reveal,
 * and each plaintext would live for as long as that table did.
 *
 * A row that does not open is ABSENT from the map rather than present with a
 * placeholder. The caller renders it as sealed, which is what it is. That case
 * is real: a row written under an earlier project data key version does not
 * open under the current one, and there is no re-key yet.
 */

const EMPTY: ReadonlyMap<string, string> = new Map();

/**
 * What the stored names belong to.
 *
 * The result is tagged with the key and the rows it was produced from, and is
 * returned only when both still match. That is what makes a stale result
 * UNRENDERABLE rather than merely short-lived: an effect that cleared it would
 * clear it one frame late, and that frame would show one environment's names
 * against another environment's rows.
 */
interface OpenedNames {
  readonly pdk: Uint8Array;
  readonly rowKey: string;
  readonly names: ReadonlyMap<string, string>;
}

export function useSecretNames(
  pdk: Uint8Array | null,
  rows: readonly SealedSecretRow[] | undefined,
): ReadonlyMap<string, string> {
  const [opened, setOpened] = useState<OpenedNames | null>(null);

  // Identity of the listing, not of the array. Two fetches of unchanged data
  // produce the same string, so a redraw does not invalidate the names.
  const rowKey =
    rows === undefined
      ? null
      : rows.map((row) => `${row.secretId}:${row.nameNonce}`).join("|");

  useEffect(() => {
    // No `setState` in the effect body, deliberately: the "nothing to do" cases
    // are handled by the match below, during render, so there is nothing to
    // clear here and no cascading render to cause.
    if (pdk === null || rows === undefined || rowKey === null) return;

    // A result that lands after the environment has changed must never be
    // written into state. The tag would reject it anyway; cancelling avoids the
    // wasted render.
    let cancelled = false;

    void (async () => {
      const names = new Map<string, string>();
      await Promise.all(
        rows.map(async (row) => {
          try {
            names.set(row.secretId, await openSecretName(pdk, row));
          } catch {
            // Swallowed on purpose, and it is the only swallow in this surface.
            // `SecretOpenError` carries no detail by design, one unopenable row
            // must not stop the others rendering, and the row is shown as
            // sealed, which is the truth. Nothing is logged: the caught value
            // is an AEAD rejection and a log line is not a place for it.
          }
        }),
      );
      if (!cancelled) setOpened({ pdk, rowKey, names });
    })();

    return () => {
      cancelled = true;
    };
  }, [pdk, rows, rowKey]);

  if (pdk === null || rowKey === null) return EMPTY;
  // Reference equality on `pdk` is the point. Locking and unlocking the vault
  // produces a different key object, so names opened under the old one are not
  // served across the lock.
  if (opened === null || opened.pdk !== pdk || opened.rowKey !== rowKey) return EMPTY;
  return opened.names;
}
