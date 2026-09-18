"use client";

import { useState } from "react";
import type { Id } from "@convex/_generated/dataModel";
import { Eyebrow, StatusPill, focusRing, quietButton } from "@/components/app/controls";
import { NewSecretForm } from "@/components/app/create-forms";
import { VALUE_MASK, openSecretValue } from "@/lib/secrets/decrypt";
import type { SealedSecretRow } from "@/lib/secrets/decrypt";
import type { ProjectDataKeyState } from "@/lib/secrets/use-project-data-key";

/**
 * THE CENTRE PANE: the secrets of one environment.
 *
 * Dense, mono throughout, values masked by default. Density comes from a tight
 * vertical rhythm and hairline dividers, NOT from small type: body text stays
 * at 16px, which is the accessibility floor this product holds to.
 *
 * WHAT THIS TABLE SHOWS. It reads `secrets.listSecrets` for real and, when this
 * client holds the project data key for the environment, it shows every NAME in
 * the clear and every VALUE masked. A previous revision of this comment said
 * names and values could never be shown because no Convex function read
 * `pdkGrants`; that was true then and is not now. `createEnvironment` mints the
 * creator's grant in the same transaction, `getMyPdkGrant` returns it, and the
 * shell opens it with the master unlock key.
 *
 * A NAME IS OPENED FOR EVERY ROW. A VALUE IS OPENED FOR NONE, until somebody
 * presses Reveal on that row. The distinction is the whole reason `decrypt.ts`
 * has `openSecretName` and `openSecretValue` beside `openSecret`: decrypting a
 * value to render a list nobody asked to reveal would put every plaintext in
 * the environment into memory for as long as the list was on screen. Here a
 * revealed value lives in one map, keyed by row, and is DELETED the moment the
 * row is hidden, the environment changes, or the key goes away.
 *
 * A row whose name did not open renders as sealed rather than as an error. That
 * happens for real: a row written under an earlier project data key version
 * does not open under the current one.
 *
 * MASKING. The mask is a FIXED WIDTH regardless of the value. One dot per
 * character would publish the length of every secret to anyone looking at a
 * screen share, and a length is a real hint about what a value is.
 */

export interface SecretsPaneProps {
  readonly environmentId: Id<"environments"> | null;
  readonly environmentName: string | null;
  readonly rows: readonly SealedSecretRow[] | undefined;
  /** Opened NAME by `secretId`. A row that did not open is absent. */
  readonly names: ReadonlyMap<string, string>;
  /** The project data key, when this client holds one for this environment. */
  readonly pdk: Uint8Array | null;
  readonly keyState: ProjectDataKeyState;
  readonly locked: boolean;
  readonly selectedSecretId: string | null;
  onSelect(secretId: string): void;
}

const EMPTY_VALUES: ReadonlyMap<string, string> = new Map();

/** Enough of a lineage id to tell two rows apart, without the full 32. */
function shortLineage(lineageId: string): string {
  return lineageId.slice(0, 12);
}

/**
 * The sentence under the header when no value on this page can be opened.
 *
 * `null` when a key is in hand, so the banner disappears entirely rather than
 * becoming a permanent strip of reassurance.
 */
function keyNotice(keyState: ProjectDataKeyState): string | null {
  switch (keyState.status) {
    case "ready":
    case "idle":
      return null;
    case "loading":
      return "Opening the key for this environment.";
    case "locked":
      return "Your vault is locked, so names and values stay sealed. Unlock it in the right hand panel.";
    case "refused":
      return `This account holds no key for this environment, so its names and values stay sealed. Only the person who created an environment is given its key today, because nothing wraps an existing key to a second member yet. The server said: ${keyState.message}`;
    case "failed":
      return keyState.message;
  }
}

export function SecretsPane({
  environmentId,
  environmentName,
  rows,
  names,
  pdk,
  keyState,
  locked,
  selectedSecretId,
  onSelect,
}: SecretsPaneProps) {
  /**
   * REVEALED PLAINTEXT, AND THE ONLY PLACE ANY OF IT LIVES.
   *
   * One entry per row the user explicitly revealed. Hiding a row deletes its
   * entry. Nothing here is written to storage, to a URL, to a query argument or
   * to a log, and no value is ever lifted into a parent component.
   *
   * IT IS TAGGED WITH THE KEY AND THE ENVIRONMENT IT BELONGS TO, and the match
   * is checked DURING RENDER rather than cleared by an effect. An effect would
   * clear it one frame late, and that frame would paint one environment's
   * plaintext against another environment's rows. Tagging makes the stale case
   * unrenderable instead of merely brief: switch environment, or lock the
   * vault, and the map is not returned at all.
   */
  const [held, setHeld] = useState<{
    pdk: Uint8Array;
    environmentId: Id<"environments">;
    values: ReadonlyMap<string, string>;
    error: string | null;
  } | null>(null);

  const current =
    pdk !== null &&
    environmentId !== null &&
    held !== null &&
    held.pdk === pdk &&
    held.environmentId === environmentId
      ? held
      : null;
  const revealed = current?.values ?? EMPTY_VALUES;
  const revealError = current?.error ?? null;

  const hide = (secretId: string) => {
    setHeld((previous) => {
      if (previous === null) return null;
      const values = new Map(previous.values);
      values.delete(secretId);
      return { ...previous, values };
    });
  };

  const reveal = (row: SealedSecretRow) => {
    if (pdk === null || environmentId === null) return;
    void openSecretValue(pdk, row)
      .then((value) => {
        setHeld((previous) => {
          const base =
            previous !== null &&
            previous.pdk === pdk &&
            previous.environmentId === environmentId
              ? previous.values
              : EMPTY_VALUES;
          return {
            pdk,
            environmentId,
            values: new Map(base).set(row.secretId, value),
            error: null,
          };
        });
      })
      .catch(() => {
        // `SecretOpenError` and nothing else reaches here, and it deliberately
        // carries no detail. The value is not shown and nothing is logged.
        setHeld((previous) => ({
          pdk,
          environmentId,
          values:
            previous !== null &&
            previous.pdk === pdk &&
            previous.environmentId === environmentId
              ? previous.values
              : EMPTY_VALUES,
          error: "That value could not be opened with the key this client holds.",
        }));
      });
  };

  const notice = keyNotice(keyState);

  return (
    <section className="flex h-full min-h-0 flex-col bg-surface-base">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-4 py-3">
        <div className="flex min-w-0 items-baseline gap-3">
          <h1 className="truncate font-mono text-base font-medium text-text-primary">
            {environmentName ?? "No environment selected"}
          </h1>
          {rows === undefined ? null : (
            <span className="font-mono text-sm text-text-muted">{rows.length}</span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {locked ? <StatusPill tone="warning">vault locked</StatusPill> : null}
          {environmentId !== null && pdk !== null ? (
            <NewSecretForm environmentId={environmentId} pdk={pdk} />
          ) : null}
        </div>
      </header>

      {notice === null ? null : (
        <p className="border-b border-hairline px-4 py-3 text-base text-text-muted">{notice}</p>
      )}
      {revealError === null ? null : (
        <p role="alert" className="border-b border-hairline px-4 py-3 text-base text-text-primary">
          {revealError}
        </p>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        {environmentName === null ? (
          <p className="px-4 py-6 text-base text-text-muted">
            Pick an environment in the left pane.
          </p>
        ) : rows === undefined ? (
          <p className="px-4 py-6 text-base text-text-muted">Loading secrets</p>
        ) : rows.length === 0 ? (
          <div className="flex flex-col gap-2 px-4 py-6">
            <Eyebrow>Empty</Eyebrow>
            <p className="text-base text-text-muted">
              {pdk === null
                ? "This environment has no secrets. Adding one needs the key for this environment."
                : "This environment has no secrets. Add one with the control above."}
            </p>
          </div>
        ) : (
          <ul className="flex flex-col">
            {rows.map((row) => {
              const name = names.get(row.secretId);
              const value = revealed.get(row.secretId);
              const isRevealed = value !== undefined;
              const selected = row.secretId === selectedSecretId;
              const openable = pdk !== null && name !== undefined;

              return (
                <li key={row.secretId}>
                  {/* A row is a button so it is reachable by keyboard and
                      announces itself. Actions are revealed on hover AND on
                      focus-within, because hover-only actions do not exist for
                      anyone using a keyboard. */}
                  <div
                    className={`group flex items-center gap-3 border-b border-hairline px-4 py-2.5 transition-colors ${
                      selected ? "bg-brand-subtle" : "hover:bg-surface-card"
                    }`}
                  >
                    <button
                      type="button"
                      onClick={() => onSelect(row.secretId)}
                      className={`flex min-w-0 flex-1 cursor-pointer flex-col items-start gap-1 rounded-input text-left sm:flex-row sm:items-center sm:gap-4 ${focusRing}`}
                    >
                      <span
                        className={`w-full truncate font-mono text-base sm:w-2/5 ${
                          name === undefined ? "text-text-muted italic" : "text-text-primary"
                        }`}
                      >
                        {name ?? `sealed:${shortLineage(row.lineageId)}`}
                      </span>
                      <span className="w-full min-w-0 truncate font-mono text-base text-text-muted sm:flex-1">
                        {isRevealed ? value : VALUE_MASK}
                      </span>
                    </button>

                    <span className="shrink-0 font-mono text-xs text-text-muted">v{row.version}</span>

                    <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                      <button
                        type="button"
                        disabled={!openable}
                        onClick={() => (isRevealed ? hide(row.secretId) : reveal(row))}
                        className={quietButton}
                        title={openable ? undefined : "This client has no key for this row"}
                      >
                        {isRevealed ? "Hide" : "Reveal"}
                      </button>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}
