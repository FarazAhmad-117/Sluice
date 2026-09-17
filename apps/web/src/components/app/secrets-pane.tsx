"use client";

import { useState } from "react";
import { Eyebrow, StatusPill, focusRing, quietButton } from "@/components/app/controls";
import { VALUE_MASK } from "@/lib/secrets/decrypt";
import type { OpenedSecret, SealedSecretRow } from "@/lib/secrets/decrypt";

/**
 * THE CENTRE PANE: the secrets of one environment.
 *
 * Dense, mono throughout, values masked by default. Density comes from a tight
 * vertical rhythm and hairline dividers, NOT from small type: body text stays
 * at 16px, which is the accessibility floor this product holds to.
 *
 * WHAT THIS TABLE SHOWS AND WHAT IT CANNOT. It reads `secrets.listSecrets` for
 * real and renders one row per live secret with its real metadata. It does NOT
 * show names and values, because it cannot get them: every secret is sealed
 * under the project data key for its environment, the wrapped copies of that
 * key live in `pdkGrants`, and `convex/` exports NO FUNCTION THAT READS OR
 * WRITES THAT TABLE. The client therefore has no route to the key, and no
 * amount of work on this page changes that.
 *
 * So the rows say "sealed" and show the lineage id, which is the one
 * non-secret identifier a row has. They do not show a spinner, because nothing
 * is loading. They do not show a placeholder name, because there is no honest
 * one to show. When a grant query lands, `openSecret` in `lib/secrets/decrypt.ts`
 * is what fills `opened` and every row here starts working with no change to
 * this file beyond deleting the banner.
 *
 * MASKING. The mask is a FIXED WIDTH regardless of the value. One dot per
 * character would publish the length of every secret to anyone looking at a
 * screen share, and a length is a real hint about what a value is.
 */

export interface SecretsPaneProps {
  readonly environmentName: string | null;
  readonly rows: readonly SealedSecretRow[] | undefined;
  /** Opened name and value by `secretId`. Empty until a project data key exists. */
  readonly opened: ReadonlyMap<string, OpenedSecret>;
  readonly locked: boolean;
  readonly selectedSecretId: string | null;
  onSelect(secretId: string): void;
}

/** Enough of a lineage id to tell two rows apart, without the full 32. */
function shortLineage(lineageId: string): string {
  return lineageId.slice(0, 12);
}

export function SecretsPane({
  environmentName,
  rows,
  opened,
  locked,
  selectedSecretId,
  onSelect,
}: SecretsPaneProps) {
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(new Set());

  const toggleReveal = (secretId: string) => {
    setRevealed((current) => {
      const next = new Set(current);
      if (next.has(secretId)) next.delete(secretId);
      else next.add(secretId);
      return next;
    });
  };

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
        {locked ? <StatusPill tone="warning">vault locked</StatusPill> : null}
      </header>

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
              This environment has no secrets. Creating one is not built yet: see the right hand
              panel.
            </p>
          </div>
        ) : (
          <ul className="flex flex-col">
            {rows.map((row) => {
              const open = opened.get(row.secretId);
              const isRevealed = revealed.has(row.secretId);
              const selected = row.secretId === selectedSecretId;

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
                          open === undefined ? "text-text-muted italic" : "text-text-primary"
                        }`}
                      >
                        {open?.name ?? `sealed:${shortLineage(row.lineageId)}`}
                      </span>
                      <span className="w-full min-w-0 truncate font-mono text-base text-text-muted sm:flex-1">
                        {open === undefined
                          ? VALUE_MASK
                          : isRevealed
                            ? open.value
                            : VALUE_MASK}
                      </span>
                    </button>

                    <span className="shrink-0 font-mono text-xs text-text-muted">v{row.version}</span>

                    <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                      <button
                        type="button"
                        disabled={open === undefined}
                        onClick={() => toggleReveal(row.secretId)}
                        className={quietButton}
                        title={
                          open === undefined
                            ? "This client has no key for this environment"
                            : undefined
                        }
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
