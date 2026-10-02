import type { ReactNode, RefObject } from "react";
import { Button, IconButton } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy-button";
import { IconClose, IconEye, IconEyeOff, IconPlus } from "@/components/ui/icons";
import { ScopePill } from "@/components/ui/pill";
import { focusRing } from "@/components/ui/styles";
import { middleTruncate } from "@/lib/format/id";
import { VALUE_MASK } from "@/lib/secrets/decrypt";
import type { CompareCell } from "@/lib/secrets/compare";
import type { Reveals } from "@/lib/secrets/use-reveals";
import type { SecretScope } from "@/lib/secrets/scope";
import type { ListedSecret } from "@/lib/secrets/use-project-secrets";

/**
 * ONE KEY, ACROSS EVERY ENVIRONMENT.
 *
 * A 380px column beside the list at 1280px and up, the body of a sheet below
 * (the sheet brings its own title and close). One block per environment that
 * has the key, masked until somebody presses its eye; an environment without
 * it says so and offers "Add here". Then the version, when it last changed
 * (only when the server sent a time), the secret's id, and the actions.
 */

export interface DetailProps {
  readonly name: string;
  /** The row in the environment on screen, if it has the key. */
  readonly scope: { readonly scope: SecretScope; readonly environmentName: string; readonly missingIn: readonly string[] } | null;
  readonly cells: readonly CompareCell<ListedSecret>[];
  readonly reveals: Reveals;
  readonly openValue: (cell: CompareCell<ListedSecret>) => Promise<string>;
  readonly canOpen: (environmentId: string) => boolean;
  readonly onAnnounce: (message: string) => void;
  readonly version: number | null;
  /** "2 minutes ago", or `null` when no time was recorded. */
  readonly lastChanged: { readonly label: string; readonly title: string } | null;
  /** `shr_...` for a shared secret, else the row's `sec_...`. */
  readonly secretUid: string | null;
  readonly onEdit: (() => void) | null;
  readonly onDelete: (() => void) | null;
  readonly deleteLabel: string;
  readonly onAddHere: (environmentId: string) => void;
  readonly runCommand: string;
  readonly runEnvironment: string;
}

function ValueBlock({
  cell,
  name,
  props,
}: {
  readonly cell: CompareCell<ListedSecret>;
  readonly name: string;
  readonly props: DetailProps;
}) {
  const { reveals } = props;
  if (cell.kind === "missing" || cell.kind === "unknown") {
    return (
      <li className="flex min-h-[52px] items-center justify-between gap-3 border-t border-hairline px-3.5 py-2 first:border-t-0">
        <span className="text-sm text-text-muted">
          {cell.kind === "missing" ? `Not in ${cell.environmentName}` : `Not known in ${cell.environmentName}`}
        </span>
        {cell.kind === "missing" ? (
          <Button size="sm" variant="secondary" icon={<IconPlus className="size-3.5" />} onClick={() => props.onAddHere(cell.environmentId)}>
            Add here
            <span className="sr-only">: {name} to {cell.environmentName}</span>
          </Button>
        ) : null}
      </li>
    );
  }
  const secret = cell.secret!;
  const value = reveals.value(secret.secretId);
  const failed = reveals.failed(secret.secretId);
  const openable = props.canOpen(cell.environmentId);
  const label = `${name} in ${cell.environmentName}`;
  return (
    <li className="flex flex-col gap-2 border-t border-hairline px-3.5 py-3 first:border-t-0">
      <div className="flex items-center justify-between gap-3">
        <span className="truncate text-sm text-text-primary">{cell.environmentName}</span>
        {cell.kind === "shared" ? (
          <span className="text-xs text-text-muted">Shared value</span>
        ) : cell.kind === "own" ? (
          <span className="text-xs text-status-warning light:text-text-primary">Own value</span>
        ) : null}
      </div>
      <div className="flex items-center gap-1 rounded-[7px] border border-hairline bg-surface-deep py-0.5 pr-0.5 pl-2.5">
        <code
          className={`min-w-0 grow font-mono text-[12.5px] ${
            value === undefined ? "overflow-hidden text-clip whitespace-nowrap tracking-[0.12em] text-text-muted" : value === "" ? "text-text-muted" : "break-all text-text-primary"
          }`}
        >
          {value === undefined ? (failed ? "Could not be opened" : VALUE_MASK) : value === "" ? "Empty value" : value}
        </code>
        <button
          type="button"
          aria-label={value === undefined ? `Show value of ${label}` : `Hide value of ${label}`}
          aria-pressed={value !== undefined}
          disabled={!openable}
          onClick={() =>
            value === undefined ? void reveals.reveal(secret.secretId, () => props.openValue(cell)) : reveals.hide(secret.secretId)
          }
          className={`inline-flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-input text-text-muted transition-colors hover:bg-surface-card hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40 lg:size-8 lg:pointer-coarse:size-11 ${focusRing}`}
        >
          {value === undefined ? <IconEye className="size-[15px]" /> : <IconEyeOff className="size-[15px]" />}
        </button>
        {openable ? (
          <CopyButton text={() => props.openValue(cell)} label={`Copy value of ${label}`} onDone={props.onAnnounce} />
        ) : null}
      </div>
    </li>
  );
}

function Facts({ props }: { readonly props: DetailProps }) {
  const rows: [string, ReactNode][] = [];
  if (props.version !== null) rows.push(["Version", `v${props.version}`]);
  if (props.lastChanged !== null) rows.push(["Last changed", <span title={props.lastChanged.title}>{props.lastChanged.label}</span>]);
  if (props.secretUid !== null) {
    rows.push([
      "Secret id",
      <span className="flex items-center gap-1">
        <code title={props.secretUid} className="font-mono text-xs text-text-muted">
          {middleTruncate(props.secretUid)}
        </code>
        <CopyButton text={props.secretUid} label="Copy the secret id" onDone={props.onAnnounce} />
      </span>,
    ]);
  }
  if (rows.length === 0) return null;
  return (
    <dl className="m-0 grid grid-cols-[100px_minmax(0,1fr)] items-center gap-y-1.5 pt-1 text-[13px]">
      {rows.map(([term, detail]) => (
        <div key={term} className="contents">
          <dt className="text-text-muted">{term}</dt>
          <dd className="m-0 flex min-h-8 items-center text-text-primary">{detail}</dd>
        </div>
      ))}
    </dl>
  );
}

/** The panel's body: values, facts, actions, run command. */
export function SecretDetailBody({ props }: { readonly props: DetailProps }) {
  return (
    <div className="flex grow flex-col">
      <div className="flex flex-col gap-3 px-5 py-[18px]">
        <h3 className="m-0 text-sm font-medium text-text-primary">Value in each environment</h3>
        <ul className="m-0 list-none overflow-hidden rounded-[10px] border border-hairline p-0">
          {props.cells.map((cell) => (
            <ValueBlock key={cell.environmentId} cell={cell} name={props.name} props={props} />
          ))}
        </ul>
        <Facts props={props} />
      </div>
      {props.onEdit === null && props.onDelete === null ? null : (
        <div className="flex gap-2 px-5">
          {props.onEdit === null ? null : (
            <Button size="sm" variant="secondary" className="grow" onClick={props.onEdit}>
              Edit value
            </Button>
          )}
          {props.onDelete === null ? null : (
            <Button size="sm" variant="danger-outline" className="grow" onClick={props.onDelete}>
              {props.deleteLabel}
            </Button>
          )}
        </div>
      )}
      <div className="min-h-5 grow" />
      <div className="m-5 flex flex-col gap-1 rounded-[10px] border border-hairline bg-surface-deep py-2 pr-1.5 pl-3.5">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-text-muted">Run with {props.runEnvironment} secrets</span>
          <CopyButton text={props.runCommand} label="Copy the run command" onDone={props.onAnnounce} />
        </div>
        <code className="pr-2 pb-1.5 font-mono text-[12.5px] leading-relaxed break-words text-text-primary">
          {props.runCommand}
        </code>
      </div>
    </div>
  );
}

/** The 380px column, at 1280px and up. */
export function SecretDetailAside({
  props,
  panelId,
  onClose,
  closeRef,
}: {
  readonly props: DetailProps;
  readonly panelId: string;
  readonly onClose: () => void;
  readonly closeRef: RefObject<HTMLButtonElement | null>;
}) {
  return (
    <aside
      id={panelId}
      aria-label={`${props.name} details`}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          onClose();
        }
      }}
      className="sticky top-0 flex max-h-[100dvh] w-[380px] shrink-0 flex-col overflow-y-auto border-l border-hairline bg-surface-panel"
    >
      <div className="flex items-start justify-between gap-3 border-b border-hairline py-4 pr-3 pl-5">
        <div className="flex min-w-0 flex-col gap-2 pt-0.5">
          <h2 className="m-0 font-mono text-[15px] font-medium break-all text-text-primary">{props.name}</h2>
          {props.scope === null ? null : (
            <span className="self-start">
              <ScopePill scope={props.scope.scope} environmentName={props.scope.environmentName} missingIn={props.scope.missingIn} />
            </span>
          )}
        </div>
        <IconButton ref={closeRef} label={`Close ${props.name} details`} onClick={onClose}>
          <IconClose className="size-4" />
        </IconButton>
      </div>
      <SecretDetailBody props={props} />
    </aside>
  );
}

/** The sheet's body, under the drawer's own title bar: the scope, then the same body. */
export function SecretDetailSheet({ props }: { readonly props: DetailProps }) {
  return (
    <div className="-m-6 flex grow flex-col">
      {props.scope === null ? null : (
        <div className="px-5 pt-4">
          <ScopePill scope={props.scope.scope} environmentName={props.scope.environmentName} missingIn={props.scope.missingIn} />
        </div>
      )}
      <SecretDetailBody props={props} />
    </div>
  );
}
