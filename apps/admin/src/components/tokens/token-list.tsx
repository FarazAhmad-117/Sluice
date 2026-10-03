import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Skeleton } from "@/components/ui/feedback";
import { TextField } from "@/components/ui/field";
import { formatDateTime, timeAgo } from "@/lib/format/time";
import { useNow } from "@/lib/format/use-now";
import { useShell } from "@/lib/shell/shell-context";
import { CONNECTION_LABEL, TARGET_LABEL, canRevoke, connectionState } from "@/lib/tokens/connection";
import type { ConnectionState } from "@/lib/tokens/connection";
import type { TokenRow } from "@/lib/tokens/use-project-tokens";
import { useRevokeToken } from "@/lib/tokens/use-token-actions";

/**
 * A LIST OF SERVICE TOKENS: WHAT EACH IS, WHETHER IT IS CONNECTED, AND REVOKE.
 *
 * Shared by the Environments page (one list per environment) and the Tokens
 * page (all of them). Revoking signs in this browser; the dialog says what
 * that does, and that the reason is broadcast, before anything is signed.
 */

const CHIP: Record<ConnectionState, string> = {
  live: "bg-status-healthy/12 text-status-healthy",
  idle: "border border-hairline-strong text-text-muted",
  never: "border border-dashed border-hairline-strong text-text-muted",
  revoked: "bg-status-danger/10 text-status-danger",
  expired: "bg-status-warning/12 text-status-warning",
};

export function ConnectionChip({ state }: { readonly state: ConnectionState }) {
  return (
    <span className={`inline-flex h-6 shrink-0 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium ${CHIP[state]}`}>
      {state === "live" ? <span aria-hidden className="size-1.5 rounded-full bg-status-healthy" /> : null}
      {CONNECTION_LABEL[state]}
    </span>
  );
}

function seenLine(row: TokenRow, state: ConnectionState, now: number): string {
  if (state === "revoked") return row.revokedAt === null ? "Revoked" : `Revoked ${timeAgo(row.revokedAt, now)}`;
  if (state === "expired" && row.expiresAt !== null) return `Expired ${timeAgo(row.expiresAt, now)}`;
  if (row.lastSeenAt === null) return `Created ${timeAgo(row.createdAt, now)}, not connected yet`;
  return `Last seen ${timeAgo(row.lastSeenAt, now)}`;
}

function TokenName({ row }: { readonly row: TokenRow }) {
  if (row.name === undefined) return <Skeleton className="h-4 w-32" />;
  if (row.name === null) return <span className="text-text-muted italic">Unnamed token</span>;
  return <span className="truncate font-medium text-text-primary">{row.name}</span>;
}

export function TokenList({
  rows,
  showEnvironment,
  empty,
}: {
  readonly rows: readonly TokenRow[];
  readonly showEnvironment: boolean;
  readonly empty?: string;
}) {
  const now = useNow();
  const { announce } = useShell();
  const revoke = useRevokeToken();
  const [pending, setPending] = useState<TokenRow | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (rows.length === 0) {
    return empty === undefined ? null : <p className="m-0 px-4 py-4 text-sm text-text-muted">{empty}</p>;
  }

  const close = () => {
    if (busy) return;
    setPending(null);
    setReason("");
    setError(null);
  };

  const confirm = async () => {
    if (pending === null || typeof pending.tokenIdHex !== "string") return;
    setBusy(true);
    setError(null);
    const result = await revoke({ tokenIdHex: pending.tokenIdHex, reason });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    announce(`${pending.name ?? "The token"} was revoked.`);
    setPending(null);
    setReason("");
  };

  return (
    <>
      <ul className="m-0 list-none p-0">
        {rows.map((row) => {
          const state = connectionState(row, now);
          const revocable = canRevoke(state) && typeof row.tokenIdHex === "string";
          const meta = [
            row.target === null ? null : TARGET_LABEL[row.target],
            showEnvironment ? row.environmentName : null,
            row.createdByIsYou ? "created by you" : row.createdByEmail === null ? null : `created by ${row.createdByEmail}`,
          ].filter((part): part is string => part !== null);
          return (
            <li
              key={row.serviceTokenId}
              className="flex flex-col gap-2 border-t border-hairline px-4 py-3 first:border-t-0 sm:flex-row sm:items-center sm:gap-4"
            >
              <div className="flex min-w-0 grow flex-col gap-0.5">
                <div className="flex min-w-0 items-center gap-2">
                  <TokenName row={row} />
                </div>
                <span className="truncate text-[13px] text-text-muted">{meta.join(" · ")}</span>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                <div className="flex flex-col items-start gap-0.5 sm:items-end">
                  <ConnectionChip state={state} />
                  <span
                    className="text-xs text-text-muted"
                    title={row.lastSeenAt === null ? undefined : formatDateTime(row.lastSeenAt)}
                  >
                    {seenLine(row, state, now)}
                  </span>
                </div>
                {state === "revoked" ? null : (
                  <Button
                    size="sm"
                    variant="danger-outline"
                    disabled={!revocable}
                    title={
                      revocable
                        ? undefined
                        : "This token's details could not be opened here, so it cannot be revoked from this browser."
                    }
                    onClick={() => setPending(row)}
                  >
                    Revoke<span className="sr-only"> {row.name ?? "token"}</span>
                  </Button>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      <ConfirmDialog
        open={pending !== null}
        title={`Revoke ${pending?.name ?? "this token"}?`}
        confirmLabel="Revoke token"
        busy={busy}
        error={error}
        onConfirm={() => void confirm()}
        onClose={close}
      >
        <div className="flex flex-col gap-4">
          <p className="m-0">
            Every process using it stops getting {pending?.environmentName ?? "these"} secrets and shuts down within
            seconds. This cannot be undone; you would create a new token instead.
          </p>
          <TextField
            label="Reason (optional)"
            hint="Sent to every process using this token and written to their logs. Never put a secret here."
            value={reason}
            maxLength={200}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Laptop lost"
          />
        </div>
      </ConfirmDialog>
    </>
  );
}
