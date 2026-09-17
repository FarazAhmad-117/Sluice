"use client";

import { useEffect, useId, useState } from "react";
import {
  Eyebrow,
  Field,
  FormError,
  StatusPill,
  inputControl,
  primaryButton,
} from "@/components/app/controls";
import { DerivationPathNotice, DerivationProgress } from "@/components/auth/derivation";
import { useAuth } from "@/lib/auth/auth-context";
import type { SealedSecretRow } from "@/lib/secrets/decrypt";

/**
 * THE RIGHT PANE.
 *
 * THE DESIGN DIRECTION ASKS FOR THE LIVE AUDIT STREAM HERE, and it is not
 * built, because there is nothing to build it from. `convex/` exports twenty
 * functions and not one of them reads `auditLog`: rows go in through
 * `lib/audit.ts` on every mutation and no query brings them back out. A stream
 * rendered from anything else would be invented data, which the copy rules
 * forbid outright.
 *
 * What this pane carries instead is the other thing that has to be visible at
 * all times and had nowhere to live: the state of the vault, the route the key
 * derivation actually took, when the session dies, and the metadata of the
 * selected secret. The lock state in particular belongs on screen permanently
 * rather than in a toast, because a locked vault is the normal state after
 * every page refresh and the user needs to know why nothing will open.
 */

function remainingLabel(expiresAt: number, now: number): string {
  const remaining = Math.max(0, expiresAt - now);
  const hours = Math.floor(remaining / 3_600_000);
  const minutes = Math.floor((remaining % 3_600_000) / 60_000);
  return `${hours}h ${String(minutes).padStart(2, "0")}m`;
}

/**
 * Re-opens the vault after a refresh. Password only: the session is still live,
 * so there is no second login and no new token, just the local derivation that
 * cannot be skipped because the key is never persisted.
 */
function UnlockForm() {
  const { unlock, phase } = useAuth();
  const passwordId = useId();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const busy = phase !== "idle";

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (busy || password.length === 0) return;
        setError(null);
        void unlock({ password })
          .then(() => setPassword(""))
          .catch((cause: unknown) => {
            setError(cause instanceof Error ? cause.message : "Something went wrong.");
          });
      }}
    >
      <p className="text-base text-text-primary">
        Your session survived the refresh. Your key did not, because it is never written down
        anywhere. Enter your password to open the vault again.
      </p>
      <Field label="Password" htmlFor={passwordId}>
        <input
          id={passwordId}
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className={inputControl}
        />
      </Field>
      <DerivationProgress phase={phase} />
      {error === null ? null : <FormError>{error}</FormError>}
      <button type="submit" className={primaryButton} disabled={busy || password.length === 0}>
        {busy ? "Unlocking" : "Unlock"}
      </button>
    </form>
  );
}

export interface RightPanelProps {
  readonly secret: SealedSecretRow | null;
  /** True when a project data key for the selected environment is in hand. */
  readonly keyAvailable: boolean;
}

export function RightPanel({ secret, keyAvailable }: RightPanelProps) {
  const { session, locked, derivation } = useAuth();
  const [now, setNow] = useState(() => Date.now());

  // A minute is enough for an "h mm" readout and costs nothing.
  useEffect(() => {
    const handle = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(handle);
  }, []);

  return (
    <aside
      aria-label="Session and secret details"
      className="flex h-full min-h-0 flex-col gap-5 overflow-y-auto border-hairline bg-surface-panel p-4 lg:border-l"
    >
      <section className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-2">
          <Eyebrow>Vault</Eyebrow>
          <StatusPill tone={locked ? "warning" : "healthy"}>
            {locked ? "locked" : "unlocked"}
          </StatusPill>
        </div>
        {locked ? (
          <UnlockForm />
        ) : (
          <p className="text-base text-text-muted">
            Your private keys are in memory for this tab only. Closing or refreshing this page
            locks them again.
          </p>
        )}
      </section>

      <section className="flex flex-col gap-2 border-t border-hairline pt-4">
        <Eyebrow>Session</Eyebrow>
        {session === null ? (
          <p className="text-base text-text-muted">No session.</p>
        ) : (
          <dl className="flex flex-col gap-1.5">
            <div className="flex items-baseline justify-between gap-3">
              <dt className="text-base text-text-muted">Expires in</dt>
              <dd className="font-mono text-base text-text-primary">
                {remainingLabel(session.sessionExpiresAt, now)}
              </dd>
            </div>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="shrink-0 text-base text-text-muted">User</dt>
              <dd className="truncate font-mono text-sm text-text-primary">{session.userId}</dd>
            </div>
          </dl>
        )}
        <DerivationPathNotice report={derivation} />
        <p className="text-base text-text-muted">
          The session token is kept in this tab&apos;s sessionStorage, which any script running on
          this origin can read. An httpOnly cookie is not available: every Convex call takes the
          token as a function argument, so the page has to be able to read it.
        </p>
      </section>

      <section className="flex flex-col gap-2 border-t border-hairline pt-4">
        <Eyebrow>Selected secret</Eyebrow>
        {secret === null ? (
          <p className="text-base text-text-muted">Pick a row in the centre pane.</p>
        ) : (
          <dl className="flex flex-col gap-1.5">
            {[
              ["Version", `v${secret.version}`],
              ["Key version", `pdk v${secret.pdkVersion}`],
              ["Lineage", secret.lineageId],
              ["Secret id", secret.secretId],
              ["Environment", secret.environmentId],
            ].map(([label, value]) => (
              <div key={label} className="flex flex-col gap-0.5">
                <dt className="text-base text-text-muted">{label}</dt>
                <dd className="font-mono text-sm break-all text-text-primary">{value}</dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      {/* The honest account of what this surface cannot do, on screen rather
          than only in a report. A user who cannot see a secret name deserves
          the reason rather than a spinner. */}
      <section className="flex flex-col gap-2 border-t border-hairline pt-4">
        <Eyebrow>Not built yet</Eyebrow>
        <ul className="flex list-disc flex-col gap-2 pl-5 text-base text-text-muted">
          {keyAvailable ? null : (
            <li>
              Secret names and values stay sealed. They are encrypted under the project data key
              for their environment, and the backend exposes no function that reads or writes the
              pdkGrants table, so this client has no way to obtain that key.
            </li>
          )}
          <li>
            Creating an organisation, a project or an environment. The backend supports all three;
            creating an org also has to wrap the org revocation signing key, and the format for
            that wrap is not written down anywhere, so guessing it would silently break signed
            revocation.
          </li>
          <li>Creating, editing and revoking secrets.</li>
          <li>
            The live audit stream this pane is meant to carry. Audit rows are written on every
            mutation and no query returns them.
          </li>
        </ul>
      </section>
    </aside>
  );
}
