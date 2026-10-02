import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { useNavigate } from "react-router";
import { DerivationProgress } from "@/components/auth/derivation";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/ui/field";
import { messageForUser } from "@/lib/auth/auth-errors";
import { useAuth } from "@/lib/auth/auth-context";

/**
 * THE PAGE, OR THE PASSWORD THAT OPENS IT.
 *
 * A reload keeps the session (it is in this tab's sessionStorage) and loses the
 * master unlock key (it is never written anywhere). Every screen behind this
 * needs that key to show a single name, so while the vault is locked the page
 * is replaced by one card that asks for the password, rather than every
 * screen inventing its own locked state.
 */
export function UnlockGate({ children }: { readonly children: ReactNode }) {
  const { locked } = useAuth();
  if (!locked) return <>{children}</>;
  return <UnlockCard />;
}

function UnlockCard() {
  const { unlock, logout, phase } = useAuth();
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const field = useRef<HTMLInputElement>(null);
  const busy = phase !== "idle";

  return (
    <div className="flex justify-center py-16 sm:py-24">
      <form
        className="flex w-full max-w-[400px] flex-col gap-6 rounded-card border border-hairline bg-surface-panel p-6 sm:p-8"
        onSubmit={(event) => {
          event.preventDefault();
          if (busy) return;
          if (password.length === 0) {
            setError("Enter your password.");
            field.current?.focus();
            return;
          }
          setError(null);
          void unlock({ password })
            .then(() => setPassword(""))
            .catch((cause: unknown) => {
              setError(messageForUser(cause));
              field.current?.focus();
            });
        }}
      >
        <div className="flex flex-col gap-2">
          <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-text-primary">
            Unlock Sluice
          </h1>
          <p className="m-0 text-text-muted">
            Your session is still signed in. Enter your password to open your keys in this browser.
          </p>
        </div>
        <TextField
          ref={field}
          label="Password"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          error={error ?? undefined}
        />
        <DerivationProgress phase={phase} />
        <div className="flex flex-col gap-3">
          <Button type="submit" size="lg" loading={busy} loadingLabel="Unlocking" className="w-full">
            Unlock
          </Button>
          <Button
            variant="ghost"
            className="w-full"
            onClick={() => {
              void logout().then(() => navigate("/login", { replace: true }));
            }}
          >
            Sign out
          </Button>
        </div>
      </form>
    </div>
  );
}
