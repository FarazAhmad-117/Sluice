import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/feedback";
import { TextField } from "@/components/ui/field";
import { focusRing } from "@/components/ui/styles";
import { AuthShell } from "@/components/auth/auth-shell";
import {
  CapabilityNotice,
  DerivationPathNotice,
  DerivationProgress,
} from "@/components/auth/derivation";
import { redirectAfterAuth } from "@/lib/redirect";
import { useAuth } from "@/lib/auth/auth-context";
import { isValidEmail } from "@/lib/auth/email";

/**
 * SIGN IN.
 *
 * Same derivation as signup, one call instead of two: derive the master unlock
 * key, derive the auth verifier from it, send the email and the verifier, and
 * unwrap the blobs that come back. The password does not leave the tab and
 * neither does the key.
 *
 * NO STRENGTH GATE HERE, DELIBERATELY. The account already exists, so a rule
 * applied at this point would only lock out a user whose password predates the
 * rule, while telling an attacker exactly what shape of password to guess. The
 * gate belongs at the one moment the password is chosen.
 *
 * NO PASSWORD RESET LINK HERE, DELIBERATELY. There is no reset. A link that
 * said "forgot your password?" and led to an apology would be worse than its
 * absence, so the footer states the position plainly instead.
 *
 * WHERE IT GOES AFTERWARDS. `redirectAfterAuth` reads the location the route
 * guard stashed, so arriving here by being bounced off a deep link returns to
 * that link rather than to the dashboard root.
 */
export default function LoginRoute() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, phase, derivation, capability, session, configured } = useAuth();

  const destination = redirectAfterAuth(location.state);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const busy = phase !== "idle";
  const canSubmit = configured && isValidEmail(email) && password.length > 0 && !busy;

  // A session already exists, so there is nothing to sign in to. `replace`
  // rather than a push, so the back button does not land on this page again.
  useEffect(() => {
    if (session !== null) void navigate(destination, { replace: true });
  }, [session, destination, navigate]);

  return (
    <AuthShell
      title="Sign in"
      lead="Your password never leaves this browser."
      footer={
        <div className="flex flex-col gap-2">
          <span>
            No account yet?{" "}
            <Link to="/signup" state={location.state} className={`${LINK} ${focusRing}`}>
              Create one
            </Link>
          </span>
          <span className="text-[13px] text-text-faint">
            There is no password reset: the server never sees your password.
          </span>
        </div>
      }
    >
      <form
        noValidate
        className="flex flex-col gap-5"
        onSubmit={(event) => {
          event.preventDefault();
          if (!canSubmit) return;
          setError(null);
          void login({ email, password })
            .then(() => navigate(destination, { replace: true }))
            .catch((cause: unknown) => {
              setError(cause instanceof Error ? cause.message : "Something went wrong.");
            });
        }}
      >
        <CapabilityNotice capability={capability} />

        <TextField
          label="Email"
          type="email"
          autoComplete="username"
          inputMode="email"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />

        <TextField
          label="Password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />

        <DerivationProgress phase={phase} />
        {error === null ? null : (
          <Callout tone="danger" role="alert" title="Not signed in">
            {error}
          </Callout>
        )}

        <Button
          type="submit"
          size="lg"
          loading={busy}
          loadingLabel="Signing in"
          disabled={!canSubmit && !busy}
          className="w-full"
        >
          {busy ? "Signing in" : "Sign in"}
        </Button>

        <DerivationPathNotice report={derivation} />
      </form>
    </AuthShell>
  );
}

const LINK = "rounded-input font-medium text-brand underline-offset-4 hover:text-brand-hover hover:underline";
