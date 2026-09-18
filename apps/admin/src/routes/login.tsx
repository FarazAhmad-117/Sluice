import { useEffect, useId, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import {
  Field,
  FormError,
  inputControl,
  primaryButton,
  textLink,
} from "@/components/app/controls";
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

  const emailId = useId();
  const passwordId = useId();

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
      title="Sign in to Sluice"
      lead="Your password is turned into a key in this browser. What reaches the server is a verifier derived from that key, which authenticates you and unlocks nothing."
      footer={
        <>
          No account yet?{" "}
          <Link to="/signup" state={location.state} className={textLink}>
            Create one
          </Link>
          . There is no password reset: the server has never seen your password and has nothing to
          reset.
        </>
      }
    >
      <form
        noValidate
        className="flex flex-col gap-6"
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

        <Field label="Email" htmlFor={emailId}>
          <input
            id={emailId}
            type="email"
            autoComplete="username"
            inputMode="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className={inputControl}
          />
        </Field>

        <Field label="Password" htmlFor={passwordId}>
          <input
            id={passwordId}
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className={inputControl}
          />
        </Field>

        <DerivationProgress phase={phase} />
        {error === null ? null : <FormError>{error}</FormError>}

        <button type="submit" className={primaryButton} disabled={!canSubmit}>
          {busy ? "Signing in" : "Sign in"}
        </button>

        <DerivationPathNotice report={derivation} />
      </form>
    </AuthShell>
  );
}
