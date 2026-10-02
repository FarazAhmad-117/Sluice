import { useEffect, useId, useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { AuthShell } from "@/components/auth/auth-shell";
import {
  CapabilityNotice,
  DerivationPathNotice,
  DerivationProgress,
} from "@/components/auth/derivation";
import { PasswordMeter } from "@/components/auth/password-meter";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/feedback";
import { TextField } from "@/components/ui/field";
import { focusRing } from "@/components/ui/styles";
import { redirectAfterAuth } from "@/lib/redirect";
import { useAuth } from "@/lib/auth/auth-context";
import { isValidEmail } from "@/lib/auth/email";
import { assessPassword } from "@/lib/auth/password";

/**
 * SIGN UP.
 *
 * What leaves this page: an email address, a 64 hex character auth verifier, an
 * X25519 public key, an Ed25519 verify key, and two AES-256-GCM blobs. The
 * password never leaves the tab, and neither does the master unlock key. All of
 * that is enforced in `lib/auth/identity.ts` and `lib/auth/auth-context.tsx`;
 * this file is the form.
 *
 * TWO GATES, AND NEITHER IS DECORATION.
 *
 * 1. THE STRENGTH GATE. The Argon2id salt is a random per-account value, but
 *    it is public (`auth.getLoginSalt` returns it to anyone), so the password
 *    is the only secret input to the master unlock key.
 *    `lib/auth/password.ts` carries the rule and the argument for it.
 *
 * 2. THE ACKNOWLEDGEMENT. There is NO ACCOUNT RECOVERY in this product. The
 *    server has never seen the password and has nothing to reset. A forgotten
 *    password is permanent, total, unrecoverable loss of every secret the
 *    account can reach. That is stated in a bordered panel the eye cannot skip,
 *    in the second person, ABOVE the submit control, and the submit control is
 *    disabled until the box is ticked. A checkbox is a low bar for a
 *    consequence this size; it is the highest bar that does not also train
 *    people to paste text they have not read.
 *
 * On the recovery kit: `packages/crypto/src/muk.ts` describes one, and
 * `auth.signup` accepts an optional `recoveryBlob`. NOTHING IN THIS REPOSITORY
 * GENERATES ONE, so this page does not claim a recovery kit exists. Promising a
 * kit that is never produced would be worse than the honest warning below.
 */
export default function SignupRoute() {
  const navigate = useNavigate();
  const location = useLocation();
  const { signup, phase, derivation, capability, session, configured } = useAuth();

  const destination = redirectAfterAuth(location.state);

  const acknowledgeId = useId();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const assessment = useMemo(() => assessPassword(password, email), [password, email]);

  const busy = phase !== "idle";
  const emailOk = isValidEmail(email);
  const confirmOk = confirm.length > 0 && confirm === password;
  const canSubmit =
    configured && emailOk && assessment.acceptable && confirmOk && acknowledged && !busy;

  // A session already exists, so there is nothing to sign up for. Replace
  // rather than push, so the back button does not land on this page again.
  useEffect(() => {
    if (session !== null) void navigate(destination, { replace: true });
  }, [session, destination, navigate]);

  return (
    <AuthShell
      title="Create your account"
      lead="Your password never leaves this browser."
      footer={
        <>
          Already have an account?{" "}
          <Link
            to="/login"
            state={location.state}
            className={`rounded-input font-medium text-brand underline-offset-4 hover:text-brand-hover hover:underline ${focusRing}`}
          >
            Sign in
          </Link>
        </>
      }
    >
      <form
        noValidate
        className="flex flex-col gap-5"
        onSubmit={(event) => {
          event.preventDefault();
          if (!canSubmit) return;
          setError(null);
          void signup({ email, password })
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
          aria-invalid={email.length > 0 && !emailOk}
        />

        <TextField
          label="Password"
          type="password"
          autoComplete="new-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-invalid={password.length > 0 && !assessment.acceptable}
          hint={<PasswordMeter assessment={assessment} />}
        />

        <TextField
          label="Confirm password"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          error={confirm.length > 0 && !confirmOk ? "The two passwords do not match." : undefined}
        />

        {/* The consequence, in a panel with the danger token on it. It is above
            the submit control rather than below it, because a warning under a
            button is a warning read after the click. */}
        <div className="flex flex-col gap-3 rounded-card border border-status-danger/50 bg-status-danger/8 p-4">
          <p className="m-0 text-sm text-text-primary">
            If you forget this password, your secrets cannot be recovered by anyone, including us.
            Save it in a password manager before you continue.
          </p>
          <label
            htmlFor={acknowledgeId}
            className="flex min-h-11 cursor-pointer items-start gap-3 rounded-input py-1 text-sm text-text-primary"
          >
            <input
              id={acknowledgeId}
              type="checkbox"
              required
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
              className={`mt-0.5 size-[18px] shrink-0 cursor-pointer accent-brand ${focusRing}`}
            />
            <span>I understand that nobody can recover this password for me.</span>
          </label>
        </div>

        <DerivationProgress phase={phase} />
        {error === null ? null : (
          <Callout tone="danger" role="alert" title="The account was not created">
            {error}
          </Callout>
        )}

        <Button
          type="submit"
          size="lg"
          loading={busy}
          loadingLabel="Creating your account"
          disabled={!canSubmit && !busy}
          className="w-full"
        >
          {busy ? "Creating your account" : "Create account"}
        </Button>

        <DerivationPathNotice report={derivation} />
      </form>
    </AuthShell>
  );
}
