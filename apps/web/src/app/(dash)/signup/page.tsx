"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useState } from "react";
import {
  Field,
  FormError,
  focusRing,
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
import { PasswordMeter } from "@/components/auth/password-meter";
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
 * 1. THE STRENGTH GATE. The Argon2id salt is derived from the email address,
 *    which is public, so the password is the only entropy in the master unlock
 *    key. `lib/auth/password.ts` carries the rule and the argument for it.
 *
 * 2. THE ACKNOWLEDGEMENT. There is NO ACCOUNT RECOVERY in this product. The
 *    server has never seen the password and has nothing to reset. A forgotten
 *    password is permanent, total, unrecoverable loss of every secret the
 *    account can reach. That is stated in a bordered panel the eye cannot skip,
 *    in the second person, and the submit control is disabled until the box is
 *    ticked. A checkbox is a low bar for a consequence this size; it is the
 *    highest bar that does not also train people to paste text they have not
 *    read.
 *
 * On the recovery kit: `packages/crypto/src/muk.ts` describes one, and
 * `auth.signup` accepts an optional `recoveryBlob`. NOTHING IN THIS REPOSITORY
 * GENERATES ONE, so this page does not claim a recovery kit exists. Promising a
 * kit that is never produced would be worse than the honest warning below.
 */
export default function SignupPage() {
  const router = useRouter();
  const { signup, phase, derivation, capability, session, configured } = useAuth();

  const emailId = useId();
  const passwordId = useId();
  const confirmId = useId();
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
    if (session !== null) router.replace("/app");
  }, [session, router]);

  return (
    <AuthShell
      title="Create your Sluice account"
      lead="Your password is turned into a key in this browser and never sent anywhere. The server stores public keys and sealed blobs it cannot open."
      footer={
        <>
          Already have an account?{" "}
          <Link href="/login" className={textLink}>
            Sign in
          </Link>
          .
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
          void signup({ email, password })
            .then(() => router.replace("/app"))
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
            aria-invalid={email.length > 0 && !emailOk}
          />
        </Field>

        <Field
          label="Password"
          htmlFor={passwordId}
          hint={<PasswordMeter assessment={assessment} />}
        >
          <input
            id={passwordId}
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className={inputControl}
            aria-invalid={password.length > 0 && !assessment.acceptable}
          />
        </Field>

        <Field label="Confirm password" htmlFor={confirmId}>
          <input
            id={confirmId}
            type="password"
            autoComplete="new-password"
            required
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            className={inputControl}
            aria-invalid={confirm.length > 0 && !confirmOk}
          />
        </Field>
        {confirm.length > 0 && !confirmOk ? (
          <p className="text-base text-status-danger">The two passwords do not match.</p>
        ) : null}

        {/* The consequence, in a panel with the danger token on it. It is above
            the submit control rather than below it, because a warning under a
            button is a warning read after the click. */}
        <div className="flex flex-col gap-3 rounded-card border border-status-danger/60 bg-status-danger/10 p-4">
          <h2 className="text-base font-medium text-text-primary">
            There is no way to recover this password.
          </h2>
          <p className="text-base text-text-primary">
            Sluice never receives your password and never receives your key. That is the whole
            point, and it has one consequence with no exceptions: if you forget this password, no
            support request, no database access and no amount of time will get your secrets back.
            They are gone. Write it down, or put it in a password manager, before you continue.
          </p>
          <label
            htmlFor={acknowledgeId}
            className={`flex cursor-pointer items-start gap-3 rounded-input p-1 text-base text-text-primary focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-brand`}
          >
            <input
              id={acknowledgeId}
              type="checkbox"
              required
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
              className={`mt-1 size-5 shrink-0 cursor-pointer accent-brand-solid ${focusRing}`}
            />
            <span>
              I understand that forgetting this password permanently destroys access to every
              secret in this account.
            </span>
          </label>
        </div>

        <DerivationProgress phase={phase} />
        {error === null ? null : <FormError>{error}</FormError>}

        <button type="submit" className={primaryButton} disabled={!canSubmit}>
          {busy ? "Creating your account" : "Create account"}
        </button>

        <DerivationPathNotice report={derivation} />
      </form>
    </AuthShell>
  );
}
