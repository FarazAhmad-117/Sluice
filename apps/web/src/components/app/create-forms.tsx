"use client";

import { useId, useState } from "react";
import { useMutation } from "convex/react";
import { ConvexError } from "convex/values";
import type { ReactNode } from "react";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import {
  Field,
  FormError,
  inputControl,
  primaryButton,
  quietButton,
} from "@/components/app/controls";
import { useAuth } from "@/lib/auth/auth-context";
import { SLUG_HINT, isSlug } from "@/lib/naming";
import { createProjectDataKey, wrapProjectDataKey } from "@/lib/secrets/pdk";
import { sealSecret } from "@/lib/secrets/seal";

/**
 * CREATING THE THINGS THIS DASHBOARD READS.
 *
 * Two of the three forms below mint or use key material in this browser, and
 * the server never sees any of it:
 *
 *   environment  a fresh 32 byte project data key is generated here, wrapped
 *                under the master unlock key, and only the ciphertext and its
 *                nonce are sent. `createEnvironment` writes the environment and
 *                that first grant in ONE transaction, so an environment whose
 *                secrets nobody can open cannot exist.
 *   secret       the name and the value are sealed here under the project data
 *                key for the environment, bound to that environment id by the
 *                associated data. The mutation takes four hex strings.
 *
 * CREATING AN ORGANISATION IS NOT HERE, and its absence is the one thing that
 * still leaves a fresh account with nowhere to go. `orgs.createOrg` requires
 * `wrappedRevocationKey`: the org's Ed25519 revocation signing key, wrapped to
 * its creator. THE ASSOCIATED DATA FOR THAT WRAP IS NOT DEFINED ANYWHERE.
 * `@sluice/crypto` defines exactly three cross-wire constructions,
 * `secretAssociatedData`, `pdkAssociatedData` and `tokenIdHash`, and none of
 * them is this one. Choosing a literal here would pin bytes that the backend
 * and the SDK would later have to match by coincidence, and if they did not,
 * the failure is a revocation notice that cannot be signed, discovered during
 * the incident revocation exists for. That belongs in the package, beside its
 * three siblings, and not in a form component.
 */

/**
 * A form that is closed until it is needed.
 *
 * A permanently open form in a nav pane is a permanently open form, and this
 * one sits under a list somebody is trying to read. The trigger is a real
 * button, so it is in the tab order and announces its state.
 */
function Disclosure({
  label,
  children,
}: {
  label: string;
  children: (close: () => void) => ReactNode;
}) {
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className={quietButton}>
        {label}
      </button>
    );
  }
  return (
    <div className="flex flex-col gap-3 rounded-input border border-hairline bg-surface-base p-3">
      {children(() => setOpen(false))}
      <button type="button" onClick={() => setOpen(false)} className={quietButton}>
        Cancel
      </button>
    </div>
  );
}

/**
 * Turns anything a mutation throws into a sentence.
 *
 * `ConvexError.data` carries the server's own message, which is already written
 * for a person and deliberately says nothing it should not. Everything else
 * gets a generic line: a raw transport error is noise, and a thrown value on
 * these paths can carry ciphertext.
 */
function messageFor(cause: unknown): string {
  if (cause instanceof ConvexError && typeof cause.data === "string" && cause.data.length > 0) {
    return cause.data;
  }
  if (cause instanceof Error && cause.name === "PdkUnwrapError") return cause.message;
  return "That did not work. Try again.";
}

export function NewProjectForm({
  orgId,
  onCreated,
}: {
  orgId: Id<"orgs">;
  onCreated(projectId: Id<"projects">): void;
}) {
  const { session } = useAuth();
  const createProject = useMutation(api.projects.createProject);
  const nameId = useId();
  const slugId = useId();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ready = name.trim().length > 0 && isSlug(slug) && !busy;

  return (
    <Disclosure label="New project">
      {(close) => (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (!ready || session === null) return;
            setBusy(true);
            setError(null);
            void createProject({
              sessionToken: session.sessionToken,
              orgId,
              name: name.trim(),
              slug,
            })
              .then((projectId) => {
                setName("");
                setSlug("");
                onCreated(projectId);
                close();
              })
              .catch((cause: unknown) => setError(messageFor(cause)))
              .finally(() => setBusy(false));
          }}
        >
          <Field label="Name" htmlFor={nameId}>
            <input
              id={nameId}
              value={name}
              onChange={(event) => setName(event.target.value)}
              className={inputControl}
              autoComplete="off"
            />
          </Field>
          {/* Its own field, always visible, never derived from the name. The
              server REJECTS a bad slug rather than rewriting it, precisely so
              that two names cannot collapse onto one identifier. */}
          <Field label="Slug" htmlFor={slugId} hint={SLUG_HINT}>
            <input
              id={slugId}
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
              className={`${inputControl} font-mono`}
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
          {error === null ? null : <FormError>{error}</FormError>}
          <button type="submit" className={primaryButton} disabled={!ready}>
            {busy ? "Creating" : "Create project"}
          </button>
        </form>
      )}
    </Disclosure>
  );
}

/**
 * THE FORM THAT MINTS A PROJECT DATA KEY.
 *
 * It needs the master unlock key, so it is unavailable while the vault is
 * locked, and it says so rather than failing on submit. Creating an environment
 * whose key was wrapped under nothing is not a state this offers.
 */
export function NewEnvironmentForm({
  projectId,
  onCreated,
}: {
  projectId: Id<"projects">;
  onCreated(environmentId: Id<"environments">): void;
}) {
  const { session, muk } = useAuth();
  const createEnvironment = useMutation(api.environments.createEnvironment);
  const nameId = useId();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (session === null || muk === null) {
    return (
      <p className="px-2.5 py-1.5 text-base text-text-muted">
        Unlock your vault to add an environment. Creating one mints its encryption key in this
        browser.
      </p>
    );
  }

  // `name` is the last segment of the address the SDK resolves a config by, so
  // it obeys the slug rule rather than the display-name rule.
  const ready = isSlug(name) && !busy;

  return (
    <Disclosure label="New environment">
      {(close) => (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (!ready) return;
            setBusy(true);
            setError(null);
            void (async () => {
              try {
                // MINTED HERE. This 32 byte key is the only thing that will
                // ever open this environment's secrets, and this browser is the
                // only place it exists in plaintext.
                const pdk = createProjectDataKey();
                const wrapped = await wrapProjectDataKey(muk, pdk, {
                  granteeType: "user",
                  granteeId: session.userId,
                });
                const environmentId = await createEnvironment({
                  sessionToken: session.sessionToken,
                  projectId,
                  name,
                  ...wrapped,
                });
                setName("");
                onCreated(environmentId);
                close();
              } catch (cause) {
                setError(messageFor(cause));
              } finally {
                setBusy(false);
              }
            })();
          }}
        >
          <Field label="Name" htmlFor={nameId} hint={SLUG_HINT}>
            <input
              id={nameId}
              value={name}
              onChange={(event) => setName(event.target.value)}
              className={`${inputControl} font-mono`}
              autoComplete="off"
              spellCheck={false}
              placeholder="production"
            />
          </Field>
          <p className="text-base text-text-muted">
            A new encryption key is generated in this browser and wrapped to your account. The
            server never sees it.
          </p>
          {error === null ? null : <FormError>{error}</FormError>}
          <button type="submit" className={primaryButton} disabled={!ready}>
            {busy ? "Creating" : "Create environment"}
          </button>
        </form>
      )}
    </Disclosure>
  );
}

/**
 * THE FORM THAT SEALS A SECRET.
 *
 * `pdk` is required rather than optional: without a project data key there is
 * nothing to seal under, and a form that accepted input it could not encrypt
 * would be a form that loses what somebody typed. The caller renders it only
 * when a key is in hand.
 *
 * The value is held in component state for exactly as long as the form is open,
 * and is cleared on success. It is never logged, never put in a query argument,
 * and never lifted into a parent.
 */
export function NewSecretForm({
  environmentId,
  pdk,
}: {
  environmentId: Id<"environments">;
  pdk: Uint8Array;
}) {
  const { session } = useAuth();
  const createSecret = useMutation(api.secrets.createSecret);
  const nameId = useId();
  const valueId = useId();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ready = name.trim().length > 0 && value.length > 0 && !busy;

  return (
    <Disclosure label="New secret">
      {(close) => (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (!ready || session === null) return;
            setBusy(true);
            setError(null);
            void (async () => {
              try {
                // Sealed BEFORE anything is sent. What crosses the wire is four
                // hex strings, bound to this environment id by the associated
                // data, under a key the server has never held.
                const sealed = await sealSecret(pdk, {
                  environmentId,
                  name: name.trim(),
                  value,
                });
                await createSecret({
                  sessionToken: session.sessionToken,
                  environmentId,
                  ...sealed,
                });
                setName("");
                // Cleared on success, so the plaintext does not sit in a
                // component that stays mounted behind a collapsed form.
                setValue("");
                close();
              } catch (cause) {
                setError(messageFor(cause));
              } finally {
                setBusy(false);
              }
            })();
          }}
        >
          <Field label="Name" htmlFor={nameId}>
            <input
              id={nameId}
              value={name}
              onChange={(event) => setName(event.target.value)}
              className={`${inputControl} font-mono`}
              autoComplete="off"
              spellCheck={false}
              placeholder="DATABASE_URL"
            />
          </Field>
          <Field label="Value" htmlFor={valueId}>
            {/* `type="password"` rather than a text field: this is a secret
                being typed on a screen somebody may be sharing. */}
            <input
              id={valueId}
              type="password"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              className={`${inputControl} font-mono`}
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
          <p className="text-base text-text-muted">
            The name and the value are encrypted in this browser before anything is sent.
          </p>
          {error === null ? null : <FormError>{error}</FormError>}
          <button type="submit" className={primaryButton} disabled={!ready}>
            {busy ? "Saving" : "Save secret"}
          </button>
        </form>
      )}
    </Disclosure>
  );
}
