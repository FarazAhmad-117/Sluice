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
import { createRevocationKeypair, wrapRevocationKey } from "@/lib/orgs/revocation-key";
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
 * EVERY FORM BODY IS ITS OWN COMPONENT, MOUNTED ONLY WHILE THE FORM IS OPEN,
 * and that is a decision about plaintext rather than about tidiness. If the
 * fields lived in the always-mounted wrapper, a half-typed secret value would
 * survive Cancel and sit in React state for the rest of the session, invisible
 * and unreachable. Closing the disclosure unmounts the body, and everything
 * typed into it goes with it.
 *
 *   organisation an Ed25519 revocation keypair is generated here, and its
 *                private half is wrapped under the master unlock key before
 *                anything is sent. `createOrg` writes the org, the ownership
 *                row and that first revocation grant in ONE transaction, so an
 *                org whose kill switch nobody can arm cannot exist.
 *
 * CREATING AN ORGANISATION USED TO BE ABSENT FROM THIS FILE, and the reason is
 * worth keeping. `orgs.createOrg` requires `wrappedRevocationKey`, and until
 * `revocationKeyAssociatedData` was added to `@sluice/crypto` the associated
 * data for that wrap was defined nowhere. Choosing a literal here would have
 * pinned bytes the backend and the SDK later had to match by coincidence, and
 * a mismatch is a revocation notice that cannot be signed, discovered during
 * the incident revocation exists for. The rule now lives in the package beside
 * its three siblings, which is the only reason the form below can exist. Do not
 * reintroduce a literal at this call site.
 */

/**
 * A form that is closed until it is needed, and gone when it is not.
 *
 * `children` is a function so that the body is CONSTRUCTED only while open. A
 * permanently open form in a nav pane is a permanently open form, and this one
 * sits under a list somebody is trying to read. The trigger is a real button,
 * so it is in the tab order and announces its state.
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

function OrgFields({
  onCreated,
  close,
}: {
  onCreated(orgId: Id<"orgs">): void;
  close(): void;
}) {
  const { session, muk } = useAuth();
  const createOrg = useMutation(api.orgs.createOrg);
  const nameId = useId();
  const slugId = useId();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ready = name.trim().length > 0 && isSlug(slug) && !busy && session !== null && muk !== null;

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready || session === null || muk === null) return;
        setBusy(true);
        setError(null);
        void (async () => {
          try {
            /**
             * MINTED HERE, AND MINTED AGAIN ON EVERY ATTEMPT.
             *
             * The seed exists in plaintext only inside this frame: it is never
             * lifted into React state, never logged, never sent. What crosses
             * the wire is a public key and two hex strings.
             *
             * Generating inside the handler rather than once per mount is
             * load-bearing rather than tidy. `createOrg` can refuse AFTER the
             * wrap has happened, and the refusal a person will actually hit is
             * the duplicate slug: two people creating `acme` at the same time
             * means one of them retries under another name. A form that reused
             * a keypair across attempts would be a form that could pair a wrap
             * with the wrong attempt's state. A fresh pair per submit cannot.
             */
            const keypair = createRevocationKeypair();
            const wrapped = await wrapRevocationKey(muk, keypair.privateKey, {
              granteeId: session.userId,
            });
            const orgId = await createOrg({
              sessionToken: session.sessionToken,
              name: name.trim(),
              slug,
              revocationPublicKey: keypair.revocationPublicKey,
              ...wrapped,
            });
            onCreated(orgId);
            close();
          } catch (cause) {
            setError(messageFor(cause));
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
          className={inputControl}
          autoComplete="off"
        />
      </Field>
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
      <p className="text-base text-text-muted">
        A revocation signing key is generated in this browser and wrapped to your account. It is
        the only thing that can kill a stolen token, and the server never sees it.
      </p>
      {error === null ? null : <FormError>{error}</FormError>}
      <button type="submit" className={primaryButton} disabled={!ready}>
        {busy ? "Creating" : "Create organisation"}
      </button>
    </form>
  );
}

/**
 * THE FORM THAT MINTS AN ORGANISATION REVOCATION KEY.
 *
 * It needs the master unlock key, so it says so while the vault is locked
 * rather than failing on submit. An org whose revocation key was wrapped under
 * nothing is an org whose kill switch cannot be armed, and that is not a state
 * this offers.
 */
export function NewOrgForm({ onCreated }: { onCreated(orgId: Id<"orgs">): void }) {
  const { session, muk } = useAuth();

  if (session === null || muk === null) {
    return (
      <p className="px-2.5 py-1.5 text-base text-text-muted">
        Unlock your vault to create an organisation. Creating one mints its revocation signing key
        in this browser.
      </p>
    );
  }

  return (
    <Disclosure label="New organisation">
      {(close) => <OrgFields onCreated={onCreated} close={close} />}
    </Disclosure>
  );
}

function ProjectFields({
  orgId,
  onCreated,
  close,
}: {
  orgId: Id<"orgs">;
  onCreated(projectId: Id<"projects">): void;
  close(): void;
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
            onCreated(projectId);
            close();
          })
          .catch((cause: unknown) => {
            setError(messageFor(cause));
            setBusy(false);
          });
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
      {/* Its own field, always visible, never derived from the name. The server
          REJECTS a bad slug rather than rewriting it, precisely so that two
          names cannot collapse onto one identifier. */}
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
  );
}

export function NewProjectForm({
  orgId,
  onCreated,
}: {
  orgId: Id<"orgs">;
  onCreated(projectId: Id<"projects">): void;
}) {
  return (
    <Disclosure label="New project">
      {(close) => <ProjectFields orgId={orgId} onCreated={onCreated} close={close} />}
    </Disclosure>
  );
}

function EnvironmentFields({
  projectId,
  onCreated,
  close,
}: {
  projectId: Id<"projects">;
  onCreated(environmentId: Id<"environments">): void;
  close(): void;
}) {
  const { session, muk } = useAuth();
  const createEnvironment = useMutation(api.environments.createEnvironment);
  const nameId = useId();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // `name` is the last segment of the address the SDK resolves a config by, so
  // it obeys the slug rule rather than the display-name rule.
  const ready = isSlug(name) && !busy && session !== null && muk !== null;

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready || session === null || muk === null) return;
        setBusy(true);
        setError(null);
        void (async () => {
          try {
            // MINTED HERE. This 32 byte key is the only thing that will ever
            // open this environment's secrets, and this browser is the only
            // place it exists in plaintext.
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
            onCreated(environmentId);
            close();
          } catch (cause) {
            setError(messageFor(cause));
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
        A new encryption key is generated in this browser and wrapped to your account. The server
        never sees it.
      </p>
      {error === null ? null : <FormError>{error}</FormError>}
      <button type="submit" className={primaryButton} disabled={!ready}>
        {busy ? "Creating" : "Create environment"}
      </button>
    </form>
  );
}

/**
 * THE FORM THAT MINTS A PROJECT DATA KEY.
 *
 * It needs the master unlock key, so it says so while the vault is locked
 * rather than failing on submit. Creating an environment whose key was wrapped
 * under nothing is not a state this offers.
 */
export function NewEnvironmentForm({
  projectId,
  onCreated,
}: {
  projectId: Id<"projects">;
  onCreated(environmentId: Id<"environments">): void;
}) {
  const { session, muk } = useAuth();

  if (session === null || muk === null) {
    return (
      <p className="px-2.5 py-1.5 text-base text-text-muted">
        Unlock your vault to add an environment. Creating one mints its encryption key in this
        browser.
      </p>
    );
  }

  return (
    <Disclosure label="New environment">
      {(close) => (
        <EnvironmentFields projectId={projectId} onCreated={onCreated} close={close} />
      )}
    </Disclosure>
  );
}

function SecretFields({
  environmentId,
  pdk,
  close,
}: {
  environmentId: Id<"environments">;
  pdk: Uint8Array;
  close(): void;
}) {
  const { session } = useAuth();
  const createSecret = useMutation(api.secrets.createSecret);
  const nameId = useId();
  const valueId = useId();
  const [name, setName] = useState("");
  /**
   * PLAINTEXT, HELD FOR AS LONG AS THIS COMPONENT IS MOUNTED AND NOT ONE RENDER
   * LONGER. Closing or cancelling the form unmounts it. Nothing lifts it into a
   * parent, writes it to storage, puts it in a query argument or logs it.
   */
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ready = name.trim().length > 0 && value.length > 0 && !busy;

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready || session === null) return;
        setBusy(true);
        setError(null);
        void (async () => {
          try {
            // Sealed BEFORE anything is sent. What crosses the wire is four hex
            // strings, bound to this environment id by the associated data,
            // under a key the server has never held.
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
            close();
          } catch (cause) {
            setError(messageFor(cause));
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
        {/* `type="password"` rather than a text field: this is a secret being
            typed on a screen somebody may be sharing. */}
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
  );
}

/**
 * THE FORM THAT SEALS A SECRET.
 *
 * `pdk` is required rather than optional: without a project data key there is
 * nothing to seal under, and a form that accepted input it could not encrypt
 * would be a form that loses what somebody typed. The caller renders it only
 * when a key is in hand.
 */
export function NewSecretForm({
  environmentId,
  pdk,
}: {
  environmentId: Id<"environments">;
  pdk: Uint8Array;
}) {
  return (
    <Disclosure label="New secret">
      {(close) => <SecretFields environmentId={environmentId} pdk={pdk} close={close} />}
    </Disclosure>
  );
}
