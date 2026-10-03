import { useRef, useState } from "react";
import type { FormEvent } from "react";
import { useMutation } from "convex/react";
import { ConvexError } from "convex/values";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/feedback";
import { Drawer } from "@/components/ui/drawer";
import { TextField } from "@/components/ui/field";
import { useAuth } from "@/lib/auth/auth-context";
import { MAX_SLUG_LENGTH, isSlug } from "@/lib/naming";
import { sealProjectEnvironments } from "@/lib/projects/create-project";

/**
 * ADD AN ENVIRONMENT TO A PROJECT.
 *
 * A new environment gets its own project data key, minted and wrapped to the
 * person in this browser (`sealProjectEnvironments`, the same path project
 * creation uses), so its secrets are readable only by people holding a grant.
 * The name is the last segment of the address a workload resolves, so it obeys
 * the slug rule, and the server checks it again.
 */

/** Matches `MAX_ENVIRONMENTS_PER_PROJECT` in `convex/lib/environments.ts`. */
export const MAX_ENVIRONMENTS = 20;

const SUGGESTIONS = ["staging", "production", "preview", "test"];

function nameProblem(name: string, taken: readonly string[]): string | null {
  if (name === "") return "Give it a name.";
  if (name.length > MAX_SLUG_LENGTH || !isSlug(name)) {
    return "Use lowercase letters and digits, with single hyphens between them.";
  }
  if (taken.includes(name)) return `This project already has ${name}.`;
  return null;
}

export function AddEnvironmentDrawer({
  open,
  onClose,
  projectId,
  existing,
  onCreated,
}: {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly projectId: string;
  readonly existing: readonly string[];
  readonly onCreated: (name: string) => void;
}) {
  const { session, muk } = useAuth();
  const create = useMutation(api.environments.createEnvironment);
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const full = existing.length >= MAX_ENVIRONMENTS;
  const problem = nameProblem(name, existing);
  const suggestion = SUGGESTIONS.find((candidate) => !existing.includes(candidate));

  const close = () => {
    if (busy) return;
    setName("");
    setTouched(false);
    setError(null);
    onClose();
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (problem !== null || full || busy) return;
    if (session === null || muk === null) {
      setError("Unlock with your password to add an environment.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const { payload } = await sealProjectEnvironments(muk, session.userUid, [name]);
      const sealed = payload[0];
      if (sealed === undefined) throw new Error("Nothing was sealed.");
      await create({ sessionToken: session.sessionToken, projectId: projectId as Id<"projects">, ...sealed });
      const created = name;
      setBusy(false);
      setName("");
      setTouched(false);
      onCreated(created);
    } catch (caught) {
      setBusy(false);
      setError(
        caught instanceof ConvexError && typeof caught.data === "string"
          ? caught.data
          : "The environment could not be added. Try again.",
      );
    }
  };

  return (
    <Drawer
      open={open}
      onClose={close}
      title="Add an environment"
      initialFocus={input}
      footer={
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" form="add-environment" loading={busy} loadingLabel="Adding…" disabled={full}>
            Add environment
          </Button>
        </div>
      }
    >
      <form id="add-environment" onSubmit={(event) => void submit(event)} className="flex flex-col gap-5" noValidate>
        <p className="m-0 text-sm text-text-muted">
          It starts empty, with its own key. Add secrets to it, or share existing ones with it.
        </p>
        {full ? (
          <Callout tone="warning" title={`This project has ${MAX_ENVIRONMENTS} environments`}>
            That is the most a project can have.
          </Callout>
        ) : null}
        <TextField
          ref={input}
          label="Name"
          mono
          value={name}
          maxLength={MAX_SLUG_LENGTH}
          autoComplete="off"
          spellCheck={false}
          placeholder={suggestion ?? "staging"}
          hint="Lowercase letters, digits and hyphens. Your app's token names it, so pick something you can type."
          error={touched ? problem : null}
          onChange={(event) => setName(event.target.value.toLowerCase())}
          onBlur={() => setTouched(true)}
        />
        {error === null ? null : (
          <Callout tone="danger" role="alert" title="Not added">
            {error}
          </Callout>
        )}
      </form>
    </Drawer>
  );
}
