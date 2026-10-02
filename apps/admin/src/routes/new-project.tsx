import { useId, useRef, useState } from "react";
import type { DragEvent, ReactNode } from "react";
import { useMutation } from "convex/react";
import { useNavigate, useSearchParams } from "react-router";
import { api } from "@convex/_generated/api";
import type { Id } from "@convex/_generated/dataModel";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/feedback";
import { Checkbox, RadioCard, TextField } from "@/components/ui/field";
import { IconUpload } from "@/components/ui/icons";
import { focusRing } from "@/components/ui/styles";
import { useAuth } from "@/lib/auth/auth-context";
import { parseDotenv } from "@/lib/dotenv";
import type { DotenvResult } from "@/lib/dotenv";
import { SLUG_HINT } from "@/lib/naming";
import { useCurrentOrg } from "@/lib/orgs/use-current-org";
import {
  environmentNames,
  projectNameProblem,
  projectSlugProblem,
  sealProjectEnvironments,
  slugFromName,
} from "@/lib/projects/create-project";
import type { OptionalEnvironment } from "@/lib/projects/create-project";
import { newSecretSlot, sealSecret } from "@/lib/secrets/seal";
import { describeWriteFailure } from "@/lib/secrets/write-errors";

/**
 * CREATE A PROJECT: A NAME, ITS ENVIRONMENTS, AND OPTIONALLY A .ENV.
 *
 * Every environment's key is minted and wrapped in this browser and the
 * project and its environments are created in ONE mutation, so there is no
 * half-made project to clean up if that call is refused. An import runs after
 * it, one sealed secret at a time, into development only; if it stops part
 * way, the project exists and the page says how far it got.
 *
 * The .env is read and parsed here and never leaves the tab as plaintext.
 * Nothing on this page shows a value: the import lists names only.
 */

/** A .env bigger than this is not a .env. */
const MAX_IMPORT_BYTES = 256 * 1024;

const ENVIRONMENT_DESCRIPTION: Record<OptionalEnvironment, string> = {
  production: "What your live servers and deploys use.",
  staging: "For testing a release before production.",
};

export interface ProjectPlan {
  readonly name: string;
  readonly slug: string;
  readonly extra: readonly OptionalEnvironment[];
  /** The parsed .env to import into development, or `null` to start empty. */
  readonly entries: DotenvResult["entries"] | null;
}

export type CreateOutcome =
  | { readonly ok: true; readonly slug: string }
  /** Nothing was created. */
  | { readonly ok: false; readonly created: false; readonly message: string }
  /** The project exists; the import stopped after `imported` secrets. */
  | {
      readonly ok: false;
      readonly created: true;
      readonly slug: string;
      readonly imported: number;
      readonly message: string;
    };

export default function NewProjectRoute() {
  const { session, muk } = useAuth();
  const { org } = useCurrentOrg();
  const navigate = useNavigate();
  const createProject = useMutation(api.projects.createProjectWithEnvironments);
  const createSecret = useMutation(api.secrets.createSecret);

  const create = async (
    plan: ProjectPlan,
    onProgress: (done: number, total: number) => void,
  ): Promise<CreateOutcome> => {
    if (session === null || muk === null || org === null) {
      return { ok: false, created: false, message: "Your session is not ready. Reload the page." };
    }
    const sessionToken = session.sessionToken;
    let projectEnvironments: { environmentIds: Id<"environments">[] };
    let keys: Awaited<ReturnType<typeof sealProjectEnvironments>>["keys"];
    try {
      // Fresh uids and keys per attempt: a refused attempt's wraps are never reused.
      const sealed = await sealProjectEnvironments(muk, session.userUid, environmentNames(plan.extra));
      keys = sealed.keys;
      projectEnvironments = await createProject({
        sessionToken,
        orgId: org.orgId,
        name: plan.name,
        slug: plan.slug,
        environments: sealed.payload,
      });
    } catch (cause) {
      return { ok: false, created: false, message: describeWriteFailure(cause).message };
    }

    const entries = plan.entries ?? [];
    // `development` is always first in `environmentNames`, and the server
    // returns ids in the order it was given the environments.
    const developmentKey = keys[0];
    const developmentId = projectEnvironments.environmentIds[0];
    if (entries.length > 0 && (developmentKey === undefined || developmentId === undefined)) {
      return {
        ok: false,
        created: true,
        slug: plan.slug,
        imported: 0,
        message: "The development environment was not returned, so nothing was imported.",
      };
    }
    for (const [index, entry] of entries.entries()) {
      onProgress(index, entries.length);
      try {
        const slot = newSecretSlot();
        const sealedSecret = await sealSecret(developmentKey!, { ...slot, name: entry.name, value: entry.value });
        await createSecret({
          sessionToken,
          environmentId: developmentId!,
          secretUid: slot.secretUid,
          version: slot.version,
          pdkVersion: developmentKey!.pdkVersion,
          ...sealedSecret,
        });
      } catch (cause) {
        return {
          ok: false,
          created: true,
          slug: plan.slug,
          imported: index,
          message: `${entry.name} could not be imported: ${describeWriteFailure(cause).message}`,
        };
      }
    }
    return { ok: true, slug: plan.slug };
  };

  return (
    <NewProjectView
      onCreate={create}
      onDone={(slug) => void navigate(`/projects/${slug}/secrets?env=development`)}
      onCancel={() => void navigate("/projects")}
    />
  );
}

/** The form, with the work handed in, so it renders without a backend. */
export function NewProjectView({
  onCreate,
  onDone,
  onCancel,
}: {
  readonly onCreate: (
    plan: ProjectPlan,
    onProgress: (done: number, total: number) => void,
  ) => Promise<CreateOutcome>;
  readonly onDone: (slug: string) => void;
  readonly onCancel: () => void;
}) {
  const [params] = useSearchParams();
  const [name, setName] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [typedSlug, setTypedSlug] = useState("");
  const [extra, setExtra] = useState<OptionalEnvironment[]>(["production"]);
  const [start, setStart] = useState<"empty" | "import">(
    params.get("start") === "import" ? "import" : "empty",
  );
  const [file, setFile] = useState<{ name: string; result: DotenvResult } | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [failure, setFailure] = useState<Extract<CreateOutcome, { ok: false }> | null>(null);
  const nameField = useRef<HTMLInputElement>(null);
  const slugField = useRef<HTMLInputElement>(null);

  const proposed = slugFromName(name);
  const slug = slugEdited ? typedSlug : proposed;
  const nameProblem = projectNameProblem(name);
  // Before anything is typed, an empty slug is not yet a problem worth shouting.
  const slugProblem = name.trim() === "" && !slugEdited ? null : projectSlugProblem(slug, !slugEdited);
  const importMissing = start === "import" && (file === null || file.result.entries.length === 0);

  const submit = async () => {
    // Once the project exists, submitting again would create a second one.
    if (failure?.created === true) {
      onDone(failure.slug);
      return;
    }
    setTouched(true);
    setFailure(null);
    if (nameProblem !== null) {
      nameField.current?.focus();
      return;
    }
    if (projectSlugProblem(slug, !slugEdited) !== null) {
      (slugEdited ? slugField : nameField).current?.focus();
      return;
    }
    if (importMissing) return;
    setBusy(true);
    setProgress("Creating the project…");
    const outcome = await onCreate(
      { name: name.trim(), slug, extra, entries: start === "import" ? (file?.result.entries ?? []) : null },
      (done, total) => setProgress(`Importing ${done + 1} of ${total}…`),
    );
    if (outcome.ok) {
      onDone(outcome.slug);
      return;
    }
    setBusy(false);
    setProgress(null);
    setFailure(outcome);
  };

  const readFile = async (picked: File | undefined) => {
    setFileError(null);
    if (picked === undefined) return;
    if (picked.size > MAX_IMPORT_BYTES) {
      setFile(null);
      setFileError("That file is larger than 256 KB, which is more than a .env holds.");
      return;
    }
    try {
      setFile({ name: picked.name, result: parseDotenv(await picked.text()) });
    } catch {
      setFile(null);
      setFileError("That file could not be read as text.");
    }
  };

  return (
    <div className="flex justify-center py-8 sm:py-10">
      <form
        noValidate
        aria-busy={busy}
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy) void submit();
        }}
        className="flex w-full max-w-[600px] flex-col gap-7"
      >
        <div className="flex flex-col gap-2">
          <h1 className="m-0 text-[28px] font-semibold tracking-[-0.02em] text-text-primary">
            Create a project
          </h1>
          <p className="m-0 text-sm text-text-muted">
            A project holds the secrets for one app or service, split into environments.
          </p>
        </div>

        <div className="flex flex-col gap-4">
          <TextField
            ref={nameField}
            label="Project name"
            value={name}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setName(event.target.value)}
            error={touched ? (nameProblem ?? (slugEdited ? undefined : (slugProblem ?? undefined))) : undefined}
            hint={
              slugEdited ? undefined : (
                <span className="flex flex-wrap items-baseline gap-x-1.5">
                  <span>
                    You'll use it in commands:{" "}
                    <code className="font-mono text-text-primary [overflow-wrap:anywhere]">
                      sluice run --project {proposed === "" ? "<slug>" : proposed}
                    </code>
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setTypedSlug(proposed);
                      setSlugEdited(true);
                      requestAnimationFrame(() => slugField.current?.focus());
                    }}
                    className={`-my-2 inline-flex min-h-11 cursor-pointer items-center rounded-input px-1 font-medium text-brand hover:text-brand-hover sm:min-h-0 sm:py-0 ${focusRing}`}
                  >
                    Change
                  </button>
                </span>
              )
            }
          />
          {slugEdited ? (
            <div className="flex flex-col gap-2">
              <TextField
                ref={slugField}
                label="Slug"
                mono
                value={typedSlug}
                autoComplete="off"
                spellCheck={false}
                autoCapitalize="none"
                onChange={(event) => setTypedSlug(event.target.value)}
                hint={
                  <>
                    {SLUG_HINT} Used in commands:{" "}
                    <code className="font-mono text-text-primary [overflow-wrap:anywhere]">
                      sluice run --project {typedSlug === "" ? "<slug>" : typedSlug}
                    </code>
                  </>
                }
                error={slugProblem ?? undefined}
              />
              <button
                type="button"
                onClick={() => {
                  setSlugEdited(false);
                  requestAnimationFrame(() => nameField.current?.focus());
                }}
                className={`inline-flex min-h-11 cursor-pointer items-center self-start rounded-input px-1 text-sm font-medium text-brand hover:text-brand-hover ${focusRing}`}
              >
                Use the slug from the name
              </button>
            </div>
          ) : null}
        </div>

        <fieldset className="m-0 flex min-w-0 flex-col gap-2.5 border-0 p-0">
          <legend className="pb-2.5 font-medium text-text-primary">Environments</legend>
          <div className="overflow-hidden rounded-card border border-hairline">
            <Checkbox
              label="development"
              description="Your local work. Every project starts with it."
              checked
              disabled
              className="bg-surface-panel"
              aside={
                <span className="flex h-6 shrink-0 items-center rounded-full bg-surface-card px-2.5 text-xs text-text-muted">
                  Always created
                </span>
              }
            />
            {(["production", "staging"] as const).map((environment) => (
              <Checkbox
                key={environment}
                label={environment}
                description={ENVIRONMENT_DESCRIPTION[environment]}
                checked={extra.includes(environment)}
                onChange={(event) =>
                  setExtra((current) =>
                    event.target.checked
                      ? [...current, environment]
                      : current.filter((value) => value !== environment),
                  )
                }
                className="border-t border-hairline"
              />
            ))}
          </div>
        </fieldset>

        <fieldset className="m-0 flex min-w-0 flex-col gap-2.5 border-0 p-0">
          <legend className="pb-2.5 font-medium text-text-primary">Start with</legend>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <RadioCard
              name="start"
              label="No secrets yet"
              description="Add them one by one."
              checked={start === "empty"}
              onChange={() => setStart("empty")}
            />
            <RadioCard
              name="start"
              label="Import a .env file"
              description="Imported into development only."
              checked={start === "import"}
              onChange={() => setStart("import")}
            />
          </div>
          {start === "import" ? (
            <ImportZone
              file={file}
              fileError={fileError}
              missing={touched && importMissing && fileError === null}
              onFile={(picked) => void readFile(picked)}
              onClear={() => {
                setFile(null);
                setFileError(null);
              }}
            />
          ) : null}
        </fieldset>

        {failure === null ? null : failure.created ? (
          <Callout
            tone="warning"
            role="alert"
            title={`The project was created. ${failure.imported} ${failure.imported === 1 ? "secret was" : "secrets were"} imported before it stopped.`}
          >
            {failure.message}
          </Callout>
        ) : (
          <Callout tone="danger" role="alert" title="The project was not created">
            {failure.message}
          </Callout>
        )}

        <div className="flex flex-col-reverse gap-4 border-t border-hairline pt-5 sm:flex-row sm:items-center sm:justify-between">
          <span className="text-[13px] text-text-muted">Encrypted in this browser before anything is saved.</span>
          <div className="flex flex-col-reverse gap-3 sm:flex-row">
            <Button variant="ghost" onClick={onCancel} className="w-full sm:w-auto">
              Cancel
            </Button>
            <Button
              type="submit"
              size="lg"
              loading={busy}
              loadingLabel={progress ?? "Working…"}
              className="w-full sm:w-auto"
            >
              {busy && progress !== null
                ? progress
                : failure?.created === true
                  ? "Open the project"
                  : "Create project"}
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
}

function ImportZone({
  file,
  fileError,
  missing,
  onFile,
  onClear,
}: {
  readonly file: { name: string; result: DotenvResult } | null;
  readonly fileError: string | null;
  readonly missing: boolean;
  readonly onFile: (file: File | undefined) => void;
  readonly onClear: () => void;
}) {
  const inputId = useId();
  const [over, setOver] = useState(false);

  const onDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setOver(false);
    onFile(event.dataTransfer.files[0]);
  };

  if (file !== null) {
    const { entries, errors } = file.result;
    return (
      <div className="flex flex-col gap-3 rounded-card border border-hairline-strong p-4" aria-live="polite">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="font-medium text-text-primary">
              {entries.length} {entries.length === 1 ? "secret" : "secrets"} found
            </span>
            <span className="truncate font-mono text-[13px] text-text-muted">{file.name}</span>
          </div>
          <Button variant="secondary" onClick={onClear}>
            Choose another
          </Button>
        </div>
        {entries.length > 0 ? (
          <ul className="m-0 flex max-h-40 list-none flex-wrap gap-1.5 overflow-y-auto p-0">
            {entries.map((entry) => (
              <li key={entry.name} className="rounded-input bg-surface-card px-2 py-1 font-mono text-xs text-text-primary">
                {entry.name}
              </li>
            ))}
          </ul>
        ) : (
          <p role="alert" className="m-0 text-sm text-status-danger">
            No secrets in that file. Choose another, or start with no secrets.
          </p>
        )}
        {errors.length > 0 ? (
          <div className="flex flex-col gap-1.5 border-t border-hairline pt-3">
            <span className="text-sm font-medium text-text-primary">
              {errors.length} {errors.length === 1 ? "line was" : "lines were"} skipped or replaced
            </span>
            <ul className="m-0 flex max-h-32 list-none flex-col gap-1 overflow-y-auto p-0 text-[13px] text-text-muted">
              {errors.map((error) => (
                <li key={`${error.line}-${error.message}`}>
                  <span className="font-mono text-text-primary">Line {error.line}</span> {error.message}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <label
        htmlFor={inputId}
        onDragOver={(event) => {
          event.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={onDrop}
        className={`flex min-h-[76px] cursor-pointer items-center justify-center gap-2.5 rounded-card border border-dashed px-4 text-center text-sm text-text-muted transition-colors focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-brand hover:border-brand/60 ${
          over ? "border-brand bg-brand-subtle" : missing ? "border-status-danger" : "border-hairline-strong"
        }`}
      >
        <IconUpload className="size-[18px] shrink-0" />
        <span>
          Drop .env here or <span className="font-medium text-brand">browse</span>
        </span>
        <input
          id={inputId}
          type="file"
          className="sr-only"
          onChange={(event) => {
            onFile(event.target.files?.[0]);
            event.target.value = "";
          }}
        />
      </label>
      <Problem>{fileError ?? (missing ? "Choose a .env file to import, or start with no secrets." : null)}</Problem>
    </div>
  );
}

function Problem({ children }: { readonly children: ReactNode }) {
  if (children === null || children === undefined) return null;
  return (
    <p role="alert" className="m-0 text-sm text-status-danger">
      {children}
    </p>
  );
}
