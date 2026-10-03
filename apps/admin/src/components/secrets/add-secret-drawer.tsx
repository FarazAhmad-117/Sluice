import { useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { Callout } from "@/components/ui/feedback";
import { RadioCard, TextField } from "@/components/ui/field";
import { MaskedTextarea } from "@/components/ui/masked-textarea";
import { IconEye, IconEyeOff } from "@/components/ui/icons";
import { focusRing, inputControl } from "@/components/ui/styles";
import { listOf } from "@/lib/list-of";
import {
  MAX_NAME_BYTES,
  duplicateProblem,
  secretKeyProblem,
  secretValueProblem,
  unavailableEnvironments,
} from "@/lib/secrets/add-secret";
import type { ProjectDataKeyState } from "@/lib/secrets/environment-key";
import { describeWriteFailure } from "@/lib/secrets/write-errors";

/**
 * ADD A SECRET: TO ONE ENVIRONMENT, OR TO ALL OF THEM WITH OPTIONAL OVERRIDES.
 *
 * "All environments" seals the value once per environment under each
 * environment's own key, in one atomic write (`createSharedSecret`), so every
 * key must be open: if one is not, the drawer says which and will not save.
 * "Only <env>" seals one row for the current environment.
 *
 * The value is typed into a field masked by default, and no value is held
 * anywhere but this component, which unmounts when the drawer closes.
 *
 * A name is checked against the names this browser has opened in every
 * environment it writes to. The server cannot do that check: it never sees a
 * name.
 */

export interface DrawerEnvironment {
  readonly environmentId: string;
  readonly name: string;
}

export type AddSecretPlan =
  | {
      readonly scope: "all";
      readonly name: string;
      readonly value: string;
      /** Own values, by environment id. Absent means "uses the shared value". */
      readonly overrides: ReadonlyMap<string, string>;
    }
  | { readonly scope: "only"; readonly name: string; readonly value: string };


export function AddSecretDrawer({
  environments,
  current,
  keys,
  namesByEnvironment,
  onSave,
  onClose,
  initialName = "",
  initialScope,
}: {
  readonly environments: readonly DrawerEnvironment[];
  readonly current: DrawerEnvironment;
  /** A key to start with: "Add here" on a key another environment has. */
  readonly initialName?: string;
  /** Defaults to "all" when there is more than one environment. */
  readonly initialScope?: "all" | "only";
  readonly keys: ReadonlyMap<string, ProjectDataKeyState>;
  readonly namesByEnvironment: ReadonlyMap<string, ReadonlyMap<string, string>>;
  /** Seals and writes. Resolves to the new secret ids. */
  readonly onSave: (plan: AddSecretPlan) => Promise<{ readonly name: string; readonly secretIds: readonly string[] }>;
  readonly onClose: (saved?: { readonly name: string; readonly secretIds: readonly string[] }) => void;
}) {
  const formId = useId();
  const keyField = useRef<HTMLInputElement>(null);
  const valueField = useRef<HTMLTextAreaElement>(null);
  const [name, setName] = useState(initialName);
  const [value, setValue] = useState("");
  const [shown, setShown] = useState(false);
  const [scope, setScope] = useState<"all" | "only">(
    environments.length > 1 ? (initialScope ?? "all") : "only",
  );
  const [overrides, setOverrides] = useState<ReadonlyMap<string, string>>(new Map());
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const targets = scope === "all" ? environments : [current];
  const unavailable = unavailableEnvironments(targets, keys, namesByEnvironment);
  const keyProblem = secretKeyProblem(name);
  const duplicate = keyProblem === null ? duplicateProblem(name, targets, namesByEnvironment) : null;
  const allOverridden = scope === "all" && environments.every((environment) => overrides.has(environment.environmentId));
  // Shown as soon as a value is over, not only on save: nothing is sealed for
  // a value the server would refuse.
  const valueProblem = secretValueProblem(value);
  const overrideProblems = new Map<string, string>();
  if (scope === "all") {
    for (const [environmentId, own] of overrides) {
      const problem = secretValueProblem(own);
      if (problem !== null) overrideProblems.set(environmentId, problem);
    }
  }
  const others = environments.filter((environment) => environment.environmentId !== current.environmentId);
  const everyName = environments.map((environment) => environment.name);

  const save = async () => {
    setTouched(true);
    setFailure(null);
    if (keyProblem !== null || duplicate !== null) {
      keyField.current?.focus();
      return;
    }
    if (valueProblem !== null || overrideProblems.size > 0) {
      valueField.current?.focus();
      return;
    }
    if (unavailable.length > 0 || allOverridden) return;
    setBusy(true);
    try {
      const saved = await onSave(
        scope === "all" ? { scope, name, value, overrides } : { scope, name, value },
      );
      onClose(saved);
    } catch (cause) {
      setFailure(describeWriteFailure(cause).message);
      setBusy(false);
    }
  };

  return (
    <Drawer
      open
      onClose={() => {
        if (!busy) onClose();
      }}
      title={initialName === "" ? "Add a secret" : `Add ${initialName} to ${current.name}`}
      // With the key already given, the value is the next thing to type.
      initialFocus={initialName === "" ? keyField : valueField}
      footer={
        <>
          <span className="text-[13px] text-text-muted">Encrypted in this browser before it's saved</span>
          <div className="flex w-full gap-2.5 sm:w-auto">
            <Button variant="secondary" onClick={() => !busy && onClose()} className="grow sm:grow-0" aria-disabled={busy || undefined}>
              Cancel
            </Button>
            <Button
              type="submit"
              form={formId}
              loading={busy}
              loadingLabel="Encrypting and saving"
              aria-disabled={unavailable.length > 0 || undefined}
              className="grow sm:grow-0"
            >
              Save secret
            </Button>
          </div>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy) void save();
        }}
        className="flex flex-col gap-[22px]"
      >
        <TextField
          ref={keyField}
          label="Key"
          mono
          value={name}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          onChange={(event) => setName(event.target.value)}
          // A key over the length limit says so at once, like a value over its limit.
          error={
            touched || name.length > MAX_NAME_BYTES ? (keyProblem ?? duplicate ?? undefined) : undefined
          }
        />

        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <label htmlFor={`${formId}-value`} className="font-medium text-text-primary">
              Value
            </label>
            <button
              type="button"
              aria-pressed={shown}
              onClick={() => setShown((value) => !value)}
              className={`-my-2 inline-flex min-h-11 cursor-pointer items-center gap-1.5 rounded-input px-2 text-sm text-text-muted hover:text-text-primary ${focusRing}`}
            >
              {shown ? <IconEyeOff className="size-4" /> : <IconEye className="size-4" />}
              {shown ? "Hide values" : "Show values"}
            </button>
          </div>
          <MaskedTextarea
            shown={shown}
            ref={valueField}
            id={`${formId}-value`}
            rows={2}
            value={value}
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            onChange={(event) => setValue(event.target.value)}
            aria-invalid={valueProblem === null ? undefined : true}
            aria-describedby={valueProblem === null ? undefined : `${formId}-value-error`}
            className={`${inputControl} resize-y font-mono text-sm leading-normal ${
              valueProblem === null ? "border-hairline-strong" : "border-status-danger hover:border-status-danger"
            }`}
          />
          {valueProblem === null ? null : (
            <p id={`${formId}-value-error`} role="alert" className="m-0 text-sm text-status-danger">
              {valueProblem}
            </p>
          )}
        </div>

        {environments.length > 1 ? (
          <fieldset className="m-0 flex min-w-0 flex-col gap-2.5 border-0 p-0">
            <legend className="pb-2.5 font-medium text-text-primary">Where does it apply?</legend>
            <RadioCard
              name={`${formId}-scope`}
              label="All environments"
              description={`One shared value for ${listOf(everyName)}. Any of them can override it.`}
              checked={scope === "all"}
              onChange={() => setScope("all")}
            />
            <RadioCard
              name={`${formId}-scope`}
              label={`Only ${current.name}`}
              description={`${capitalise(listOf(others.map((environment) => environment.name)))} won't have it.`}
              checked={scope === "only"}
              onChange={() => setScope("only")}
            />
          </fieldset>
        ) : null}

        {unavailable.length > 0 ? (
          <Callout tone="warning" title={`Can't save to ${listOf(unavailable.map((row) => row.name))} right now`}>
            <ul className="m-0 flex list-none flex-col gap-1 p-0">
              {unavailable.map((row) => (
                <li key={row.name}>
                  <span className="text-text-primary">{row.name}:</span> {row.reason}
                </li>
              ))}
            </ul>
            {scope === "all" ? <p className="m-0 mt-2">You can still add it to {current.name} only.</p> : null}
          </Callout>
        ) : null}

        {scope === "all" && environments.length > 1 ? (
          <div className="flex flex-col">
            <span className="pb-2.5 font-medium text-text-primary">
              Different value somewhere? <span className="font-normal text-text-muted">Optional</span>
            </span>
            <ul className="m-0 list-none border-b border-hairline p-0">
              {environments.map((environment) => {
                const own = overrides.get(environment.environmentId);
                const switchId = `${formId}-own-${environment.environmentId}`;
                return (
                  <li key={environment.environmentId} className="flex flex-col gap-2.5 border-t border-hairline py-1.5">
                    <div className="flex min-h-11 items-center justify-between gap-3">
                      <div className="flex min-w-0 flex-col">
                        <span className="truncate text-text-primary">{environment.name}</span>
                        {own === undefined ? (
                          <span className="text-[13px] text-text-muted">Uses the shared value</span>
                        ) : null}
                      </div>
                      <label
                        htmlFor={switchId}
                        className={`flex min-h-11 shrink-0 cursor-pointer items-center gap-2 text-sm ${
                          own === undefined ? "text-text-muted" : "text-status-warning light:text-text-primary"
                        }`}
                      >
                        Own value
                        <input
                          id={switchId}
                          type="checkbox"
                          role="switch"
                          aria-label={`Own value for ${environment.name}`}
                          checked={own !== undefined}
                          onChange={(event) =>
                            setOverrides((currentOverrides) => {
                              const next = new Map(currentOverrides);
                              if (event.target.checked) next.set(environment.environmentId, "");
                              else next.delete(environment.environmentId);
                              return next;
                            })
                          }
                          // The input IS the visible switch (track drawn by the
                          // input, thumb by its ::before), so it is the click
                          // target itself, not a hidden box behind a picture.
                          className={`relative m-0 h-5 w-[34px] shrink-0 cursor-pointer appearance-none rounded-full bg-hairline-strong transition-colors before:absolute before:top-0.5 before:left-0.5 before:size-4 before:rounded-full before:bg-surface-base before:transition-[left] before:content-[''] checked:bg-status-warning checked:before:left-4 motion-reduce:before:transition-none ${focusRing}`}
                        />
                      </label>
                    </div>
                    {own === undefined ? null : (
                      <MaskedTextarea
            shown={shown}
                        aria-label={`${environment.name} value`}
                        rows={1}
                        value={own}
                        autoComplete="off"
                        spellCheck={false}
                        autoCapitalize="none"
                        onChange={(event) =>
                          setOverrides((currentOverrides) =>
                            new Map(currentOverrides).set(environment.environmentId, event.target.value),
                          )
                        }
                        aria-invalid={overrideProblems.has(environment.environmentId) || undefined}
                        aria-describedby={
                          overrideProblems.has(environment.environmentId) ? `${formId}-own-error-${environment.environmentId}` : undefined
                        }
                        className={`${inputControl} mb-1.5 resize-y font-mono text-sm leading-normal ${
                          overrideProblems.has(environment.environmentId)
                            ? "border-status-danger hover:border-status-danger"
                            : "border-status-warning/50 hover:border-status-warning"
                        }`}
                      />
                    )}
                    {overrideProblems.has(environment.environmentId) ? (
                      <p
                        id={`${formId}-own-error-${environment.environmentId}`}
                        role="alert"
                        className="m-0 mb-1.5 text-sm text-status-danger"
                      >
                        {overrideProblems.get(environment.environmentId)}
                      </p>
                    ) : null}
                  </li>
                );
              })}
            </ul>
            {touched && allOverridden ? (
              <p role="alert" className="m-0 pt-2 text-sm text-status-danger">
                At least one environment must use the shared value. Turn one off, or choose Only {current.name}.
              </p>
            ) : null}
          </div>
        ) : null}

        {failure === null ? null : (
          <Callout tone="danger" role="alert" title="The secret was not saved">
            {failure}
          </Callout>
        )}
      </form>
    </Drawer>
  );
}

function capitalise(text: string): string {
  return text.slice(0, 1).toUpperCase() + text.slice(1);
}
