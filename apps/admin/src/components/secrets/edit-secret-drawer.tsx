import { useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { Callout } from "@/components/ui/feedback";
import { RadioCard, TextField } from "@/components/ui/field";
import { MaskedTextarea } from "@/components/ui/masked-textarea";
import { IconEye, IconEyeOff } from "@/components/ui/icons";
import { focusRing, inputControl } from "@/components/ui/styles";
import { secretValueProblem } from "@/lib/secrets/add-secret";
import type { EditOutcome } from "@/lib/secrets/edit-secret";

/**
 * EDIT A VALUE: THE KEY IS FIXED, THE VALUE IS NEW.
 *
 * A key with more than one value (a shared value and an override somewhere)
 * asks which one; the choice starts on the value the current environment
 * uses. The new value is typed into a masked field and is never prefilled:
 * prefilling would mean decrypting the old value without anybody asking.
 *
 * The write is `lib/secrets/edit-secret.ts`, handed in as `onSave`. A stale
 * version or a re-keyed environment comes back with a Reload button, because
 * saving again would be refused the same way.
 */

export interface EditChoice {
  readonly id: string;
  readonly label: string;
  readonly description: string;
}


export function EditSecretDrawer({
  name,
  choices,
  initialChoice,
  onSave,
  onClose,
}: {
  readonly name: string;
  readonly choices: readonly EditChoice[];
  /** `null`: nothing preselected, the person must pick. */
  readonly initialChoice: string | null;
  readonly onSave: (choiceId: string, value: string) => Promise<EditOutcome>;
  readonly onClose: (saved?: { readonly label: string }) => void;
}) {
  const formId = useId();
  const valueField = useRef<HTMLTextAreaElement>(null);
  const [choice, setChoice] = useState<string | null>(initialChoice);
  const [mustChoose, setMustChoose] = useState(false);
  const firstChoice = useRef<HTMLDivElement>(null);
  const [value, setValue] = useState("");
  const [shown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Extract<EditOutcome, { ok: false }> | null>(null);
  const chosen = choices.find((option) => option.id === choice);
  // Checked before anything is sealed; the server applies the same limit.
  const valueProblem = secretValueProblem(value);

  const save = async () => {
    if (chosen === undefined) {
      setMustChoose(true);
      firstChoice.current?.querySelector("input")?.focus();
      return;
    }
    if (valueProblem !== null) {
      valueField.current?.focus();
      return;
    }
    setBusy(true);
    setFailure(null);
    const outcome = await onSave(chosen.id, value);
    if (outcome.ok) {
      onClose({ label: chosen.label });
      return;
    }
    setBusy(false);
    setFailure(outcome);
  };

  return (
    <Drawer
      open
      onClose={() => {
        if (!busy) onClose();
      }}
      title={`Edit ${name}`}
      initialFocus={valueField}
      footer={
        <>
          <span className="text-[13px] text-text-muted">Encrypted in this browser before it's saved</span>
          <div className="flex w-full gap-2.5 sm:w-auto">
            <Button
              variant="secondary"
              onClick={() => !busy && onClose()}
              className="grow sm:grow-0"
              aria-disabled={busy || undefined}
            >
              Cancel
            </Button>
            <Button type="submit" form={formId} loading={busy} loadingLabel="Encrypting and saving" className="grow sm:grow-0">
              Save new value
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
        <TextField label="Key" mono value={name} readOnly hint="A key cannot be renamed. Add a new one and delete this one instead." />

        {choices.length > 1 ? (
          <fieldset
            aria-describedby={mustChoose && chosen === undefined ? `${formId}-choice-error` : undefined}
            className="m-0 flex min-w-0 flex-col gap-2.5 border-0 p-0"
          >
            <legend className="pb-2.5 font-medium text-text-primary">Which value?</legend>
            <div ref={firstChoice} className="flex flex-col gap-2.5">
              {choices.map((option) => (
                <RadioCard
                  key={option.id}
                  name={`${formId}-choice`}
                  label={option.label}
                  description={option.description}
                  checked={choice === option.id}
                  onChange={() => {
                    setChoice(option.id);
                    setFailure(null);
                  }}
                />
              ))}
            </div>
            {mustChoose && chosen === undefined ? (
              <p id={`${formId}-choice-error`} role="alert" className="m-0 text-sm text-status-danger">
                Choose which value to change.
              </p>
            ) : null}
          </fieldset>
        ) : chosen === undefined ? null : (
          <p className="m-0 text-sm text-text-muted">{chosen.description}</p>
        )}

        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <label htmlFor={`${formId}-value`} className="font-medium text-text-primary">
              New value
            </label>
            <button
              type="button"
              aria-pressed={shown}
              onClick={() => setShown((open) => !open)}
              className={`-my-2 inline-flex min-h-11 cursor-pointer items-center gap-1.5 rounded-input px-2 text-sm text-text-muted hover:text-text-primary ${focusRing}`}
            >
              {shown ? <IconEyeOff className="size-4" /> : <IconEye className="size-4" />}
              {shown ? "Hide value" : "Show value"}
            </button>
          </div>
          <MaskedTextarea
            shown={shown}
            ref={valueField}
            id={`${formId}-value`}
            rows={3}
            value={value}
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            aria-describedby={`${formId}-value-hint${valueProblem === null ? "" : ` ${formId}-value-error`}`}
            aria-invalid={valueProblem === null ? undefined : true}
            onChange={(event) => setValue(event.target.value)}
            className={`${inputControl} resize-y font-mono text-sm leading-normal ${
              valueProblem === null ? "border-hairline-strong" : "border-status-danger hover:border-status-danger"
            }`}
          />
          <p id={`${formId}-value-hint`} className="m-0 text-sm text-text-muted">
            Saved as a new version. The current one is kept as an earlier version.
          </p>
          {valueProblem === null ? null : (
            <p id={`${formId}-value-error`} role="alert" className="m-0 text-sm text-status-danger">
              {valueProblem}
            </p>
          )}
        </div>

        {failure === null ? null : (
          <Callout
            tone={failure.reload ? "warning" : "danger"}
            role="alert"
            title="The value was not changed"
            action={
              failure.reload ? (
                <Button variant="secondary" onClick={() => window.location.reload()}>
                  Reload
                </Button>
              ) : undefined
            }
          >
            {failure.message}
          </Callout>
        )}
      </form>
    </Drawer>
  );
}
