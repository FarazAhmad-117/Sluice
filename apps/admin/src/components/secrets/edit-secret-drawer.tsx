import { useId, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { Callout } from "@/components/ui/feedback";
import { RadioCard, TextField } from "@/components/ui/field";
import { IconEye, IconEyeOff } from "@/components/ui/icons";
import { focusRing, inputControl } from "@/components/ui/styles";
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

/** Masks a textarea's characters where the browser supports it. */
const MASKED = "[-webkit-text-security:disc]";

export function EditSecretDrawer({
  name,
  choices,
  initialChoice,
  onSave,
  onClose,
}: {
  readonly name: string;
  readonly choices: readonly EditChoice[];
  readonly initialChoice: string;
  readonly onSave: (choiceId: string, value: string) => Promise<EditOutcome>;
  readonly onClose: (saved?: { readonly label: string }) => void;
}) {
  const formId = useId();
  const valueField = useRef<HTMLTextAreaElement>(null);
  const [choice, setChoice] = useState(initialChoice);
  const [value, setValue] = useState("");
  const [shown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Extract<EditOutcome, { ok: false }> | null>(null);
  const chosen = choices.find((option) => option.id === choice) ?? choices[0];

  const save = async () => {
    if (chosen === undefined) return;
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
          <fieldset className="m-0 flex min-w-0 flex-col gap-2.5 border-0 p-0">
            <legend className="pb-2.5 font-medium text-text-primary">Which value?</legend>
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
          <textarea
            ref={valueField}
            id={`${formId}-value`}
            rows={3}
            value={value}
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            aria-describedby={`${formId}-value-hint`}
            onChange={(event) => setValue(event.target.value)}
            className={`${inputControl} resize-y border-hairline-strong font-mono text-sm leading-normal ${shown ? "" : MASKED}`}
          />
          <p id={`${formId}-value-hint`} className="m-0 text-sm text-text-muted">
            Saved as a new version. The current one is kept as an earlier version.
          </p>
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
