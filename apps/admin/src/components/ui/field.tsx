import { useId } from "react";
import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from "react";
import { focusRing, inputControl } from "./styles";

/**
 * FORM FIELDS: A REAL LABEL ABOVE, HINT AND ERROR BELOW, ALL WIRED.
 *
 * Every field renders a `<label>` tied to its control, and its hint and error
 * are joined to the control with `aria-describedby`, so a screen reader reads
 * them when the control takes focus rather than only when somebody happens to
 * reach them. An error also sets `aria-invalid` and is announced as it
 * appears (`role="alert"`).
 *
 * Errors here must never contain a secret value. The fields cannot enforce
 * that; the messages handed to them are written not to.
 */

interface FieldChrome {
  readonly label: ReactNode;
  readonly hint?: ReactNode;
  readonly error?: ReactNode;
  /** Monospace text, for keys and values. */
  readonly mono?: boolean;
}

/**
 * Whether a hint or error renders anything. `{cond && "text"}` hands in
 * `false` (or `""`), and an empty node named by `aria-describedby` would be
 * an empty description, or for an error an empty alert.
 */
function present(node: ReactNode): boolean {
  return node !== undefined && node !== null && node !== false && node !== true && node !== "";
}

function useDescribedBy(hint: ReactNode, error: ReactNode, own?: string) {
  const id = useId();
  const hintId = present(hint) ? `${id}-hint` : undefined;
  const errorId = present(error) ? `${id}-error` : undefined;
  const describedBy = [own, hintId, errorId].filter(Boolean).join(" ") || undefined;
  return { id, hintId, errorId, describedBy };
}

function Below({
  hintId,
  hint,
  errorId,
  error,
}: {
  hintId: string | undefined;
  hint: ReactNode;
  errorId: string | undefined;
  error: ReactNode;
}) {
  return (
    <>
      {hintId === undefined ? null : (
        <p id={hintId} className="m-0 text-sm text-text-muted">
          {hint}
        </p>
      )}
      {errorId === undefined ? null : (
        <p id={errorId} role="alert" className="m-0 text-sm text-status-danger">
          {error}
        </p>
      )}
    </>
  );
}

const controlClass = (mono: boolean | undefined, invalid: boolean, extra = "") =>
  `${inputControl} border-hairline-strong ${mono === true ? "font-mono text-sm" : ""} ${
    invalid ? "border-status-danger hover:border-status-danger" : ""
  } ${extra}`;

export function TextField({
  label,
  hint,
  error,
  mono,
  id: ownId,
  className = "",
  "aria-describedby": ownDescribedBy,
  ...input
}: FieldChrome & Omit<InputHTMLAttributes<HTMLInputElement>, "children">) {
  const { id, hintId, errorId, describedBy } = useDescribedBy(hint, error, ownDescribedBy);
  const inputId = ownId ?? `${id}-input`;
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={inputId} className="font-medium text-text-primary">
        {label}
      </label>
      <input
        {...input}
        id={inputId}
        aria-describedby={describedBy}
        aria-invalid={errorId === undefined ? undefined : true}
        className={controlClass(mono, errorId !== undefined, className)}
      />
      <Below hintId={hintId} hint={hint} errorId={errorId} error={error} />
    </div>
  );
}

export function TextArea({
  label,
  hint,
  error,
  mono,
  id: ownId,
  className = "",
  rows = 3,
  "aria-describedby": ownDescribedBy,
  ...textarea
}: FieldChrome & Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "children">) {
  const { id, hintId, errorId, describedBy } = useDescribedBy(hint, error, ownDescribedBy);
  const inputId = ownId ?? `${id}-input`;
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={inputId} className="font-medium text-text-primary">
        {label}
      </label>
      <textarea
        {...textarea}
        id={inputId}
        rows={rows}
        aria-describedby={describedBy}
        aria-invalid={errorId === undefined ? undefined : true}
        className={controlClass(mono, errorId !== undefined, `resize-y leading-normal ${className}`)}
      />
      <Below hintId={hintId} hint={hint} errorId={errorId} error={error} />
    </div>
  );
}

/** The native control, sized and tinted. Native, so keyboard and screen readers just work. */
const nativeBox = `size-[18px] shrink-0 cursor-pointer accent-brand disabled:cursor-not-allowed ${focusRing}`;

/**
 * A checkbox row: the whole row is the label, so the touch target is the row
 * (at least 44px tall), not the 18px box. `aside` sits at the far end, for a
 * badge like "Always created".
 */
export function Checkbox({
  label,
  description,
  aside,
  className = "",
  ...input
}: {
  readonly label: ReactNode;
  readonly description?: ReactNode;
  readonly aside?: ReactNode;
} & Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "children">) {
  return (
    <label
      className={`flex min-h-11 items-center gap-3.5 p-4 ${
        input.disabled === true ? "cursor-default" : "cursor-pointer"
      } ${className}`}
    >
      <input {...input} type="checkbox" className={nativeBox} />
      <span className="flex grow flex-col gap-0.5">
        <span className="font-medium text-text-primary">{label}</span>
        {description === undefined ? null : (
          <span className="text-sm text-text-muted">{description}</span>
        )}
      </span>
      {aside}
    </label>
  );
}

/**
 * One choice of a radio group, drawn as a card. Selected is a brand border on
 * a brand tint, read off the input's own `:checked` state, so the card and
 * the control cannot disagree. Wrap a group in a `<fieldset>` with a
 * `<legend>`.
 */
export function RadioCard({
  label,
  description,
  className = "",
  ...input
}: {
  readonly label: ReactNode;
  readonly description?: ReactNode;
} & Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "children">) {
  return (
    <label
      className={`flex min-h-11 cursor-pointer gap-3 rounded-card border border-hairline-strong p-4 transition-colors hover:border-brand/60 has-checked:border-brand has-checked:bg-brand-subtle has-disabled:cursor-not-allowed has-disabled:opacity-55 ${className}`}
    >
      <input {...input} type="radio" className={`${nativeBox} mt-px`} />
      <span className="flex flex-col gap-0.5">
        <span className="font-medium text-text-primary">{label}</span>
        {description === undefined ? null : (
          <span className="text-sm leading-snug text-text-muted">{description}</span>
        )}
      </span>
    </label>
  );
}
