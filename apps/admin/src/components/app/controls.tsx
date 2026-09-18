import type { ReactNode } from "react";

/**
 * SHARED CONTROLS FOR THE ADMIN PANEL.
 *
 * These exist so there is one focus ring, one pair of button shapes and one
 * field shell, rather than a dozen class strings that drift. Nothing here names
 * a colour. Every value is a token utility from `app.css`, so the whole surface
 * follows `data-theme` without a single conditional.
 *
 * THE FOCUS RING IS DECLARED HERE NOW, AND THAT IS A REAL COST WORTH NAMING.
 * It used to be imported from the landing page's primitives, on the argument
 * that a product with two focus rings has one of them wrong. That argument is
 * still correct and the import is no longer available: this application and the
 * marketing site are separate builds with separate dependency graphs, and
 * reaching across would mean one of them importing the other's source tree.
 *
 * What holds the two in agreement instead is the token layer. `app.css` and
 * `apps/web/src/app/globals.css` declare the same custom properties with the
 * same values, and both rings are written against `outline-brand`. If you
 * change the ring here, change it there. There is no build step that will tell
 * you.
 *
 * `outline` rather than `ring`, so it sits outside the element and never
 * participates in layout, which keeps the "hover and focus must not shift
 * anything" rule true by construction.
 *
 * THE TYPE SIZE RULE. Body text is `text-base`, which is 16px, everywhere.
 * `text-sm` and `text-xs` appear only on chrome that is not body text: column
 * headings, status pills, counts and eyebrows. Density in this surface comes
 * from tight vertical rhythm and hairlines, never from shrinking the text
 * people actually have to read.
 */
export const focusRing =
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";

/**
 * Filled control. `bg-brand-solid` with `text-text-on-brand-solid`, never
 * `bg-brand`: white on `--brand` measures 3.81:1 and fails AA, which is the
 * entire reason two brand tokens exist. This is the rule that is easiest to
 * break by reaching for the more obvious token name.
 */
export const primaryButton = `inline-flex w-full cursor-pointer items-center justify-center gap-2 rounded-input bg-brand-solid px-4 py-3 text-base font-medium text-text-on-brand-solid transition-colors hover:bg-brand-solid-hover disabled:cursor-not-allowed disabled:opacity-55 ${focusRing}`;

/** Outlined control. Only the border and text colour move on hover. */
export const secondaryButton = `inline-flex cursor-pointer items-center justify-center gap-2 rounded-input border border-hairline bg-transparent px-3 py-2 text-base font-medium text-text-primary transition-colors hover:border-brand hover:text-brand disabled:cursor-not-allowed disabled:opacity-55 ${focusRing}`;

/** A quiet control for row actions and toggles. */
export const quietButton = `inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-input px-2 py-1 text-sm font-medium text-text-muted transition-colors hover:bg-brand-subtle hover:text-brand disabled:cursor-not-allowed disabled:opacity-55 ${focusRing}`;

/** Inline text link. Underline is always on, so hover changes colour only. */
export const textLink = `cursor-pointer rounded-input text-brand underline underline-offset-4 transition-colors hover:text-brand-hover ${focusRing}`;

/**
 * Text input. 16px on every breakpoint, which is also what stops iOS Safari
 * zooming the viewport the moment the field takes focus.
 */
export const inputControl = `w-full rounded-input border border-hairline bg-surface-base px-3 py-3 text-base text-text-primary transition-colors placeholder:text-text-muted hover:border-brand/60 ${focusRing}`;

export function Field({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={htmlFor} className="text-base font-medium text-text-primary">
        {label}
      </label>
      {children}
      {hint === undefined ? null : <div className="text-base text-text-muted">{hint}</div>}
    </div>
  );
}

/**
 * An error a person can act on, with `role="alert"` so a screen reader is told
 * about it when it appears rather than when focus happens to reach it.
 */
export function FormError({ children }: { children: ReactNode }) {
  return (
    <p
      role="alert"
      className="rounded-input border border-status-danger/50 bg-status-danger/10 px-3 py-2.5 text-base text-text-primary"
    >
      {children}
    </p>
  );
}

/** A small uppercase wide-tracking label. Chrome, not body text. */
export function Eyebrow({ children }: { children: ReactNode }) {
  return (
    <p className="font-mono text-xs font-medium tracking-[0.18em] text-text-muted uppercase">
      {children}
    </p>
  );
}

export type StatusTone = "healthy" | "warning" | "danger" | "neutral";

const TONE_CLASS: Record<StatusTone, string> = {
  healthy: "border-status-healthy/50 text-status-healthy",
  warning: "border-status-warning/50 text-status-warning",
  danger: "border-status-danger/50 text-status-danger",
  neutral: "border-hairline text-text-muted",
};

/** A status pill. The dot carries the colour, so the label stays readable. */
export function StatusPill({ tone, children }: { tone: StatusTone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-input border px-2 py-0.5 font-mono text-xs whitespace-nowrap ${TONE_CLASS[tone]}`}
    >
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {children}
    </span>
  );
}
