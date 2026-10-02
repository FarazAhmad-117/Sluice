/**
 * THE CLASS STRINGS EVERY PRIMITIVE SHARES.
 *
 * One focus ring and one input shell, so they cannot drift between controls.
 * Nothing here names a colour; every value is a token utility from `app.css`,
 * so the whole surface follows `data-theme`.
 *
 * THE FOCUS RING MUST MATCH THE LANDING PAGE'S. This application and the
 * marketing site are separate builds, so nothing imports one from the other:
 * what holds them in agreement is the token layer, and both rings are written
 * against `outline-brand`. If you change the ring here, change it in
 * `apps/web` too. There is no build step that will tell you.
 *
 * `outline` rather than `ring`, so it sits outside the element and never
 * participates in layout, which keeps "hover and focus must not shift
 * anything" true by construction.
 */
export const focusRing =
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";

/**
 * Text input. 16px on every breakpoint, which is also what stops iOS Safari
 * zooming the viewport the moment the field takes focus.
 */
export const inputControl = `w-full rounded-input border border-hairline bg-surface-base px-3 py-3 text-base text-text-primary transition-colors placeholder:text-text-muted hover:border-brand/60 ${focusRing}`;

/**
 * THE ONE COMPACT HEIGHT. 34px on a desktop with a mouse, where the Round 3
 * mocks draw their header buttons, toolbar fields and sidebar rows; 44px
 * below 1024px and on any coarse pointer, which is the touch-target floor in
 * PRODUCT.md. Every compact control uses this string, so a header button, a
 * filter field and a sidebar row can never disagree about how tall they are.
 */
export const compactHeight = "min-h-11 lg:min-h-[34px] lg:pointer-coarse:min-h-11";

/** The page gutter: 28px on a desktop, 16px on a phone. Shared by the header bar and the page body. */
export const pageGutter = "px-4 sm:px-7";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "danger-outline";
export type ButtonSize = "sm" | "md" | "lg";

const BUTTON_BASE = `inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 rounded-input font-semibold whitespace-nowrap no-underline transition-colors disabled:cursor-not-allowed disabled:opacity-55 aria-disabled:cursor-not-allowed aria-disabled:opacity-55 ${focusRing}`;

/**
 * Primary is the inverted-to-the-canvas fill the mocks use, always with
 * `text-text-on-control-solid`. Danger text is `text-surface-base`, black on
 * the red fill on dark; on light that token is white, which measures under
 * AA on this red, so the light theme uses the near-black primary text.
 */
const BUTTON_VARIANT: Record<ButtonVariant, string> = {
  // `sluice-primary` carries the disabled look; see `app.css`.
  primary: "sluice-primary bg-control-solid text-text-on-control-solid hover:bg-control-solid-hover",
  secondary:
    "border border-hairline-strong bg-transparent text-text-primary hover:bg-surface-card",
  ghost: "bg-transparent text-text-muted hover:bg-surface-card hover:text-text-primary",
  danger:
    "bg-status-danger text-surface-base hover:bg-status-danger/90 light:text-text-primary",
  // The detail panel's Delete: it says what it does in words, outlined so it
  // does not shout beside Edit. On light the label goes near-black, because
  // this red on white is under AA at 14px; the red border stays.
  "danger-outline":
    "border border-status-danger/50 bg-transparent text-status-danger hover:bg-status-danger/8 light:text-text-primary",
};

/** `sm` is {@link compactHeight}; `md` 44px; `lg` 48px. */
const BUTTON_SIZE: Record<ButtonSize, string> = {
  sm: `${compactHeight} px-3.5 text-sm lg:px-3`,
  md: "min-h-11 px-4 text-sm",
  lg: "min-h-12 px-5 text-base",
};

/** The button look, for the rare control that cannot be a `Button` (a file picker's label). */
export function buttonClass(
  variant: ButtonVariant = "primary",
  size: ButtonSize = "md",
  extra = "",
): string {
  return `${BUTTON_BASE} ${BUTTON_VARIANT[variant]} ${BUTTON_SIZE[size]} ${extra}`;
}
