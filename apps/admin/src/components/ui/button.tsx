import type { ButtonHTMLAttributes, ComponentPropsWithRef, ReactNode } from "react";
import { Link } from "react-router";
import type { LinkProps } from "react-router";
import { IconSpinner } from "./icons";
import { buttonClass, focusRing } from "./styles";
import type { ButtonSize, ButtonVariant } from "./styles";

export type { ButtonSize, ButtonVariant } from "./styles";

/**
 * THE DASHBOARD'S BUTTONS.
 *
 * Primary is the inverted-to-the-canvas fill the mocks use (near white on
 * dark, near black on light), always with `text-text-on-control-solid`. Every
 * size is at least 44px tall, which is the touch-target floor in PRODUCT.md
 * even where the mock draws a 38px control.
 *
 * With `to`, it renders a react-router `<Link>`: navigation stays a link (so
 * it opens in a new tab and reads as a link to a screen reader) while looking
 * like a button.
 */

interface CommonProps {
  readonly variant?: ButtonVariant;
  readonly size?: ButtonSize;
  /** Leading icon, decorative. */
  readonly icon?: ReactNode;
  readonly className?: string;
  readonly children: ReactNode;
}

type AsButton = CommonProps &
  Omit<ComponentPropsWithRef<"button">, keyof CommonProps> & {
    readonly to?: undefined;
    /**
     * Shows a spinner and refuses clicks, WITHOUT the `disabled` attribute.
     * Disabling the focused control makes the browser drop focus to `<body>`,
     * which loses the person's place and, inside a drawer, would let focus out
     * of the trap. So it is `aria-disabled` plus a guarded click, focus stays
     * on the button, and a visually hidden status says what is happening.
     */
    readonly loading?: boolean;
    /** What the status announces while loading. Defaults to "Working…". */
    readonly loadingLabel?: string;
  };

type AsLink = CommonProps & Omit<LinkProps, keyof CommonProps> & { readonly to: LinkProps["to"] };

export type ButtonProps = AsButton | AsLink;

export function Button(props: ButtonProps) {
  if (props.to !== undefined) {
    const { variant, size, icon, className = "", children, ...link } = props;
    return (
      <Link {...link} className={buttonClass(variant, size, className)}>
        {icon}
        {children}
      </Link>
    );
  }
  const {
    variant,
    size,
    icon,
    className = "",
    children,
    loading = false,
    loadingLabel = "Working…",
    onClick,
    type = "button",
    ...button
  } = props;
  return (
    <>
      <button
        {...button}
        type={type}
        aria-disabled={loading ? true : button["aria-disabled"]}
        aria-busy={loading || undefined}
        onClick={(event) => {
          // Also stops a submit button submitting its form, including the
          // implicit submit from pressing Enter in a field.
          if (loading) {
            event.preventDefault();
            return;
          }
          onClick?.(event);
        }}
        className={buttonClass(variant, size, className)}
      >
        {loading ? (
          <IconSpinner className="size-4 animate-spin motion-reduce:animate-none" />
        ) : (
          icon
        )}
        {children}
      </button>
      {/* Outside the button, so it is announced rather than folded into the
          button's name. Always rendered, so the live region exists before
          its text changes, which is what makes screen readers announce it. */}
      <span role="status" className="sr-only">
        {loading ? loadingLabel : ""}
      </span>
    </>
  );
}

/**
 * A square icon-only control: close, reveal, row menu. `label` is required
 * because the icon is `aria-hidden`; it becomes the accessible name. 44px
 * square, with the visible glyph as small as the mock draws it.
 */
export function IconButton({
  label,
  children,
  className = "",
  type = "button",
  ...button
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label" | "children"> & {
  readonly label: string;
  readonly children: ReactNode;
}) {
  return (
    <button
      {...button}
      type={type}
      aria-label={label}
      className={`inline-flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-input text-text-muted transition-colors hover:bg-surface-card hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-55 ${focusRing} ${className}`}
    >
      {children}
    </button>
  );
}
