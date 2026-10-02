import type { ReactNode, SVGProps } from "react";

/**
 * THE DASHBOARD'S ICONS, INLINE.
 *
 * Paths come from the approved Round 2 mocks; the few the mocks do not show
 * (eye-off, check) are drawn on the same 24 grid with the same stroke. Every
 * icon is decorative (`aria-hidden`): the control around it carries the
 * accessible name. Colour is `currentColor`, so an icon follows its control's
 * token and both themes for free. Size with `className` (`size-4`, ...).
 */

type IconProps = Omit<SVGProps<SVGSVGElement>, "children">;

function Icon({ children, className = "size-4", ...props }: IconProps & { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={className}
      {...props}
    >
      {children}
    </svg>
  );
}

export function IconSearch(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </Icon>
  );
}

export function IconPlus(props: IconProps) {
  return (
    <Icon strokeWidth={2.2} {...props}>
      <path d="M12 5v14M5 12h14" />
    </Icon>
  );
}

export function IconChevronUpDown(props: IconProps) {
  return (
    <Icon strokeWidth={1.8} {...props}>
      <path d="m8 9 4-4 4 4M8 15l4 4 4-4" />
    </Icon>
  );
}

export function IconChevronDown(props: IconProps) {
  return (
    <Icon strokeWidth={1.8} {...props}>
      <path d="m7 10 5 5 5-5" />
    </Icon>
  );
}

export function IconChevronLeft(props: IconProps) {
  return (
    <Icon strokeWidth={1.8} {...props}>
      <path d="m15 18-6-6 6-6" />
    </Icon>
  );
}

export function IconEye(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
      <circle cx="12" cy="12" r="3" />
    </Icon>
  );
}

export function IconEyeOff(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M10.6 5.1A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17.7 17.7 0 0 1-3.2 4.1M6.6 6.6C3.7 8.5 2 12 2 12s3.6 7 10 7a9.8 9.8 0 0 0 5.4-1.6" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      <path d="m3 3 18 18" />
    </Icon>
  );
}

export function IconCopy(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="8" y="8" width="12" height="12" rx="2" />
      <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
    </Icon>
  );
}

/** Three dots. Filled rather than stroked, as in the mocks. */
export function IconMore(props: IconProps) {
  return (
    <Icon fill="currentColor" stroke="none" {...props}>
      <circle cx="5" cy="12" r="1.6" />
      <circle cx="12" cy="12" r="1.6" />
      <circle cx="19" cy="12" r="1.6" />
    </Icon>
  );
}

export function IconClose(props: IconProps) {
  return (
    <Icon strokeWidth={1.8} {...props}>
      <path d="M6 6l12 12M18 6 6 18" />
    </Icon>
  );
}

export function IconUpload(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 15V4M7 9l5-5 5 5M5 20h14" />
    </Icon>
  );
}

export function IconCheck(props: IconProps) {
  return (
    <Icon strokeWidth={2} {...props}>
      <path d="m5 12.5 4.5 4.5L19 7" />
    </Icon>
  );
}

/** The quarter arc the mocks use for "working". Spun by the caller. */
export function IconSpinner(props: IconProps) {
  return (
    <Icon strokeWidth={2} {...props}>
      <path d="M12 3a9 9 0 1 0 9 9" />
    </Icon>
  );
}
