import type { ReactNode, SVGProps } from "react";

/**
 * THE DASHBOARD'S ICONS, INLINE.
 *
 * Paths come from the approved Round 2 and Round 3 mocks; the few the mocks do not show
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

/* The sidebar's icons, from the Round 3 mocks (stroke 1.6 there). */

export function IconOverview(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <rect x="4" y="4" width="7" height="7" rx="1.5" />
      <rect x="13" y="4" width="7" height="7" rx="1.5" />
      <rect x="4" y="13" width="7" height="7" rx="1.5" />
      <rect x="13" y="13" width="7" height="7" rx="1.5" />
    </Icon>
  );
}

export function IconKey(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <circle cx="8" cy="15" r="4" />
      <path d="M10.8 12.2 20 3M16 7l3 3M14 9l2 2" />
    </Icon>
  );
}

export function IconColumns(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M9 4v16M15 4v16" />
    </Icon>
  );
}

export function IconLayers(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <path d="m12 3 9 5-9 5-9-5 9-5Z" />
      <path d="m3 13 9 5 9-5" />
    </Icon>
  );
}

export function IconTicket(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <path d="M4 7h16v3a2 2 0 0 0 0 4v3H4v-3a2 2 0 0 0 0-4V7Z" />
    </Icon>
  );
}

export function IconActivity(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <path d="M3 12h4l3-8 4 16 3-8h4" />
    </Icon>
  );
}

export function IconSettings(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4" />
    </Icon>
  );
}

export function IconBook(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2V5Z" />
      <path d="M4 19a2 2 0 0 1 2-2h13" />
    </Icon>
  );
}

export function IconFolder(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
    </Icon>
  );
}

export function IconUsers(props: IconProps) {
  return (
    <Icon strokeWidth={1.6} {...props}>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14a6.5 6.5 0 0 1 3.5 6" />
    </Icon>
  );
}

export function IconMenu(props: IconProps) {
  return (
    <Icon strokeWidth={1.8} {...props}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </Icon>
  );
}

export function IconArrowRight(props: IconProps) {
  return (
    <Icon strokeWidth={1.8} {...props}>
      <path d="M5 12h14M13 6l6 6-6 6" />
    </Icon>
  );
}

export function IconExternal(props: IconProps) {
  return (
    <Icon strokeWidth={1.8} {...props}>
      <path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" />
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
