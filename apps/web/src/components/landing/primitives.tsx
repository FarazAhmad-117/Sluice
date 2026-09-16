import type { ReactNode } from "react";

/**
 * Shared landing-page primitives.
 *
 * These exist so that the page has one gutter, one focus ring and one pair of
 * button shapes rather than eight near-identical class strings that drift
 * apart. Nothing here names a colour: every value is a token utility from
 * `globals.css`.
 */

/** The single horizontal rhythm for the page. 20px gutter at 375px. */
export function Container({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`mx-auto w-full max-w-6xl px-5 sm:px-8 ${className}`}>
      {children}
    </div>
  );
}

/**
 * One focus ring for the whole page. `outline` rather than `ring` so it sits
 * outside the element and never participates in layout, which keeps the
 * "hover and focus must not shift anything" rule true by construction.
 */
export const focusRing =
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";

/**
 * Filled control. `bg-brand-solid` with `text-on-brand-solid`, never
 * `bg-brand`: white on `--brand` measures 3.81:1 and fails AA, which is the
 * entire reason two brand tokens exist.
 */
export const primaryAction = `inline-flex cursor-pointer items-center justify-center rounded-input bg-brand-solid px-4 py-2.5 text-base font-medium text-text-on-brand-solid transition-colors hover:bg-brand-solid-hover md:text-sm ${focusRing}`;

/** Outlined control. Only the border and text colour move on hover. */
export const secondaryAction = `inline-flex cursor-pointer items-center justify-center rounded-input border border-hairline bg-transparent px-4 py-2.5 text-base font-medium text-text-primary transition-colors hover:border-brand hover:text-brand md:text-sm ${focusRing}`;

/** Inline text link. Underline is always on, so hover changes colour only. */
export const textLink = `cursor-pointer rounded-input text-brand underline underline-offset-4 transition-colors hover:text-brand-hover ${focusRing}`;

/**
 * A small uppercase wide-tracking label above a heading.
 *
 * The design budget is at most ceil(sectionCount / 3) of these on the whole
 * page. With seven sections that is three, and the page spends two: one on the
 * kill switch and one on the threat model. Do not add a third without
 * deleting one.
 */
export function Eyebrow({ children }: { children: ReactNode }) {
  return (
    <p className="font-mono text-xs font-medium tracking-[0.18em] text-text-muted uppercase">
      {children}
    </p>
  );
}

/** Section heading. One size, so the page has one heading rhythm. */
export function SectionHeading({
  children,
  id,
  className = "",
}: {
  children: ReactNode;
  id?: string;
  className?: string;
}) {
  return (
    <h2
      id={id}
      className={`text-[1.75rem] leading-[1.15] font-medium tracking-[-0.02em] text-text-primary sm:text-4xl ${className}`}
    >
      {children}
    </h2>
  );
}
