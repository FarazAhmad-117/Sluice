import type { CSSProperties, ReactNode } from "react";

/**
 * Shared landing-page primitives.
 *
 * These exist so that the page has one gutter, one focus ring, one section
 * rhythm and one set of control shapes, rather than eight near-identical class
 * strings that drift apart. Nothing here names a colour: every value is a token
 * utility from `globals.css`.
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
    <div className={`mx-auto w-full max-w-[1200px] px-5 sm:px-8 ${className}`}>
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
 * The loudest control available, and there is at most one per viewport.
 *
 * Filled white on a pure-black canvas, not brand blue. On this palette white is
 * simply the highest-contrast fill there is, and a coloured button placed next
 * to a white one always loses; keeping the blue for links and focus rings also
 * means the one blue thing on screen is never competing with the one white
 * thing. Both halves come from tokens that invert under the light theme.
 */
export const primaryAction = `inline-flex h-10 cursor-pointer items-center justify-center rounded-input bg-control-solid px-4 text-sm font-medium text-text-on-control-solid transition-colors hover:bg-control-solid-hover ${focusRing}`;

/** Outlined control. Only the border and text colour move on hover. */
export const secondaryAction = `inline-flex h-10 cursor-pointer items-center justify-center rounded-input border border-hairline-strong bg-surface-card px-4 text-sm font-medium text-text-primary transition-colors hover:border-hairline-strong hover:bg-surface-panel ${focusRing}`;

/** The quietest control. A label with a hit area, for a secondary hero action. */
export const ghostAction = `inline-flex h-10 cursor-pointer items-center justify-center rounded-input px-3 text-sm font-medium text-text-muted transition-colors hover:text-text-primary ${focusRing}`;

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

/**
 * Section heading. One size, so the page has one heading rhythm.
 *
 * Set in the display serif. Everything about its size and tracking lives in
 * `.display-lg` rather than in utilities here, because a display serif needs
 * its tracking tightened as it grows and that is a job for one clamp in CSS,
 * not for four responsive utility variants per call site.
 */
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
    <h2 id={id} className={`display-lg text-text-primary ${className}`}>
      {children}
    </h2>
  );
}

/**
 * The page's vertical rhythm, in one place.
 *
 * Bands are separated by space, not by a hairline across the full width. A rule
 * between every section is a habit from documentation, and on a dark canvas it
 * chops the page into boxes; the eye already knows a new section has started
 * because there are 128px of black above it. `divided` is available for the one
 * or two places a line genuinely helps.
 */
export function Section({
  children,
  id,
  labelledBy,
  divided = false,
  className = "",
}: {
  children: ReactNode;
  id?: string;
  labelledBy?: string;
  divided?: boolean;
  className?: string;
}) {
  return (
    <section
      id={id}
      aria-labelledby={labelledBy}
      className={`relative scroll-mt-24 py-20 sm:py-28 lg:py-32 ${
        divided ? "border-t border-hairline" : ""
      } ${className}`}
    >
      {children}
    </section>
  );
}

/**
 * A low-opacity radial wash.
 *
 * This is the only source of colour on most of the page, and it is the reason
 * a pure-black canvas does not read as an empty div. Rules, learned the hard
 * way from the version of this page that had none of them:
 *
 *   - It is absolutely positioned and `pointer-events: none`, so it can never
 *     size its parent and can never eat a click. The parent needs `relative`
 *     and, in almost every case, `overflow-hidden`.
 *   - It sits BEHIND content. Callers put content in a `relative` wrapper
 *     rather than giving this a negative z-index, which would punch it through
 *     an opaque ancestor background.
 *   - One per band. Two glows in one viewport stop reading as light and start
 *     reading as a gradient, which is a different and much cheaper look.
 */
export function Atmosphere({
  color,
  className = "",
  blur = 0,
  style,
}: {
  /** A `--glow-*` token utility value, e.g. `var(--glow-brand)`. */
  color: string;
  className?: string;
  blur?: number;
  style?: CSSProperties;
}) {
  return (
    <div
      aria-hidden="true"
      className={`atmosphere ${className}`}
      style={
        {
          "--atmosphere-color": color,
          "--atmosphere-blur": `${blur}px`,
          ...style,
        } as CSSProperties
      }
    />
  );
}

/**
 * The small capsule above a hero headline.
 *
 * Renders as a link when `href` is given and as plain text otherwise, because
 * a pill that looks interactive and is not is worse than no pill. It carries
 * the pre-release disclosure, which is the one thing on this page that a
 * visitor must not be able to miss, and a capsule above the headline is the
 * only slot on a hero that is read before the headline.
 */
export function BadgePill({
  children,
  href,
  tone = "neutral",
}: {
  children: ReactNode;
  href?: string;
  tone?: "neutral" | "warning";
}) {
  const dot = tone === "warning" ? "bg-status-warning" : "bg-status-healthy";
  const shell =
    "inline-flex items-center gap-2 rounded-full border border-hairline bg-surface-card py-1.5 pr-4 pl-3 text-xs font-medium text-text-body";

  const content = (
    <>
      <span aria-hidden="true" className={`size-1.5 shrink-0 rounded-full ${dot}`} />
      {children}
    </>
  );

  if (href === undefined) {
    return <p className={shell}>{content}</p>;
  }

  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className={`${shell} cursor-pointer transition-colors hover:border-hairline-strong hover:text-text-primary ${focusRing}`}
    >
      {content}
    </a>
  );
}

/**
 * The standard raised surface.
 *
 * `bordered` is the default because on this palette a card with no border and
 * only a luminance step is nearly invisible against the canvas, which is fine
 * for a card sitting on a lit band and not fine for one sitting on black.
 */
export function Card({
  children,
  className = "",
  bordered = true,
}: {
  children: ReactNode;
  className?: string;
  bordered?: boolean;
}) {
  return (
    <div
      className={`rounded-card bg-surface-panel p-6 sm:p-8 ${
        bordered ? "border border-hairline" : ""
      } ${className}`}
    >
      {children}
    </div>
  );
}
