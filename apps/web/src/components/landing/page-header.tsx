import type { ReactNode } from "react";

import { Reveal } from "@/components/landing/motion";
import { Container, Eyebrow } from "@/components/landing/primitives";

/**
 * The opening band of an inner page.
 *
 * Deliberately NOT the homepage hero. It is the same type, the same gutter and
 * the same graph-paper wash, at two thirds the vertical size and with no
 * artwork, because an inner page that opens as loudly as the homepage makes a
 * reader who navigated there feel they have gone in a circle. One display
 * heading, one paragraph, and the content starts.
 *
 * `h1` per page, always, and the eyebrow is a `<p>` rather than a heading so
 * the document outline is the page's sections and not its decoration.
 */
export function PageHeader({
  eyebrow,
  title,
  children,
  aside,
}: {
  eyebrow: string;
  title: ReactNode;
  /** The lede. One paragraph. */
  children: ReactNode;
  /** Optional trailing element, such as a status pill or a repository link. */
  aside?: ReactNode;
}) {
  return (
    <header className="relative overflow-hidden pt-28 pb-14 sm:pt-32 lg:pt-36">
      <div
        aria-hidden="true"
        className="graph-paper pointer-events-none absolute inset-0"
      />
      <Container className="relative">
        <Reveal>
          <Eyebrow>{eyebrow}</Eyebrow>
        </Reveal>
        <Reveal delay={80}>
          <h1 className="display-lg ink mt-5 max-w-[22ch]">{title}</h1>
        </Reveal>
        <Reveal delay={160}>
          <div className="mt-6 max-w-160 text-[17px] leading-relaxed text-text-muted">
            {children}
          </div>
        </Reveal>
        {aside === undefined ? null : (
          <Reveal delay={220}>
            <div className="mt-8">{aside}</div>
          </Reveal>
        )}
      </Container>
    </header>
  );
}

/**
 * A slot for one of the three commissioned illustrations.
 *
 * It renders a labelled, correctly proportioned empty box rather than a
 * hand-rolled stand-in. A placeholder drawing is the worst of both: it is not
 * the illustration, and it is convincing enough that nobody replaces it.
 *
 * `aria-hidden`, because an empty box has nothing to announce and the prose
 * around every one of these carries the same information in words.
 */
export function IllustrationSlot({
  name,
  width,
  height,
  className = "",
}: {
  /** What goes here. Shown in the box and repeated in the comment at the call site. */
  name: string;
  width: number;
  height: number;
  className?: string;
}) {
  return (
    <div
      aria-hidden="true"
      className={`flex w-full items-center justify-center rounded-card border border-dashed border-hairline bg-surface-deep p-6 ${className}`}
      style={{ aspectRatio: `${width} / ${height}`, minHeight: "14rem" }}
    >
      <p className="text-center font-mono text-xs leading-6 tracking-[0.18em] text-text-faint uppercase">
        Illustration slot
        <br />
        {name}
        <br />
        {`${width} x ${height}`}
      </p>
    </div>
  );
}
