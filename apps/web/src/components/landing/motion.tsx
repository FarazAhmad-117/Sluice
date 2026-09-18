"use client";

import { useEffect, useRef, useState } from "react";
import type { CSSProperties, ElementType, ReactNode } from "react";

/**
 * SCROLL MOTION FOR THE LANDING PAGE.
 *
 * Two effects and no library. Both obey `prefers-reduced-motion`, and both are
 * built so that the no-JavaScript and pre-hydration renders are the FINISHED
 * state rather than the starting state.
 *
 * That last point is the whole design. The obvious way to write a scroll reveal
 * is to author the hidden class into the markup and let an observer remove it,
 * and it is a trap: a failed hydration, a blocked bundle or a crawler that does
 * not run scripts then gets a page of invisible text. Here the hidden class is
 * added by an effect. If the effect never runs, nothing is ever hidden.
 */

/** Distance into the viewport, as a fraction, before an element is revealed. */
const REVEAL_THRESHOLD = 0.15;

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

export interface RevealProps {
  children: ReactNode;
  /** Stagger, in milliseconds, applied as a transition delay. */
  delay?: number;
  /** Defaults to a div. Use `li`, `section` and so on where the outline needs it. */
  as?: ElementType;
  className?: string;
  style?: CSSProperties;
}

/**
 * Fades and lifts its children the first time they enter the viewport.
 *
 * Unobserves on reveal, so an element that scrolls back out does not replay.
 * Replaying on every pass is a common default and it is wrong for a document:
 * a reader scrolling back up to re-read a paragraph should find the paragraph,
 * not an animation of the paragraph arriving.
 */
export function Reveal({
  children,
  delay = 0,
  as: Tag = "div",
  className = "",
  style,
}: RevealProps) {
  const node = useRef<HTMLElement | null>(null);
  /*
    Starts false so that server output and the first client paint agree, and is
    flipped on in an effect. The hidden state therefore only ever exists on a
    page whose JavaScript is running and can undo it.
  */
  const [armed, setArmed] = useState(false);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const element = node.current;
    if (element === null || prefersReducedMotion()) return;

    setArmed(true);

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          setShown(true);
          observer.unobserve(entry.target);
        }
      },
      { threshold: REVEAL_THRESHOLD },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return (
    <Tag
      ref={node}
      className={`${armed ? "reveal" : ""} ${shown ? "reveal-in" : ""} ${className}`}
      style={delay > 0 ? { transitionDelay: `${delay}ms`, ...style } : style}
    >
      {children}
    </Tag>
  );
}

/**
 * Moves its children against the scroll, at a fraction of its speed.
 *
 * `speed` is the fraction of the scrolled distance the element gives back:
 * 0.15 means it drifts up by fifteen pixels for every hundred the page moves.
 * Keep it small. Parallax reads as depth below roughly 0.25 and as a bug above
 * it, because content that visibly outruns its own section stops looking like
 * it is behind the page and starts looking like it is detached from it.
 *
 * WHY THIS IS NOT A SCROLL LISTENER DRIVING `top`. Writing a layout property on
 * every scroll event forces a reflow of the whole document inside the scroll
 * handler, which is the classic way to make a page feel heavy precisely while
 * it is being scrolled. This writes `transform` only, from inside a
 * `requestAnimationFrame` that coalesces bursts of scroll events into one write
 * per frame, so the work stays on the compositor.
 */
export function Parallax({
  children,
  speed = 0.15,
  className = "",
}: {
  children: ReactNode;
  speed?: number;
  className?: string;
}) {
  const node = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const element = node.current;
    if (element === null || prefersReducedMotion()) return;

    let frame = 0;
    let queued = false;

    const apply = () => {
      queued = false;
      const rect = element.getBoundingClientRect();
      // Measured from the viewport centre, so the offset is zero when the
      // element is centred and symmetric either side of it. Anchoring to the
      // top instead gives every element a large constant offset on load.
      const fromCentre = rect.top + rect.height / 2 - window.innerHeight / 2;
      element.style.transform = `translate3d(0, ${(-fromCentre * speed).toFixed(2)}px, 0)`;
    };

    const onScroll = () => {
      if (queued) return;
      queued = true;
      frame = requestAnimationFrame(apply);
    };

    apply();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, [speed]);

  return (
    <div ref={node} className={`will-change-transform ${className}`}>
      {children}
    </div>
  );
}
