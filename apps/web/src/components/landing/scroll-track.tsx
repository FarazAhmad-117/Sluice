"use client";

import { useEffect, useRef } from "react";
import type { ReactNode } from "react";

/**
 * Publishes the reader's scroll position through this element as `--p`, 0 to 1.
 *
 * Its one consumer is the revocation timeline, where the line connecting the
 * four steps draws itself as the section passes through the viewport and each
 * dot lights as the line reaches it. Scroll-LINKED rather than triggered: the
 * reader is drawing the line, so scrolling back up un-draws it, and the pace is
 * theirs rather than a fixed animation they have to wait out.
 *
 * WHY THE PROGRESS IS WRITTEN AS A CSS VARIABLE AND NOT AS REACT STATE. This
 * updates on every frame of a scroll. React state would re-render this subtree
 * sixty times a second to change one number that only CSS reads. A single
 * `style.setProperty` on a ref costs nothing and keeps the whole effect on the
 * compositor, and it is why `--p` is registered with `@property` in
 * `globals.css`: a registered number interpolates and can be used in `calc()`,
 * an unregistered one is an opaque token and every dependent calculation
 * silently fails.
 *
 * THE WINDOW. Progress starts when the element's top reaches three quarters of
 * the way down the viewport and completes when it reaches one quarter. Both
 * ends are inside the viewport on purpose: a track that finished as it left the
 * screen would only ever be seen half-drawn, and one that started before it
 * arrived would already be half-drawn when it appeared.
 */

const START = 0.75;
const END = 0.25;

export function ScrollTrack({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  const node = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const element = node.current;
    if (element === null) return;

    // Reduced motion gets the finished state, not the starting one. The line is
    // information -- it says these four steps are connected -- so withholding it
    // would withhold meaning, where withholding the drawing of it costs nothing.
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      element.style.setProperty("--p", "1");
      return;
    }

    let frame = 0;
    let queued = false;

    const measure = () => {
      queued = false;
      const rect = element.getBoundingClientRect();
      const height = window.innerHeight;
      const from = height * START;
      const to = height * END;
      const raw = (from - rect.top) / (from - to);
      element.style.setProperty("--p", String(Math.min(1, Math.max(0, raw))));
    };

    const onScroll = () => {
      if (queued) return;
      queued = true;
      frame = requestAnimationFrame(measure);
    };

    measure();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, []);

  return (
    <div ref={node} className={className}>
      {children}
    </div>
  );
}
