"use client";

import { useEffect, useRef } from "react";

/**
 * The closing wordmark, and the light that moves over it.
 *
 * At rest it is barely above the background: a gradient that fades out before
 * the baseline, so it reads as an impression of the name rather than as the
 * name repeated. Moving a pointer across it does two things at once -- it wipes
 * a bright copy into view under the cursor, and it lifts the letter you are
 * over.
 *
 * WHY A MASK AND NOT AN OPACITY FADE. Two copies of the word sit exactly on top
 * of each other. The upper one is fully bright and is masked to a radial spot
 * pinned to the cursor, so what changes on pointermove is two custom properties
 * and nothing else -- no layout, no re-paint of the lower copy.
 *
 * WHY THE LIFT IS DRIVEN FROM JAVASCRIPT AND NOT `:hover`. The bright copy is
 * absolutely positioned over the resting one, so it eats every pointer event
 * and the letters underneath can never match `:hover`. Making it inert instead
 * would fix the hover and break the effect, because then only the lower copy's
 * letter would rise and the two would visibly come apart into a doubled
 * letterform. Both copies have to move together, so one handler moves both.
 *
 * WHY NEITHER IS REACT STATE. Pointermove fires at pointer frequency, well above
 * sixty times a second on a decent mouse. Both the spotlight and the lift are
 * written straight to the DOM from inside one `requestAnimationFrame`, and the
 * lift only writes at all when the letter under the cursor actually changes.
 *
 * It is `aria-hidden`. It is the brand name at the end of a document that
 * already carries it in the nav, the first footer column and the copyright
 * line; announcing it a fourth time would be reading out decoration.
 */

/**
 * How far a hovered letter rises, in ems of the wordmark's own size.
 *
 * In ems rather than pixels so the lift stays proportional: the word clamps
 * between 120px and 340px, and a fixed 16px rise that looks right on a desktop
 * is a shove at phone size. Kept small on purpose -- the brief was a letter that
 * lifts, not one that jumps out of the word.
 */
const LIFT_EM = 0.05;

export function Wordmark({ children = "sluice" }: { children?: string }) {
  const stage = useRef<HTMLDivElement | null>(null);
  /** Both copies' letter nodes, index-aligned, so a lift can move the pair. */
  const baseLetters = useRef<(HTMLSpanElement | null)[]>([]);
  const litLetters = useRef<(HTMLSpanElement | null)[]>([]);

  useEffect(() => {
    const element = stage.current;
    if (element === null) return;

    let queued = false;
    /** Raw viewport coordinates. Converted to stage space inside the frame. */
    let client = { x: 0, y: 0 };
    let lifted = -1;

    /*
      Letter geometry, measured once and cached.

      This is the fix for a lift that stuttered. The hit-test used to call
      `getBoundingClientRect` on every letter on every pointer frame, and each
      of those calls forces the browser to flush pending layout before it can
      answer -- six synchronous layouts per frame, inside the same frame that
      was trying to animate a transform. The transition was fine; it was being
      starved.

      Caching is safe precisely because the animation is a transform. Transforms
      do not affect layout, so a lifted letter's LAYOUT box is exactly where it
      was at rest, and these numbers stay true for as long as nothing reflows.
      They are taken relative to the stage, which is the letters' offset parent,
      so they also survive the page being scrolled.
    */
    let columns: { left: number; right: number }[] = [];

    const measure = () => {
      columns = baseLetters.current.map((node) =>
        node === null
          ? { left: 0, right: 0 }
          : { left: node.offsetLeft, right: node.offsetLeft + node.offsetWidth },
      );
    };

    const setLift = (index: number, on: boolean) => {
      // Back to an explicit zero translate rather than "", so the resting state
      // keeps the compositor layer the stylesheet gave it.
      const transform = on
        ? `translate3d(0, ${-LIFT_EM}em, 0)`
        : "translate3d(0, 0, 0)";
      const base = baseLetters.current[index];
      const lit = litLetters.current[index];
      if (base) base.style.transform = transform;
      if (lit) lit.style.transform = transform;
    };

    const write = () => {
      queued = false;

      /*
        The one layout read in the whole effect, and it is here rather than in
        the event handler on purpose. Pointermove fires faster than the display
        refreshes -- a 1000Hz mouse will deliver a dozen events between frames --
        so measuring in the handler meant a dozen forced layouts per frame to
        answer a question that can only be acted on once. Reading inside the
        frame makes it one, and it is the first thing the frame does, before any
        style is written, so nothing has invalidated layout yet.
      */
      const stage = element.getBoundingClientRect();
      const point = { x: client.x - stage.left, y: client.y - stage.top };

      element.style.setProperty("--spot-x", `${point.x}px`);
      element.style.setProperty("--spot-y", `${point.y}px`);

      /*
        Horizontal only. The stage is exactly the word's own box, so anywhere
        inside it is over some letter's column, and testing the vertical too
        would drop the lift in the hollows of an `s` or between the arms of a
        `u` -- which reads as the effect being broken rather than as precision.
      */
      let next = -1;
      for (let i = 0; i < columns.length; i++) {
        const column = columns[i]!;
        if (point.x >= column.left && point.x <= column.right) {
          next = i;
          break;
        }
      }

      if (next === lifted) return;
      if (lifted >= 0) setLift(lifted, false);
      if (next >= 0) setLift(next, true);
      lifted = next;
    };

    const onMove = (event: PointerEvent) => {
      client = { x: event.clientX, y: event.clientY };
      if (queued) return;
      queued = true;
      requestAnimationFrame(write);
    };

    const onLeave = () => {
      if (lifted >= 0) setLift(lifted, false);
      lifted = -1;
    };

    measure();
    // The word is set in a webfont that arrives after first paint, and its
    // metrics differ from the fallback, so a measurement taken before the swap
    // describes Georgia's letters rather than this one's.
    void document.fonts?.ready.then(measure);

    const observer = new ResizeObserver(measure);
    observer.observe(element);

    element.addEventListener("pointermove", onMove);
    element.addEventListener("pointerleave", onLeave);
    return () => {
      observer.disconnect();
      element.removeEventListener("pointermove", onMove);
      element.removeEventListener("pointerleave", onLeave);
    };
  }, [children]);

  // A space would collapse and throw the two copies' indices out of step with
  // each other, so it is rendered as a non-breaking space and still occupies a
  // slot. The wordmark is one word today; this keeps it correct if it is not.
  const glyphs = [...children];

  const letters = (into: typeof baseLetters) =>
    glyphs.map((glyph, index) => (
      <span
        // The word is fixed content, so index is a stable identity here.
        key={`${glyph}-${index}`}
        ref={(node) => {
          into.current[index] = node;
        }}
        className="wordmark-letter"
      >
        {glyph === " " ? " " : glyph}
      </span>
    ));

  return (
    <div
      ref={stage}
      aria-hidden="true"
      className="wordmark-stage relative translate-y-[12%] cursor-default"
    >
      <p className="wordmark wordmark-base">{letters(baseLetters)}</p>
      {/*
        The lit copy is absolutely positioned over the resting one and shares the
        `.wordmark` class, so the two are guaranteed to share metrics. If they
        ever drift the effect shows as a doubled letterform, which is why the
        type rules live in one class rather than being repeated here.
      */}
      <p className="wordmark wordmark-lit">{letters(litLetters)}</p>
    </div>
  );
}
