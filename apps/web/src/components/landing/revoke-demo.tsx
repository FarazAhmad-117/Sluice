"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ParticleField } from "@/components/particle-field";
import { focusRing } from "@/components/landing/primitives";

/**
 * The hero visual, and the control that makes it mean something.
 *
 * The particle field has always known how to scatter. Until now nothing ever
 * told it to, so the page's signature visual was a sphere that rotated: a
 * decoration, which is the one thing the design direction said it must not be.
 * A sphere that holds coherent and then comes apart on a revoke IS the product
 * mechanic. Rotating forever is not.
 *
 * This is the interim version, deliberately. It fires the real scatter on a
 * real click, so the visual finally says what the platform does, but the
 * processes are simulated and the millisecond figure is not measured. The full
 * version drives this from live Convex subscriptions against genuinely
 * connected clients and prints the wall clock it actually took.
 *
 * TWO THINGS THAT MUST SURVIVE INTO THAT VERSION.
 *
 * First, the readout has to carry a measured number. "Instant" is the word
 * every competitor already uses; a real figure is not.
 *
 * Second, the animation must NOT run at the real speed. A kill that completes
 * in tens of milliseconds is below the threshold at which an eye reads an
 * event as an event: it looks like the page glitched, not like the product is
 * fast. The number stays honest and the motion resolves over roughly a second
 * so a human can see what happened. That is legibility, not exaggeration, and
 * it only stays honest while the printed figure is the measured one.
 */

type Phase = "idle" | "revoking" | "done";

/** Long enough to read as an event, short enough not to feel staged. */
const SETTLE_MS = 2200;

const LINES = [
  "worker-a  read SLUICE_DB_URL",
  "worker-b  read STRIPE_SECRET_KEY",
  "worker-c  read REDIS_URL",
];

export function RevokeDemo() {
  const [phase, setPhase] = useState<Phase>("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // A leaked timer after navigation is a real bug, not a theoretical one.
  useEffect(() => {
    return () => {
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, []);

  const revoke = useCallback(() => {
    if (phase === "revoking") return;
    setPhase("revoking");
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = setTimeout(() => setPhase("done"), SETTLE_MS);
  }, [phase]);

  const dead = phase !== "idle";

  return (
    <div className="mx-auto w-full max-w-[380px] sm:max-w-[440px] lg:mr-0 lg:ml-auto lg:max-w-[520px]">
      <ParticleField
        state={phase === "revoking" ? "scattered" : "idle"}
        className="aspect-square w-full"
      />

      <div className="mt-6 rounded-card border border-hairline bg-surface-panel p-4">
        <ul className="space-y-1.5 font-mono text-xs leading-relaxed">
          {LINES.map((line) => (
            <li
              key={line}
              className={
                dead
                  ? "text-text-muted line-through decoration-status-danger/70"
                  : "text-text-muted"
              }
            >
              <span className={dead ? "" : "text-status-healthy"}>
                {dead ? "x" : "+"}
              </span>{" "}
              {line}
            </li>
          ))}
        </ul>

        <div className="mt-4 flex items-center justify-between gap-3 border-t border-hairline pt-4">
          <p
            aria-live="polite"
            className="font-mono text-xs text-text-muted"
          >
            {phase === "idle" ? "3 processes holding this token" : null}
            {phase === "revoking" ? "signature verified, draining" : null}
            {phase === "done" ? (
              <span className="text-status-danger">3 processes exited</span>
            ) : null}
          </p>

          <button
            type="button"
            onClick={phase === "done" ? () => setPhase("idle") : revoke}
            disabled={phase === "revoking"}
            className={`inline-flex shrink-0 cursor-pointer items-center rounded-input border border-hairline px-3 py-1.5 font-mono text-xs text-text-primary transition-colors hover:border-status-danger hover:text-status-danger disabled:cursor-default disabled:opacity-60 ${focusRing}`}
          >
            {phase === "done" ? "Reset" : "Revoke token"}
          </button>
        </div>
      </div>

      {/*
        Fingerprint puts "This is a demo. Production accuracy will be higher."
        directly under the live demo in their hero, and it is the reason a real
        demo can be run without over-claiming. The same discipline applies here
        and applies harder, because these processes are not real yet.
      */}
      <p className="mt-3 text-center font-mono text-[0.6875rem] text-text-muted">
        Simulated processes. The revocation path is not built yet.
      </p>
    </div>
  );
}
