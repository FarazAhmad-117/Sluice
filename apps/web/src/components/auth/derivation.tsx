"use client";

import { useEffect, useState } from "react";
import type { AuthPhase, DerivationReport, DeviceCapability } from "@/lib/auth/auth-context";

/**
 * SURFACING WHAT THE KEY DERIVATION ACTUALLY DID.
 *
 * `deriveMasterUnlockKey` reports the route it took in `result.path`. A page
 * that ignores it looks completely healthy while shipping an eight second
 * frozen tab to every user, and the realistic cause is not a code change: it is
 * a Content-Security-Policy deployed without `worker-src`, or without
 * `wasm-unsafe-eval`, which no test in this repository can see and which
 * produces no error anybody notices. `derive.ts` says so in its header. This
 * file is the other half of that contract.
 *
 * THE PROGRESS IS REAL, NOT DECORATIVE. Argon2id exposes no progress: there is
 * no callback and no way to know how far through the memory grid it is. So
 * nothing here draws a percentage, because a percentage would be invented. It
 * counts ELAPSED TIME, which is measured, and states the expected figure beside
 * it so a run that is taking five times as long is visible as exactly that.
 */

const EXPECTED_WORKER_MS = 1600;

/**
 * Milliseconds since this component mounted, ticking at 100ms.
 *
 * The timer state is deliberately owned by a component that is MOUNTED ONLY
 * WHILE A DERIVATION IS RUNNING, rather than by a hook that resets itself when
 * a boolean flips. Resetting on a flag means writing state synchronously inside
 * an effect, which schedules a second render pass for every run; letting the
 * subtree unmount gives the same reset for free, and the only `setState` left is
 * the one in the interval callback, where it belongs.
 */
function useElapsedSinceMount(): number {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const started = Date.now();
    const handle = setInterval(() => setElapsed(Date.now() - started), 100);
    return () => clearInterval(handle);
  }, []);

  return elapsed;
}

const PHASE_LABEL: Record<AuthPhase, string> = {
  idle: "",
  deriving: "Deriving your master unlock key",
  "generating-keys": "Generating your keypairs",
  "contacting-server": "Talking to the server",
  unwrapping: "Opening your wrapped keys",
};

/**
 * The in-flight state of a sign in.
 *
 * The bar is an indeterminate sweep, not a fill: a fill would imply a fraction
 * that nothing can compute. The number beside it is the real elapsed time.
 */
export function DerivationProgress({ phase }: { phase: AuthPhase }) {
  // The split is what makes the timer reset without an effect writing state:
  // `phase` returning to "idle" unmounts the body and the next run mounts a
  // fresh one at zero.
  if (phase === "idle") return null;
  return <ActiveProgress phase={phase} />;
}

function ActiveProgress({ phase }: { phase: Exclude<AuthPhase, "idle"> }) {
  const elapsed = useElapsedSinceMount();
  const slow = phase === "deriving" && elapsed > EXPECTED_WORKER_MS * 3;

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col gap-2 rounded-input border border-hairline bg-surface-panel px-3 py-3"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-base text-text-primary">{PHASE_LABEL[phase]}</span>
        <span className="font-mono text-sm text-text-muted">
          {(elapsed / 1000).toFixed(1)}s elapsed
        </span>
      </div>
      <div
        aria-hidden="true"
        className="h-1 w-full overflow-hidden rounded-input bg-hairline"
      >
        <div className="sluice-sweep h-full w-1/3 rounded-input bg-brand" />
      </div>
      {phase === "deriving" ? (
        <p className={`text-base ${slow ? "text-status-warning" : "text-text-muted"}`}>
          {slow
            ? "This is taking much longer than the expected 1.6 seconds, which usually means the work landed on the main thread. The page will say so when it finishes."
            : "Argon2id at 64 MiB. About 1.6 seconds on a worker thread. The page stays responsive."}
        </p>
      ) : null}
    </div>
  );
}

/**
 * What the derivation did, after the fact. Shown on the dashboard as well as on
 * the forms, because a degradation that only appears for one second during
 * sign in is a degradation nobody reports.
 */
export function DerivationPathNotice({ report }: { report: DerivationReport | null }) {
  if (report === null) return null;

  if (report.path === "worker-wasm") {
    return (
      <p className="font-mono text-sm text-text-muted">
        Key derived on a worker thread with WASM Argon2id in {report.elapsedMs} ms.
      </p>
    );
  }

  const detail =
    report.path === "main-wasm"
      ? "WASM Argon2id ran on the main thread. The tab was frozen for the whole derivation."
      : "Pure JavaScript Argon2id ran on the main thread. That is roughly twelve times slower and the tab was frozen throughout.";

  return (
    <div
      role="alert"
      className="flex flex-col gap-2 rounded-input border border-status-warning/60 bg-status-warning/10 px-3 py-3"
    >
      <p className="text-base font-medium text-text-primary">
        The key derivation did not run where it should have.
      </p>
      <p className="text-base text-text-primary">{detail}</p>
      <p className="text-base text-text-muted">
        The key is byte identical, so nothing is weaker. What is wrong is where the work ran. The
        usual cause is a Content-Security-Policy deployed without worker-src, or without
        wasm-unsafe-eval. Report this.
      </p>
      <ul className="flex flex-col gap-1">
        {report.degradations.map((degradation) => (
          <li
            key={`${degradation.from}-${degradation.to}-${degradation.reason}`}
            className="font-mono text-sm break-words text-text-muted"
          >
            {degradation.from} to {degradation.to}: {degradation.reason}
          </li>
        ))}
      </ul>
      <p className="font-mono text-sm text-text-muted">
        Route {report.path}, {report.elapsedMs} ms.
      </p>
    </div>
  );
}

/**
 * The result of the page-load probe.
 *
 * This is deliberately shown BEFORE the user has typed anything.
 * `probeDerivationCapability` exists precisely so that a browser which cannot
 * allocate 64 MiB is discovered now, rather than after somebody has chosen a
 * password and created an account row they can never open.
 */
export function CapabilityNotice({ capability }: { capability: DeviceCapability | null }) {
  if (capability === null) return null;
  const healthy = capability.workerAvailable && capability.memoryAvailable && capability.wasmUsable;
  if (healthy) return null;

  const fatal = !capability.memoryAvailable;

  return (
    <div
      role="alert"
      className={`flex flex-col gap-2 rounded-input border px-3 py-3 ${
        fatal
          ? "border-status-danger/60 bg-status-danger/10"
          : "border-status-warning/60 bg-status-warning/10"
      }`}
    >
      <p className="text-base font-medium text-text-primary">
        {fatal
          ? "This browser cannot allocate the memory the key derivation needs."
          : "This browser cannot run the key derivation the fast way."}
      </p>
      <p className="text-base text-text-primary">
        {fatal
          ? "Argon2id needs 64 MiB in one allocation. Without it there is no way to derive your key at the parameters this product uses, and those parameters are not negotiable."
          : "Your key will still be correct, but the derivation will run on the main thread and freeze this tab for several seconds."}
      </p>
      <ul className="flex flex-col gap-1">
        {capability.reasons.map((reason) => (
          <li key={reason} className="font-mono text-sm break-words text-text-muted">
            {reason}
          </li>
        ))}
      </ul>
    </div>
  );
}
