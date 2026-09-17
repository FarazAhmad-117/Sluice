import type { SluiceDecision, SluiceHost } from "./types";

/**
 * THE ONLY PLACE A DECISION BECOMES AN EFFECT.
 *
 * WHAT WAS DECIDED ABOUT `process.exit`. This package contains no reference to
 * `process`, no `node:` import and no `@types/node`, and that is structural
 * rather than stylistic: without the types, a `node:` import does not compile,
 * so the rule cannot be broken by accident in a later edit. `packages/crypto`
 * uses the same device for the same reason.
 *
 * Killing a process is the most destructive thing this codebase does, so it
 * happens through `SluiceHost.exit`, which the caller supplies. `SluiceCore`
 * does not import this file and does not know the interface exists: it returns
 * decisions and nothing else, which is what lets the property tests enumerate
 * hundreds of thousands of event sequences without a process ever being at
 * risk. A Node shell implements `exit` as `process.exit(code)`; a test
 * implements it as pushing a string onto an array; a Deno or Bun or edge shell
 * implements it however that runtime spells it.
 *
 * WHY EVERY CALLBACK IS WRAPPED EXCEPT `exit`. These are customer functions
 * running during the incident that triggered the revocation, which is exactly
 * when a logger, a metrics sink or a connection-pool drain is most likely to be
 * failing too. A throw from any of them must not stop the exit, or a broken
 * telemetry client would become a way to survive a revocation. `exit` itself is
 * NOT wrapped: it does not return under any correct implementation, so a throw
 * from it means the host is broken in a way this package cannot paper over, and
 * swallowing it would leave a revoked process running with nothing in the log.
 *
 * WHAT A TRANSPORT SHELL STILL OWES, and these are not optional:
 *
 *  1. On `shutdown`, arm an INDEPENDENT timer for `drainMs` that calls back
 *     into the core no matter what `onRevoke` does. The core cannot time
 *     anything itself; it only reacts to events. A shell that waits for
 *     `onRevoke` to resolve before ticking hands a customer handler the power
 *     to cancel a revocation by hanging, which is precisely what the drain
 *     bound exists to prevent.
 *  2. That timer must keep the process alive -- in Node, do not `unref()` it --
 *     or an idle process can exit 0 mid-drain and look like a clean shutdown in
 *     every dashboard.
 *  3. Feed `tick` at least every `MAX_CLOCK_STEP_MS`.
 *  4. Persist `core.epochFloor` after every accepted revocation and pass it
 *     back as `initialEpochFloor` on the next start. It is a required option
 *     with no default precisely so this cannot be forgotten quietly; a shell
 *     that answers `NO_PERSISTED_FLOOR` on every start has chosen to re-open a
 *     replay window at every restart.
 *  5. Do not call `SluiceCore.handle` synchronously from inside a host
 *     callback. The core is reentrant-safe in the sense that no invariant
 *     breaks, but a nested `applyDecisions` can reach `exit` while the outer
 *     loop is still running, and the once-only guard below is per call. Queue
 *     the event instead.
 *
 * None of this can be enforced from here, so it is written where the shell
 * author will be reading.
 */
export function applyDecisions(host: SluiceHost, decisions: readonly SluiceDecision[]): void {
  let exited = false;
  for (const decision of decisions) {
    switch (decision?.type) {
      case "log":
        guard(host, () => host.log(decision.level, decision.code, decision.message));
        break;
      case "metric":
        guard(host, () => host.metric(decision.name, decision.value));
        break;
      case "apply-secrets":
        guard(host, () => host.applySecrets?.(decision.bundle, decision.changed, decision.removed));
        break;
      case "refetch":
        guard(host, () => host.refetch?.(decision.epoch));
        break;
      case "shutdown":
        // `reason` here is the SANITISED text. `signedReason` is deliberately
        // not passed on: a host that wants the exact signed bytes can read them
        // off the decision itself, and that has to be a conscious choice rather
        // than the default path to a log line.
        guard(host, () => host.beginDrain?.(decision.reason, decision.drainMs));
        break;
      case "exit":
      case "fail-to-start":
        // Not wrapped, and at most once. A second call would be a second
        // `process.exit` in a shell that somehow returned from the first.
        if (!exited) {
          exited = true;
          host.exit(decision.code);
        }
        break;
      default:
        break;
    }
  }
}

/**
 * Runs a host callback and refuses to let it stop the loop.
 *
 * The failure is reported through `host.log`, itself guarded, because a host
 * whose logger throws is the case this exists for.
 */
function guard(host: SluiceHost, effect: () => void): void {
  try {
    effect();
  } catch (error) {
    try {
      host.log("error", "host-callback-failed", `a Sluice host callback threw: ${String(error)}`);
    } catch {
      // Nothing left to report through. Keep going: the exit still matters.
    }
  }
}
