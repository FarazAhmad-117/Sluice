import { ARGON2_PARAMS, MasterUnlockKey, assertConformantArgon2, deriveMUK } from "@sluice/crypto";
import { probeArgon2Memory, wasmArgon2 } from "./argon2-wasm";
import type {
  ProbeResult,
  WorkerRequest,
  WorkerRequestInit,
  WorkerResponse,
} from "./worker-protocol";

/**
 * THE BROWSER ENTRY POINT FOR MASTER UNLOCK KEY DERIVATION.
 *
 * Everything in this file is about the three ways deriving a key in a browser
 * goes wrong, none of which are cryptographic:
 *
 * - IT FREEZES THE TAB. Solved by the Worker, not by `argon2idAsync`, which
 *   yields a microtask and therefore blocks paint and input exactly as hard.
 * - IT ALLOCATES 64 MiB AT ONCE. Probed before the user commits, and confined
 *   to a worker so the failure is catchable instead of fatal to the tab.
 * - IT CAN BE STARTED TWICE. A double-clicked signup button means two
 *   concurrent 64 MiB allocations, which is how a phone kills the page.
 *   Single-flighted below.
 *
 * WHAT IS NEVER TRADED AWAY. There is no path in this file that derives at
 * anything other than `ARGON2_PARAMS`. Not on a slow device, not on a failed
 * probe, not on a fallback. Lowering `m` for weak devices would give the
 * least-protected users the weakest keys, and nothing in the stored bundle
 * records which parameters made which key, so it could never be audited or
 * undone. Every degradation here changes WHERE the work runs, never HOW MUCH
 * work it is.
 */

/** Which route actually produced the key. Returned, never inferred. */
export type DerivationPath =
  /** The intended route: WASM Argon2id on a worker thread. */
  | "worker-wasm"
  /** WASM on the main thread. Identical key, identical cost, frozen tab. */
  | "main-wasm"
  /** Pure-JS on the main thread. Identical key. Seconds of frozen tab. */
  | "main-noble";

/**
 * A degradation that actually happened, reported so it cannot pass unnoticed.
 *
 * `reason` is a message from a caught error or a probe. Nothing on this path
 * ever puts the password or the key into one; see `worker-protocol.ts`.
 */
export interface Degradation {
  readonly from: DerivationPath;
  readonly to: DerivationPath;
  readonly reason: string;
}

export interface DerivationResult {
  readonly key: MasterUnlockKey;
  readonly path: DerivationPath;
  readonly elapsedMs: number;
  /** Empty on the happy path. Non-empty means the UI owes the user a warning. */
  readonly degradations: readonly Degradation[];
}

export interface DeriveOptions {
  /**
   * Called the moment a fallback is taken, before the slow work begins, so a
   * UI can say "this may take a while" while it is still true.
   */
  readonly onDegraded?: (degradation: Degradation) => void;
  /**
   * Permits running on the main thread when no worker is available. Default
   * `true`: a user who cannot start a worker still deserves to sign in, and the
   * key they get is byte-identical. Set `false` in contexts where a frozen tab
   * is worse than a failed login.
   */
  readonly allowMainThreadFallback?: boolean;
}

/**
 * Thrown when a second derivation is requested with DIFFERENT inputs while one
 * is still running. Identical inputs are de-duplicated instead, which is what
 * makes a double-clicked button harmless.
 */
export class DerivationBusyError extends Error {
  constructor() {
    super("a master unlock key derivation is already running");
    this.name = "DerivationBusyError";
  }
}

/** Thrown when no route to a correct key is available. Never a silent result. */
export class DerivationUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerivationUnavailableError";
  }
}

/**
 * A ceiling, not a target. Its job is to guarantee the single-flight slot is
 * released and the worker is terminated even if the worker wedges -- otherwise
 * a hung derivation would pin the password in this module for the life of the
 * page, and every later attempt would get `DerivationBusyError` forever.
 *
 * Deliberately far above any plausible real derivation (about 0.4 s with WASM
 * on a desktop, a few seconds on a slow phone) so it never fires on a device
 * that is merely slow.
 */
const DERIVATION_TIMEOUT_MS = 120_000;

/** Ids start at 1, so `0` is never a legitimate reply and cannot match. */
let nextRequestId = 1;

/**
 * THE SINGLE-FLIGHT SLOT.
 *
 * ON HOLDING THE PASSWORD HERE, because it deserves an explicit defence rather
 * than a shrug: this keeps a reference to the cleartext password string for the
 * duration of one derivation. That is the same window in which the in-flight
 * call's own closure holds it, so the retention is not extended -- and the
 * `finally` below plus {@link DERIVATION_TIMEOUT_MS} bound it even if the
 * worker never answers.
 *
 * The alternative designs were both worse. Keying by a HASH of the password
 * would put a password oracle in module scope for no benefit. Keying by nothing
 * -- a plain mutex that rejects any concurrent call -- would turn an ordinary
 * double-click into an error message on a form the user has already filled in.
 * Comparing the strings directly is what makes the second click a no-op.
 */
let inFlight: {
  readonly password: string;
  readonly userId: string;
  readonly promise: Promise<DerivationResult>;
} | null = null;

function createWorker(): Worker {
  // `new URL(..., import.meta.url)` is the form both Turbopack and webpack
  // recognise as "bundle this as a worker entry". A bare string path would
  // ship a 404 at runtime instead of failing the build.
  return new Worker(new URL("./muk.worker.ts", import.meta.url), {
    type: "module",
    name: "sluice-muk",
  });
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

/**
 * Runs one request on a fresh worker and terminates it, whatever happens.
 *
 * THE WORKER IS NEVER REUSED. Its heap holds the 64 MiB Argon2 working buffer,
 * whose last blocks are the MUK in recoverable form and which no JavaScript can
 * scrub, plus the structured-clone copy of the cleartext password. Terminating
 * is the only reliable way to be rid of both.
 *
 * Three distinct failures are caught here and all of them surface as a
 * rejection rather than a hang: `new Worker` throwing (Content-Security-Policy
 * `worker-src`, or a sandboxed iframe), the worker emitting `error` (module
 * load blocked, WASM compilation refused by a CSP without `wasm-unsafe-eval`),
 * and the worker replying `failed`.
 */
function runInWorker(request: WorkerRequestInit): Promise<WorkerResponse> {
  return new Promise<WorkerResponse>((resolve, reject) => {
    const id = nextRequestId++;
    let worker: Worker;
    try {
      worker = createWorker();
    } catch (cause) {
      reject(new DerivationUnavailableError(`worker could not be started: ${messageOf(cause)}`));
      return;
    }

    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate();
      fn();
    };

    const timer = setTimeout(() => {
      finish(() =>
        reject(
          new DerivationUnavailableError(
            `key derivation did not finish within ${DERIVATION_TIMEOUT_MS} ms`,
          ),
        ),
      );
    }, DERIVATION_TIMEOUT_MS);

    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      // Anything that is not this request's answer is ignored rather than
      // mistaken for it. The worker is single-use today, so nothing else should
      // arrive -- but a reply correlated only by arrival order is how a future
      // change that batches or reuses workers resolves a derivation with a
      // memory probe, and that mistake would surface as a 32-byte "key" that
      // is not one.
      const data = event.data;
      if (data.id !== id) return;
      if (data.kind === "failed") {
        finish(() => reject(new DerivationUnavailableError(data.message)));
        return;
      }
      finish(() => resolve(data));
    };

    // `ErrorEvent.message` describes a script failure and carries no message
    // payload, so it cannot contain the password.
    worker.onerror = (event: ErrorEvent) => {
      finish(() =>
        reject(
          new DerivationUnavailableError(
            `worker failed: ${event.message || "script error"}` +
              " (a Content-Security-Policy without worker-src, or without" +
              " wasm-unsafe-eval, produces exactly this)",
          ),
        ),
      );
    };
    worker.onmessageerror = () => {
      finish(() =>
        reject(new DerivationUnavailableError("worker message could not be deserialised")),
      );
    };

    worker.postMessage({ ...request, id } as WorkerRequest);
  });
}

/**
 * Asks whether this device can do the derivation at all, BEFORE the user has
 * typed anything.
 *
 * Call it when the signup or login form mounts. If it reports a problem, say so
 * on the page. Do not wait for the user to choose a password, submit, and then
 * discover their browser cannot allocate 64 MiB -- by then an account row may
 * exist that they can never open.
 *
 * It also runs the Argon2 conformance check on the WASM backend, so a broken or
 * blocked `hash-wasm` is discovered at page load rather than at signup.
 */
export async function probeDerivationCapability(): Promise<{
  readonly workerAvailable: boolean;
  readonly memoryAvailable: boolean;
  readonly wasmUsable: boolean;
  readonly reasons: readonly string[];
}> {
  const reasons: string[] = [];

  let wasmUsable = false;
  try {
    await assertConformantArgon2(wasmArgon2);
    wasmUsable = true;
  } catch (cause) {
    reasons.push(`wasm argon2 unusable: ${messageOf(cause)}`);
  }

  let workerAvailable = false;
  let memoryAvailable = false;
  try {
    const response = (await runInWorker({ kind: "probe", kib: ARGON2_PARAMS.m })) as ProbeResult;
    workerAvailable = true;
    memoryAvailable = response.ok;
    if (!response.ok) {
      reasons.push(`64 MiB could not be allocated in a worker: ${response.reason ?? "unknown"}`);
    }
  } catch (cause) {
    reasons.push(`worker unavailable: ${messageOf(cause)}`);
    // The worker route is gone, so what matters now is whether the MAIN thread
    // can hold the allocation, since that is where the work would land.
    const local = probeArgon2Memory(ARGON2_PARAMS.m);
    memoryAvailable = local.ok;
    if (!local.ok) reasons.push(`64 MiB could not be allocated on the main thread: ${local.reason}`);
  }

  return { workerAvailable, memoryAvailable, wasmUsable, reasons };
}

async function deriveOnce(
  password: string,
  userId: string,
  options: DeriveOptions,
): Promise<DerivationResult> {
  const started = Date.now();
  const degradations: Degradation[] = [];
  const degrade = (d: Degradation) => {
    degradations.push(d);
    options.onDegraded?.(d);
  };

  // ROUTE 1: the intended one.
  try {
    const response = await runInWorker({ kind: "derive", password, userId });
    if (response.kind !== "derived") throw new DerivationUnavailableError("unexpected worker reply");
    return {
      // Re-wrapped here rather than in the worker: `MasterUnlockKey` keeps its
      // bytes in a `#private` field, which structured clone does not carry, so
      // the instance cannot cross a `postMessage` boundary. The constructor's
      // 32-byte check is what turns a mistake about that into an error rather
      // than a silent decryption failure later.
      key: new MasterUnlockKey(response.bytes),
      path: "worker-wasm",
      elapsedMs: Date.now() - started,
      degradations,
    };
  } catch (cause) {
    if (options.allowMainThreadFallback === false) throw cause;
    degrade({ from: "worker-wasm", to: "main-wasm", reason: messageOf(cause) });
  }

  // ROUTE 2: same algorithm, same parameters, same key -- on the thread that
  // paints. The tab freezes for the duration. This is a real degradation and it
  // is reported as one, never taken quietly.
  try {
    const key = await deriveMUK(password, userId, { argon2: wasmArgon2 });
    return { key, path: "main-wasm", elapsedMs: Date.now() - started, degradations };
  } catch (cause) {
    degrade({ from: "main-wasm", to: "main-noble", reason: messageOf(cause) });
  }

  // ROUTE 3: the audited pure-JS default, on the main thread. Reached only when
  // WebAssembly itself is unavailable -- a Content-Security-Policy without
  // `wasm-unsafe-eval` is the realistic cause. Same parameters, same key,
  // roughly twelve times the wall time: seconds on a desktop, most of a minute
  // on a slow phone. It exists because the alternative is a user who cannot log
  // in at all, and it is reported so nobody mistakes it for normal.
  const key = await deriveMUK(password, userId);
  return { key, path: "main-noble", elapsedMs: Date.now() - started, degradations };
}

/**
 * Derives the Master Unlock Key, once, off the main thread where possible.
 *
 * SINGLE-FLIGHTED. A second call with the SAME password and user id while one
 * is running returns the SAME promise -- a double-clicked submit button does
 * one derivation and one 64 MiB allocation, not two. A concurrent call with
 * DIFFERENT inputs throws {@link DerivationBusyError} rather than starting a
 * second allocation beside the first.
 *
 * The returned {@link DerivationResult} names the route that was actually
 * taken. A UI that ignores `path` and `degradations` will not notice that every
 * user on a particular browser is silently paying eleven seconds on the main
 * thread; a UI that reads them will.
 */
export function deriveMasterUnlockKey(
  password: string,
  userId: string,
  options: DeriveOptions = {},
): Promise<DerivationResult> {
  if (inFlight) {
    if (inFlight.password === password && inFlight.userId === userId) return inFlight.promise;
    throw new DerivationBusyError();
  }

  const promise = deriveOnce(password, userId, options).finally(() => {
    // Clears the retained password reference on every outcome, including
    // rejection and the timeout path.
    inFlight = null;
  });

  inFlight = { password, userId, promise };
  return promise;
}

/** True while a derivation is running. For disabling a submit control. */
export function isDeriving(): boolean {
  return inFlight !== null;
}
