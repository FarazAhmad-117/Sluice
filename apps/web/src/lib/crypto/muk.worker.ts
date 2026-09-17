/// <reference lib="webworker" />

import { deriveMUK } from "@sluice/crypto";
import { probeArgon2Memory, wasmArgon2 } from "./argon2-wasm";
import type { WorkerRequest, WorkerResponse } from "./worker-protocol";

/**
 * THE MASTER UNLOCK KEY WORKER.
 *
 * This thread exists for two reasons, and only the first is about speed.
 *
 * 1. Argon2id at the tuned parameters holds its thread for the entire
 *    derivation. On the main thread that is a frozen tab: no paint, no input,
 *    no progress bar, no cancel. MEASURED IN CHROME 152 on a desktop x64, with
 *    a 20 ms timer running throughout and the page visible:
 *
 *      noble on the main thread    8431 ms,  0 timer ticks of 421 expected
 *      WASM on the main thread      680 ms,  0 timer ticks of  33 expected
 *      WASM in THIS worker         1585 ms, 79 timer ticks of  79 expected
 *
 *    The worker row is the whole point: the tab answered on schedule for the
 *    entire derivation. The two main-thread rows did not answer once.
 *
 *    A mid-range phone runs four to ten times slower again. `argon2idAsync`
 *    does NOT help and must not be substituted: its yield point is an empty
 *    async function, so it drains as a microtask, and microtasks run BEFORE
 *    rendering and before input. Measured: 8506 ms and zero ticks, against
 *    7685 ms and zero ticks for the plain synchronous call.
 *
 * 2. `m = 65536` asks for 64 MiB of contiguous memory. On iOS Safari a request
 *    like that can kill the TAB. Here it kills a worker, which arrives on the
 *    main thread as a catchable error with the user's page, session and typed
 *    form still intact.
 *
 * ONE DERIVATION, THEN DEATH. The main thread terminates this worker after each
 * request. That is deliberate rather than wasteful: noble and hash-wasm both
 * leave the 64 MiB Argon2 working buffer unzeroed, and its final blocks are the
 * MUK in recoverable form. JavaScript offers no way to scrub it. Ending the
 * thread is the only thing that reliably does, and it also means the cleartext
 * password copy that structured clone made in this heap does not outlive the
 * call. Startup cost is a few milliseconds, paid at most twice per session.
 *
 * NOTHING HERE LOGS. Not the request, not the result, not on the error path.
 * A `console.log(event.data)` in this file would put a cleartext password into
 * the browser console and into anything that ships console output to a
 * monitoring service.
 */

const self_ = self as unknown as DedicatedWorkerGlobalScope;

function post(response: WorkerResponse, transfer?: Transferable[]): void {
  if (transfer) self_.postMessage(response, transfer);
  else self_.postMessage(response);
}

/**
 * Extracts a safe message from an unknown throw.
 *
 * Deliberately takes only `.message`, never the error object, never a stack and
 * never a `cause` chain. A structured-cloned Error can carry arbitrary own
 * properties, and an error constructed by a future library could attach the
 * input it failed on -- which here is the password.
 */
function safeMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : "unknown error in key derivation worker";
}

self_.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;

  if (request.kind === "probe") {
    const result = probeArgon2Memory(request.kib);
    post(
      result.ok
        ? { kind: "probed", id: request.id, ok: true }
        : { kind: "probed", id: request.id, ok: false, reason: result.reason },
    );
    return;
  }

  try {
    // THE PARAMETERS ARE NOT READ FROM THE MESSAGE. They come from the frozen
    // constant inside `@sluice/crypto`, so a crafted or corrupted message
    // cannot ask for a cheaper derivation. The only thing the caller controls
    // is which password and which user.
    const key = await deriveMUK(request.password, request.userId, { argon2: wasmArgon2 });

    // A COPY is posted, and the transfer detaches it on the way out. `key.bytes`
    // is the live array owned by the `MasterUnlockKey`; transferring that
    // directly would detach the instance's own buffer, leaving a
    // `MasterUnlockKey` in this heap whose 32 bytes read as zero -- a nasty
    // shape for a future refactor that decides to reuse the key here.
    const bytes = key.bytes.slice();
    post({ kind: "derived", id: request.id, bytes }, [bytes.buffer]);
  } catch (cause) {
    post({ kind: "failed", id: request.id, message: safeMessage(cause) });
  }
};

/**
 * THERE IS DELIBERATELY NO UNSOLICITED START-UP PROBE HERE, and the reason is
 * worth recording because the obvious design is actively harmful.
 *
 * An earlier version of this file ran `probeArgon2Memory(ARGON2_PARAMS.m)` at
 * module scope and posted the answer with `id: 0`, on the theory that the
 * cheapest moment to check is while the worker is warming up anyway. It was
 * wrong twice over. The main thread only ever waits for the reply to its own
 * request, so nothing read it -- and every worker the DERIVATION path spawns
 * would have allocated a 65 MiB `WebAssembly.Memory` and then immediately
 * allocated another 64 MiB for the real work. On a device near its limit, the
 * check meant to protect the user would have been the thing that pushed them
 * over it.
 *
 * The probe is now only ever run on request, by `probeDerivationCapability()`,
 * on a worker that does nothing else and is terminated before any derivation
 * starts.
 */
