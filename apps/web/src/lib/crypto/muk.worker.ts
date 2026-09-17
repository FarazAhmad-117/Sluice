/// <reference lib="webworker" />

import { ARGON2_PARAMS, deriveMUK } from "@sluice/crypto";
import { probeArgon2Memory, wasmArgon2 } from "./argon2-wasm";
import type { WorkerRequest, WorkerResponse } from "./worker-protocol";

/**
 * THE MASTER UNLOCK KEY WORKER.
 *
 * This thread exists for two reasons, and only the first is about speed.
 *
 * 1. Argon2id at the tuned parameters holds its thread for the entire
 *    derivation. On the main thread that is a frozen tab: no paint, no input,
 *    no progress bar, no cancel. Measured at 5460 ms with the pure-JS backend
 *    and 434 ms with this WASM one on a desktop x64, and a mid-range phone runs
 *    four to ten times slower than that. `argon2idAsync` does NOT help and must
 *    not be substituted: its yield point is an empty async function, so it
 *    drains as a microtask, and microtasks run BEFORE rendering and before
 *    input. Measured: zero 20 ms timer callbacks during 7.5 seconds of it.
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
 * Answers the memory question without being asked, as soon as the module runs.
 *
 * The main thread wants to know whether 64 MiB is available BEFORE the user has
 * typed a password, and the cheapest moment to find out is while the worker is
 * warming up anyway. `id: 0` is reserved for this unsolicited report; every
 * request the main thread makes uses a positive id.
 */
const result = probeArgon2Memory(ARGON2_PARAMS.m);
post(
  result.ok
    ? { kind: "probed", id: 0, ok: true }
    : { kind: "probed", id: 0, ok: false, reason: result.reason },
);
