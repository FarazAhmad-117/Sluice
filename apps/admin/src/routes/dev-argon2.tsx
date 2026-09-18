import { useCallback, useState } from "react";
import { ARGON2_PARAMS, deriveMUK, toHex } from "@sluice/crypto";
import { wasmArgon2 } from "@/lib/crypto/argon2-wasm";
import {
  DerivationBusyError,
  deriveMasterUnlockKey,
  probeDerivationCapability,
} from "@/lib/crypto/derive";

/**
 * THE ARGON2 MEASUREMENT HARNESS.
 *
 * This page exists because "the Worker frees the main thread" is a claim, and a
 * claim about browser responsiveness that has only been checked in Node is not
 * evidence.
 *
 * THE TECHNIQUE IS THE ONE THAT CAUGHT `argon2idAsync`. A `setInterval` at 20 ms
 * runs for the length of each derivation and its callbacks are counted. Zero
 * ticks means the thread never reached the task queue: no paint, no input, no
 * progress bar. `argon2idAsync` scores zero here despite its name, because its
 * yield point is an empty async function and microtasks drain before rendering.
 * A Worker-based derivation should score close to `elapsed / 20`.
 *
 * NO REAL PASSWORD IS USED. The input is the pinned known-answer vector from
 * `packages/crypto/test/muk.test.ts`, which is published in the repository and
 * in this file. Nothing here touches a user secret, so the derived value is
 * printed in full -- which would be an unforgivable thing to do with a real one.
 *
 * THIS FILE IS NOT IN A PRODUCTION BUILD. The Next version gated it in a layout
 * that called `notFound()` when `NODE_ENV` was production, which made the route
 * unreachable while leaving the component in the bundle. `routes.tsx` now only
 * reaches it through a dynamic `import()` inside an `import.meta.env.DEV`
 * branch, which Rollup folds away, so there is nothing here to find in a
 * deployed build. Do not import this module from anywhere else: a static import
 * would put it straight back.
 *
 * ONE PROPERTY THIS PAGE USED TO CARRY AND NO LONGER DOES. Under Next it was
 * the only module that reached the derivation worker, which is what forced
 * `next build` to compile and emit it -- a worker nothing references is a
 * worker whose bundling has never been proven. Vite emits the worker from the
 * `new Worker(new URL(...))` call in `lib/crypto/derive.ts` on its own, so that
 * coverage does not depend on this page existing. It is worth knowing, because
 * it means a broken worker build will now show up at sign-in rather than here.
 */

/** The published test vector. Not a secret, and deliberately not user input. */
const KAT_PASSWORD = "correct horse battery staple";
const KAT_USER_ID = "u1";
const KAT_MUK = "dfee4c58ca2653a1b5ae9a64cd3743c1cb33b26f2a6a537715f26e84cfd5b588";

const TICK_MS = 20;

interface Measurement {
  readonly label: string;
  readonly elapsedMs: number;
  readonly ticks: number;
  readonly expectedTicks: number;
  readonly muk: string;
  readonly correct: boolean;
}

/**
 * Runs `work` with a 20 ms heartbeat and reports how many beats got through.
 *
 * The interval is started and the first tick is awaited before the work begins,
 * so a timer that had not yet armed cannot be mistaken for a blocked thread.
 */
async function measure(label: string, work: () => Promise<Uint8Array>): Promise<Measurement> {
  let ticks = 0;
  const handle = setInterval(() => {
    ticks++;
  }, TICK_MS);
  // Let the interval arm and the browser paint the "running" state, so the
  // count below measures the derivation and not the render before it.
  await new Promise((resolve) => setTimeout(resolve, 100));
  ticks = 0;

  const started = performance.now();
  let bytes: Uint8Array;
  try {
    bytes = await work();
  } finally {
    clearInterval(handle);
  }
  const elapsedMs = performance.now() - started;
  const muk = toHex(bytes);

  return {
    label,
    elapsedMs,
    ticks,
    expectedTicks: Math.floor(elapsedMs / TICK_MS),
    muk,
    // Every route must produce the SAME key. A fast route that produced a
    // different one would be a catastrophe wearing a performance win.
    correct: muk === KAT_MUK,
  };
}

export default function Argon2DiagnosticsRoute() {
  const [rows, setRows] = useState<Measurement[]>([]);
  const [status, setStatus] = useState<string>("idle");
  const [busy, setBusy] = useState(false);

  const run = useCallback(async () => {
    setBusy(true);
    setRows([]);
    try {
      setStatus("probing device capability...");
      const capability = await probeDerivationCapability();
      setStatus(
        `worker=${capability.workerAvailable} memory64MiB=${capability.memoryAvailable} ` +
          `wasm=${capability.wasmUsable}` +
          (capability.reasons.length ? ` | ${capability.reasons.join("; ")}` : ""),
      );

      const results: Measurement[] = [];

      setStatus((s) => `${s} | running worker + WASM...`);
      results.push(
        await measure("WASM in Web Worker", async () => {
          const result = await deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID);
          if (result.path !== "worker-wasm") {
            throw new Error(`fell back to ${result.path}: ${JSON.stringify(result.degradations)}`);
          }
          return result.key.bytes;
        }),
      );
      setRows([...results]);

      setStatus((s) => `${s} | running WASM on main thread...`);
      results.push(
        await measure("WASM on main thread", async () => {
          const key = await deriveMUK(KAT_PASSWORD, KAT_USER_ID, { argon2: wasmArgon2 });
          return key.bytes;
        }),
      );
      setRows([...results]);

      setStatus((s) => `${s} | running noble on main thread (this will freeze the tab)...`);
      // Yield first, so the status above is actually painted before the thread
      // is taken away for several seconds.
      await new Promise((resolve) => setTimeout(resolve, 50));
      results.push(
        await measure("noble (pure JS) on main thread", async () => {
          const key = await deriveMUK(KAT_PASSWORD, KAT_USER_ID);
          return key.bytes;
        }),
      );
      setRows([...results]);
      setStatus("done");
    } catch (cause) {
      setStatus(`failed: ${cause instanceof Error ? cause.message : String(cause)}`);
    } finally {
      setBusy(false);
    }
  }, []);

  /**
   * Proves the single-flight guard from the UI, since a double-clicked submit
   * button is exactly how two concurrent 64 MiB allocations happen.
   */
  const runDoubleClick = useCallback(async () => {
    setBusy(true);
    try {
      const a = deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID);
      const b = deriveMasterUnlockKey(KAT_PASSWORD, KAT_USER_ID);
      let differentInputs = "no error";
      try {
        deriveMasterUnlockKey("a different password", KAT_USER_ID);
      } catch (cause) {
        differentInputs = cause instanceof DerivationBusyError ? "DerivationBusyError" : "other";
      }
      const [ra, rb] = await Promise.all([a, b]);
      setStatus(
        `double click: same promise = ${a === b}; ` +
          `same key = ${toHex(ra.key.bytes) === toHex(rb.key.bytes)}; ` +
          `concurrent different inputs -> ${differentInputs}`,
      );
    } finally {
      setBusy(false);
    }
  }, []);

  return (
    <main style={{ padding: 32, fontFamily: "ui-monospace, monospace", lineHeight: 1.6 }}>
      <h1>Argon2id derivation diagnostics</h1>
      <p>
        m={ARGON2_PARAMS.m} KiB, t={ARGON2_PARAMS.t}, p={ARGON2_PARAMS.p}, dkLen=
        {ARGON2_PARAMS.dkLen}. Every row below must produce the same key; a {TICK_MS}ms timer runs
        throughout and <strong>zero ticks means the thread was blocked</strong>.
      </p>
      <p>
        <button type="button" onClick={run} disabled={busy} style={{ padding: "8px 16px" }}>
          Run measurements
        </button>{" "}
        <button
          type="button"
          onClick={runDoubleClick}
          disabled={busy}
          style={{ padding: "8px 16px" }}
        >
          Simulate double click
        </button>
      </p>
      <p id="status">status: {status}</p>
      <table id="results" cellPadding={8} style={{ borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <th align="left">route</th>
            <th align="right">wall ms</th>
            <th align="right">timer ticks</th>
            <th align="right">expected</th>
            <th align="left">key matches vector</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label} style={{ borderTop: "1px solid #888" }}>
              <td>{r.label}</td>
              <td align="right">{Math.round(r.elapsedMs)}</td>
              <td align="right">{r.ticks}</td>
              <td align="right">{r.expectedTicks}</td>
              <td>{r.correct ? "yes" : `NO (${r.muk})`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
