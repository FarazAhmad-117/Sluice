import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { fromHex, randomBytes, toHex } from "@sluice/crypto";
import type {
  DeriveRequest,
  WorkerRequest,
  WorkerResponse,
} from "../src/lib/crypto/worker-protocol";

/**
 * THE MAIN-THREAD / WORKER BOUNDARY, EXERCISED FOR REAL.
 *
 * `derive-fallback.test.ts` proves what happens when there is NO worker. This
 * file proves the other half: what actually crosses `postMessage` when there
 * is one, and what the worker does with it. Node has no `Worker`, so both ends
 * are wired in-process -- a fake `Worker` class on the main side, a fake
 * `DedicatedWorkerGlobalScope` on the worker side -- and every message goes
 * through `structuredClone`, which is the exact transformation a real
 * `postMessage` applies. The REAL `muk.worker.ts` module is loaded and the REAL
 * `derive.ts` drives it; only the transport is simulated.
 *
 * THE PROPERTIES PINNED HERE:
 *
 *  - The salt crosses as LOWERCASE HEX under `accountSalt`. Not a `Uint8Array`
 *    (it would clone fine today, but a string is what the protocol states and
 *    what nothing can transfer-detach out from under the caller), and not the
 *    v1 `userId` field, whose return would mean the email is a salt again.
 *  - The WORKER decodes it and `deriveMUK` enforces the 16-byte width. The
 *    worker does not trust the main thread to have checked.
 *  - A salt of the right width derives, WHATEVER its bytes. The server's decoy
 *    for an unknown address is also 16 bytes, so it passes the same check and
 *    cannot be told apart from a real salt by anything this client does with
 *    it; the account's existence is settled only by `login` failing.
 */

const KAT_PASSWORD = "correct horse battery staple, v2";
const KAT_ACCOUNT_SALT_HEX = "303132333435363738393a3b3c3d3e3f";
const KAT_MUK = "633977bb9b6fec724f6574028da06c834895735198e653c3f8a95cb28d70436c";
const BUDGET_MS = 600_000;

/** Every request the fake main-thread `Worker` sent, after structured clone. */
const sent: WorkerRequest[] = [];

/** Where the worker's next `postMessage` is delivered. */
let deliver: ((response: WorkerResponse) => void) | null = null;

/** The worker-side scope. The real worker module installs `onmessage` on it. */
const scope: {
  onmessage: ((event: MessageEvent<WorkerRequest>) => unknown) | null;
  postMessage: (response: WorkerResponse, transfer?: Transferable[]) => void;
} = {
  onmessage: null,
  postMessage(response, transfer) {
    // `structuredClone` with a transfer list detaches the worker's buffer just
    // as the real thing does, so a worker that kept using it would fail here.
    const cloned = structuredClone(response, transfer ? { transfer } : undefined);
    deliver?.(cloned);
  },
};

function sendToWorker(request: WorkerRequest): void {
  const cloned = structuredClone(request);
  queueMicrotask(() => {
    void scope.onmessage?.({ data: cloned } as MessageEvent<WorkerRequest>);
  });
}

/** Talks to the worker module directly, bypassing `derive.ts`. */
function askWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve) => {
    deliver = resolve;
    sendToWorker(request);
  });
}

class FakeWorker {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  terminated = false;

  postMessage(request: WorkerRequest): void {
    sent.push(structuredClone(request));
    deliver = (response) => {
      if (!this.terminated) this.onmessage?.({ data: response } as MessageEvent<WorkerResponse>);
    };
    sendToWorker(request);
  }

  terminate(): void {
    this.terminated = true;
  }
}

let deriveMasterUnlockKey: typeof import("../src/lib/crypto/derive").deriveMasterUnlockKey;

beforeAll(async () => {
  vi.stubGlobal("self", scope);
  vi.stubGlobal("Worker", FakeWorker);
  // Imported AFTER the stubs: the worker module binds `self` at load, and
  // `derive.ts` reads `Worker` when it constructs one.
  await import("../src/lib/crypto/muk.worker");
  ({ deriveMasterUnlockKey } = await import("../src/lib/crypto/derive"));
  expect(scope.onmessage).toBeTypeOf("function");
});

afterAll(() => {
  vi.unstubAllGlobals();
});

describe("derive.ts through the worker", () => {
  it("sends the salt as lowercase hex under accountSalt and gets the v2 key back", async () => {
    sent.length = 0;
    const result = await deriveMasterUnlockKey(KAT_PASSWORD, fromHex(KAT_ACCOUNT_SALT_HEX));

    expect(result.path).toBe("worker-wasm");
    expect(result.degradations).toEqual([]);
    expect(toHex(result.key.bytes)).toBe(KAT_MUK);

    expect(sent).toHaveLength(1);
    const request = sent[0] as DeriveRequest;
    expect(request.kind).toBe("derive");
    expect(request.accountSalt).toBe(KAT_ACCOUNT_SALT_HEX);
    expect(request.accountSalt).toMatch(/^[0-9a-f]{32}$/);
    // Exactly these fields cross. In particular no `userId`: its presence would
    // mean some caller is still salting with the address.
    expect(Object.keys(request).sort()).toEqual(["accountSalt", "id", "kind", "password"]);
  }, BUDGET_MS);
});

describe("the worker on its own", () => {
  /**
   * The width check is the WORKER's, through `deriveMUK`, not something it
   * assumes the main thread did. A crafted or corrupted message is refused
   * with the package's own message and no key is produced.
   */
  it.each([
    ["15 bytes", "30".repeat(15)],
    ["17 bytes", "30".repeat(17)],
    ["empty", ""],
  ])("refuses a %s salt through deriveMUK's own check", async (_label, accountSalt) => {
    const response = await askWorker({ kind: "derive", id: 7, password: KAT_PASSWORD, accountSalt });
    expect(response).toEqual({
      kind: "failed",
      id: 7,
      message: "accountSalt must be 16 bytes",
    });
  });

  it("refuses a salt that is not hex, without echoing it", async () => {
    const response = await askWorker({
      kind: "derive",
      id: 8,
      password: KAT_PASSWORD,
      accountSalt: "zz".repeat(16),
    });
    expect(response.kind).toBe("failed");
    expect(response.kind === "failed" && response.message).toMatch(/hex/);
    expect(response.kind === "failed" && response.message).not.toContain("zz");
  });

  /**
   * ANY sixteen bytes derive. This is the decoy case: for an address with no
   * account the server returns a salt of the same width and alphabet, and the
   * client must spend the same Argon2 run on it as on a real one. A worker that
   * refused, or a check that could tell the two apart by shape, would turn the
   * salt lookup back into an account-existence oracle on the client side.
   */
  it("derives under any 16-byte salt, which is what a decoy is", async () => {
    const decoyShaped = toHex(randomBytes(16));
    const response = await askWorker({
      kind: "derive",
      id: 9,
      password: KAT_PASSWORD,
      accountSalt: decoyShaped,
    });
    expect(response.kind).toBe("derived");
    if (response.kind !== "derived") return;
    expect(response.bytes).toHaveLength(32);
    expect(toHex(response.bytes)).not.toBe(KAT_MUK);
  }, BUDGET_MS);
});
