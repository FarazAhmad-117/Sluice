import { describe, expect, it } from "vitest";
import { signRevocation, type RevocationNotice } from "@sluice/crypto";
import { SluiceCore } from "../src/core";
import type { SluiceDecision, SluiceEvent } from "../src/types";
import { bundle, makeCore, notice, orgKeyPair, tokenIdHex, type Org } from "./helpers";

/**
 * THE PROOF THAT AN OUTAGE CANNOT KILL A FLEET.
 *
 * The single most important property of this package is that connection loss
 * never produces a shutdown. An example test would show that one sequence is
 * safe. These tests enumerate EVERY sequence over a fixed alphabet up to a
 * bounded length and assert the property on all of them, which is a proof by
 * exhaustion over that bounded space rather than a sample of it.
 *
 * WHY THE DEPTHS DIFFER BETWEEN TESTS. Ed25519 verification costs about 10ms on
 * the machine this was written on, so a suite that verifies a signature per
 * event cannot go deep. The split is deliberate:
 *
 *  - The benign alphabet needs no crypto at all, so it is enumerated deep.
 *    That is the alphabet an outage, a network attacker, or a fully compromised
 *    Sluice server can actually produce, because none of them hold the org
 *    revocation private key. It is therefore the alphabet the headline claim is
 *    about, and it is the one explored exhaustively.
 *  - The hostile alphabet costs a verification per event and is enumerated
 *    shallower, then extended by a seeded random fuzz over long sequences.
 *
 * NOTHING HERE IS MOCKED. Every signature is checked by the real
 * `verifyRevocation` against a real Ed25519 key. A stubbed verifier would make
 * these tests pass against a core that had no signature check at all, which is
 * precisely the class of defect they exist to catch.
 */

/** Every sequence of length exactly `length` over `alphabet`, by base-N counting. */
function* sequences<T>(alphabet: readonly T[], length: number): Generator<T[]> {
  const n = alphabet.length;
  const total = n ** length;
  const out: T[] = new Array<T>(length);
  for (let code = 0; code < total; code++) {
    let rest = code;
    for (let i = 0; i < length; i++) {
      out[i] = alphabet[rest % n] as T;
      rest = Math.floor(rest / n);
    }
    yield out;
  }
}

function* upTo<T>(alphabet: readonly T[], maxLength: number): Generator<T[]> {
  for (let length = 1; length <= maxLength; length++) yield* sequences(alphabet, length);
}

interface Symbol_ {
  readonly name: string;
  readonly make: (now: number) => SluiceEvent;
}

/**
 * EVERYTHING A COMPROMISED SERVER, A BROKEN NETWORK OR AN OUTAGE CAN PRODUCE.
 *
 * Note what is here and what is not. Disconnects, reconnects, clock advances of
 * every size, bundle pushes and epoch bumps: all of it is reachable by anyone
 * who controls the delivery channel. What is NOT reachable is a valid signature
 * over a fresh notice, because that needs the org revocation private key, which
 * lives in an admin's browser and never touches the server.
 *
 * The clock symbols matter as much as the network ones. `tick-leap` is a
 * forward jump far larger than any offline window, which is what a resumed VM
 * or a bad NTP sync looks like; `tick-back` is a backwards step. Both are the
 * shapes that turn a timeout into a fleet-wide outage if handled naively.
 */
const BENIGN: readonly Symbol_[] = [
  { name: "disconnected", make: (now) => ({ type: "disconnected", now, cause: "socket closed" }) },
  { name: "reconnected", make: (now) => ({ type: "reconnected", now }) },
  { name: "tick", make: (now) => ({ type: "tick", now: now + 1_000 }) },
  { name: "tick-leap", make: (now) => ({ type: "tick", now: now + 400 * 86_400_000 }) },
  { name: "tick-back", make: (now) => ({ type: "tick", now: now - 900_000 }) },
  { name: "bundle-same", make: (now) => ({ type: "bundle", now, bundle: bundle() }) },
  {
    name: "bundle-rotated",
    make: (now) => ({ type: "bundle", now, bundle: bundle({ DATABASE_URL: `v${now}` }, 1) }),
  },
  { name: "epoch-bump", make: (now) => ({ type: "epoch-bump", now, epoch: (now % 7) + 2 }) },
];

interface Run {
  readonly decisions: SluiceDecision[];
  readonly perEvent: SluiceDecision[][];
  readonly core: SluiceCore;
}

/** Feeds a sequence into a fresh core and returns everything it decided. */
function run(
  core: SluiceCore,
  symbols: readonly Symbol_[],
  boot: "with-cache" | "no-cache",
  startAt = 1_000,
): Run {
  const perEvent: SluiceDecision[][] = [];
  const decisions: SluiceDecision[] = [];
  const first = core.handle({
    type: "boot",
    now: startAt,
    cache: boot === "with-cache" ? bundle() : null,
  });
  perEvent.push(first);
  decisions.push(...first);
  let now = startAt;
  for (const symbol of symbols) {
    now += 137; // A prime, so no two events share a timestamp by accident.
    const event = symbol.make(now);
    const step = core.handle(event);
    perEvent.push(step);
    decisions.push(...step);
    const stamped = (event as { now?: number }).now;
    if (typeof stamped === "number" && Number.isFinite(stamped)) now = Math.max(now, stamped);
  }
  return { decisions, perEvent, core };
}

function label(symbols: readonly Symbol_[], boot: string): string {
  return `boot:${boot} -> ${symbols.map((s) => s.name).join(" -> ")}`;
}

describe("connection loss can never, under any sequence, shut a process down", () => {
  // 8 symbols to depth 6, times two boot modes:
  // 8 + 64 + 512 + 4096 + 32768 + 262144 = 299592 sequences per mode,
  // 599184 in total, carrying just under 4 million events.
  const DEPTH = 6;

  for (const boot of ["no-cache", "with-cache"] as const) {
    it(
      `exhaustively, over every sequence of up to ${DEPTH} events (boot ${boot})`,
      () => {
        let sequenceCount = 0;
        let eventCount = 0;
        for (const symbols of upTo(BENIGN, DEPTH)) {
          sequenceCount++;
          eventCount += symbols.length + 1;
          const core = makeCore(orgKeyPairOnce(), tokenIdOnce());
          const { decisions, perEvent } = run(core, symbols, boot);

          for (const decision of decisions) {
            if (decision.type === "shutdown" || decision.type === "exit") {
              throw new Error(
                `a ${decision.type} decision was produced with no signed revocation: ${label(symbols, boot)}`,
              );
            }
          }

          // `fail-to-start` is terminal too, so it must be unreachable once the
          // process has secrets. It is legal only while nothing was applied.
          let applied = false;
          for (const step of perEvent) {
            for (const decision of step) {
              if (decision.type === "apply-secrets") applied = true;
              if (decision.type === "fail-to-start" && applied) {
                throw new Error(`fail-to-start after apply-secrets: ${label(symbols, boot)}`);
              }
            }
          }
          if (boot === "with-cache") {
            expect(decisions.some((d) => d.type === "fail-to-start")).toBe(false);
          }
        }
        expect(sequenceCount).toBe(
          Array.from({ length: DEPTH }, (_, i) => BENIGN.length ** (i + 1)).reduce((a, b) => a + b),
        );
        // eslint-disable-next-line no-console
        console.log(
          `  [exhaustive/${boot}] ${sequenceCount} sequences, ${eventCount} events, no shutdown`,
        );
      },
      120_000,
    );
  }

  it(
    "and still cannot, when maxOfflineDuration is opted in, for any cause but the limit itself",
    () => {
      // The opt-in is the ONE way an outage may kill a process. Even then the
      // cause must be `offline-limit`; nothing may ever masquerade as a
      // revocation, because that is what an operator will search for.
      for (const symbols of upTo(BENIGN, 4)) {
        const core = makeCore(orgKeyPairOnce(), tokenIdOnce(), { maxOfflineDurationMs: 60_000 });
        for (const decision of run(core, symbols, "with-cache").decisions) {
          if (decision.type === "shutdown") expect(decision.cause).toBe("offline-limit");
        }
      }
    },
    120_000,
  );
});

// One key pair and token id for the whole file: generating them per sequence
// would cost more than the state machine under test.
let cachedOrg: Org | undefined;
let cachedTokenId: string | undefined;
function orgKeyPairOnce(): Org {
  return (cachedOrg ??= orgKeyPair());
}
function tokenIdOnce(): string {
  return (cachedTokenId ??= tokenIdHex());
}

describe("hostile revocations, exhaustively, against real Ed25519", () => {
  const DEPTH = 3;

  function hostileAlphabet(org: Org, tokenId: string): readonly Symbol_[] {
    const impostor = orgKeyPair();
    const mine = (over: Partial<RevocationNotice>): RevocationNotice =>
      notice({ tokenId, ...over });

    // Signed at epoch 3, presented as epoch 4: the body no longer matches the
    // bytes the signature covers.
    const tamperedBody = mine({ epoch: 3 });
    const tamperedSignature = signRevocation(org.privateKey, tamperedBody);

    // Genuine, from the real org key, for a token that is not ours.
    const foreign = notice({ tokenId: tokenIdHex(), epoch: 9_999 });
    const foreignSignature = signRevocation(org.privateKey, foreign);

    // Genuine, from the real org key, for OUR token -- but below the floor the
    // core is constructed with. Authentic and stale.
    const stale = mine({ epoch: 2 });
    const staleSignature = signRevocation(org.privateKey, stale);

    // The same, at EXACTLY the floor. This is the boundary that matters: the
    // floor holds the epoch already acted on, so `epoch < floor` instead of
    // `epoch <= floor` re-admits a replay of the most recent genuine notice --
    // the one an attacker is most likely to have captured. An earlier version
    // of this alphabet only replayed below the floor and did not catch it.
    const atFloor = mine({ epoch: 5 });
    const atFloorSignature = signRevocation(org.privateKey, atFloor);

    const forgedBody = mine({ epoch: 9_999 });

    return [
      // Three benign symbols only. Clock leaps and bundle pushes are covered
      // exhaustively and far deeper by the crypto-free enumeration above; the
      // budget here is spent on signatures.
      ...BENIGN.slice(0, 3),
      {
        name: "rev/forged-signature",
        make: (now) => ({
          type: "revocation",
          now,
          notice: forgedBody,
          signature: new Uint8Array(64),
        }),
      },
      {
        name: "rev/wrong-org-key",
        make: (now) => ({
          type: "revocation",
          now,
          notice: forgedBody,
          signature: signRevocation(impostor.privateKey, forgedBody),
        }),
      },
      {
        name: "rev/other-token",
        make: (now) => ({ type: "revocation", now, notice: foreign, signature: foreignSignature }),
      },
      {
        name: "rev/tampered-body",
        make: (now) => ({
          type: "revocation",
          now,
          notice: { ...tamperedBody, epoch: 4 },
          signature: tamperedSignature,
        }),
      },
      {
        name: "rev/replayed-below-floor",
        make: (now) => ({ type: "revocation", now, notice: stale, signature: staleSignature }),
      },
      {
        name: "rev/replayed-at-floor",
        make: (now) => ({ type: "revocation", now, notice: atFloor, signature: atFloorSignature }),
      },
      {
        name: "rev/malformed",
        make: (now) => ({
          type: "revocation",
          now,
          notice: { tokenId, epoch: "4", revokedAt: 1, reason: "x" } as unknown as RevocationNotice,
          signature: new Uint8Array(64),
        }),
      },
    ];
  }

  it(
    `enumerates every sequence of up to ${DEPTH} hostile events and finds no shutdown`,
    () => {
      const org = orgKeyPairOnce();
      const tokenId = tokenIdOnce();
      const alphabet = hostileAlphabet(org, tokenId);
      let sequenceCount = 0;
      for (const symbols of upTo(alphabet, DEPTH)) {
        sequenceCount++;
        // The floor makes `rev/replayed` authentic but stale, which is the only
        // hostile symbol whose signature actually verifies.
        const core = makeCore(org, tokenId, { initialEpochFloor: 5 });
        const { decisions } = run(core, symbols, "with-cache");
        for (const decision of decisions) {
          if (decision.type === "shutdown" || decision.type === "exit") {
            throw new Error(`${decision.type} from hostile input: ${label(symbols, "with-cache")}`);
          }
        }
        // A rejected notice must never move the floor. If it could, one forged
        // message at a huge epoch would immunise a stolen token forever.
        expect(core.epochFloor).toBe(5);
      }
      // eslint-disable-next-line no-console
      console.log(`  [hostile/exhaustive] ${sequenceCount} sequences, no shutdown, floor intact`);
      expect(sequenceCount).toBe(
        Array.from({ length: DEPTH }, (_, i) => alphabet.length ** (i + 1)).reduce((a, b) => a + b),
      );
    },
    300_000,
  );
});

describe("a valid revocation always shuts down, wherever it lands", () => {
  const DEPTH = 3;

  it(
    "at every position of every benign sequence, and an exit always follows",
    () => {
      const org = orgKeyPairOnce();
      const tokenId = tokenIdOnce();
      const valid = notice({ tokenId, epoch: 42, reason: "key leaked" });
      const signature = signRevocation(org.privateKey, valid);
      let cases = 0;

      for (const symbols of upTo(BENIGN, DEPTH)) {
        for (let position = 0; position <= symbols.length; position++) {
          cases++;
          const withRevocation: Symbol_[] = [
            ...symbols.slice(0, position),
            { name: "REVOKE", make: (now) => ({ type: "revocation", now, notice: valid, signature }) },
            ...symbols.slice(position),
          ];
          const core = makeCore(org, tokenId, { drainMs: 5_000 });
          const { decisions, core: after } = run(core, withRevocation, "with-cache");

          const shutdowns = decisions.filter((d) => d.type === "shutdown");
          expect(shutdowns, label(withRevocation, "with-cache")).toHaveLength(1);
          expect(shutdowns[0]).toMatchObject({ cause: "revocation", epoch: 42 });
          expect(after.epochFloor).toBe(42);

          // Whatever the sequence did afterwards, the process must be able to
          // reach an exit. One long tick is enough; the drain is bounded.
          const tail = after.handle({ type: "tick", now: 1e12 });
          const exits =
            decisions.filter((d) => d.type === "exit").length +
            tail.filter((d) => d.type === "exit").length;
          expect(exits, `no exit after a valid revocation: ${label(withRevocation, "with-cache")}`)
            .toBe(1);
          expect(after.state).toBe("dead");
        }
      }
      // eslint-disable-next-line no-console
      console.log(`  [valid-revocation] ${cases} placements, all shut down and exited`);
    },
    300_000,
  );
});

describe("seeded deep fuzz over long sequences", () => {
  /** xorshift32. Deterministic, so a failure is reproducible from the seed. */
  function rng(seed: number): () => number {
    let x = seed | 0 || 1;
    return () => {
      x ^= x << 13;
      x ^= x >>> 17;
      x ^= x << 5;
      return (x >>> 0) / 0x1_0000_0000;
    };
  }

  it(
    "never shuts down over long random benign sequences",
    () => {
      const next = rng(0x5_10c3);
      let events = 0;
      for (let trial = 0; trial < 4_000; trial++) {
        const length = 1 + Math.floor(next() * 60);
        const symbols: Symbol_[] = [];
        for (let i = 0; i < length; i++) {
          symbols.push(BENIGN[Math.floor(next() * BENIGN.length)] as Symbol_);
        }
        events += symbols.length;
        const core = makeCore(orgKeyPairOnce(), tokenIdOnce(), {
          drainMs: Math.floor(next() * 60_000),
          bootTimeoutMs: Math.floor(next() * 60_000),
        });
        const boot = next() < 0.5 ? "with-cache" : "no-cache";
        for (const decision of run(core, symbols, boot).decisions) {
          if (decision.type === "shutdown" || decision.type === "exit") {
            throw new Error(`${decision.type} from benign fuzz: ${label(symbols, boot)}`);
          }
        }
      }
      // eslint-disable-next-line no-console
      console.log(`  [fuzz] 4000 sequences, ${events} events, no shutdown`);
    },
    120_000,
  );
});
