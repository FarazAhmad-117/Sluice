import { argon2id } from "@noble/hashes/argon2";
import { toHex, utf8 } from "./bytes";

/**
 * The cost parameters handed to an Argon2id backend.
 *
 * A backend RECEIVES these; it never chooses them. `deriveMUK` passes a frozen
 * copy of {@link ARGON2_PARAMS} and nothing else, so the only way a backend can
 * run at weaker settings is by ignoring its own argument -- which is exactly
 * what {@link assertConformantArgon2} is built to catch.
 *
 * `m` is in KiB, matching the `@noble/hashes` and Argon2 reference convention.
 */
export interface Argon2Params {
  readonly m: number;
  readonly t: number;
  readonly p: number;
  readonly dkLen: number;
}

/**
 * A pluggable Argon2id implementation.
 *
 * THIS IS AN INJECTION SEAM IN SECURITY-CRITICAL CODE, AND THAT IS A FOOTGUN.
 * It exists for one reason: the pure-JS Argon2id in `@noble/hashes` takes about
 * 5.5 seconds on a warm desktop at the tuned parameters and four to ten times
 * that on a mid-range phone, and it holds the thread for all of it. The fix is
 * a WASM implementation in a Web Worker, and `@sluice/crypto` must not take a
 * WASM dependency to get there -- the package has to keep working standalone,
 * in Node, with no bundler and no `fetch` of a `.wasm` file. So the fast
 * implementation is supplied from outside.
 *
 * The seam is deliberately NOT a registry and NOT a global. There is no
 * `setArgon2Backend()`, because a global would let any module in the process
 * silently change the derivation for every later caller, and the change would
 * be invisible at the call site. A backend is passed per call, so `grep -rn
 * 'argon2:'` finds every place the default was overridden.
 *
 * WHAT THIS CANNOT DEFEND AGAINST, STATED PLAINLY. An attacker who can pass an
 * argument to `deriveMUK` is already running code in the same realm as the
 * password. They do not need this seam; they can read the input field. This
 * seam is a guard against a MISTAKE -- a mis-wired call into a WASM library, a
 * backend that quietly implements argon2i instead of argon2id, one that ignores
 * the parameters it is handed, one that returns a truncated hash -- and the
 * mitigations below are sized for that threat, not for a hostile caller.
 *
 * The contract:
 * - MUST implement Argon2id, version 0x13, at exactly the `params` given.
 * - MUST return exactly `params.dkLen` bytes.
 * - MUST NOT log, persist, or transmit `password`; it is the user's password
 *   in cleartext bytes.
 * - MAY be asynchronous, which is the entire point: a Worker round-trip is.
 */
export type Argon2Backend = (
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params,
) => Uint8Array | Promise<Uint8Array>;

/**
 * The default backend: `@noble/hashes`, audited, pure JS, zero extra
 * dependencies.
 *
 * It is synchronous and slow, and it stays the default anyway. A package whose
 * default derivation depends on a WASM binary loading correctly is a package
 * that fails closed in the wrong direction -- in a Node script, in a test
 * runner, in an SDK consumer's build -- and the failure would arrive at signup.
 *
 * The params object handed to noble is a fresh mutable copy, because the object
 * `deriveMUK` builds is frozen and a library is entitled to normalise its own
 * options in place.
 */
export const nobleArgon2: Argon2Backend = (password, salt, params) =>
  argon2id(password, salt, { m: params.m, t: params.t, p: params.p, dkLen: params.dkLen });

/**
 * CHEAP CONFORMANCE VECTORS. These run at DELIBERATELY TINY PARAMETERS.
 *
 * READ THIS BEFORE COPYING THESE NUMBERS ANYWHERE: `m: 64` is 64 KiB, one
 * thousandth of the real memory cost, and `t: 1` is a third of the real time
 * cost. They are worthless as a password hash and are never used to derive
 * anything. They exist only to ask a backend "are you Argon2id, and do you obey
 * the parameters you are given?" for about two milliseconds instead of eleven
 * seconds. Using these parameters for a real derivation would be the exact
 * catastrophe {@link ARGON2_PARAMS} is documented against.
 *
 * THERE ARE TWO VECTORS, AND THAT IS THE POINT. A backend that ignores its
 * `params` argument and hardcodes its own settings passes any single vector it
 * was tuned against. Two vectors differing in all four of `m`, `t`, `p` and
 * `dkLen` cannot both be satisfied by a hardcoded configuration.
 *
 * PROVENANCE. Both digests were computed independently by `@noble/hashes`
 * 1.8.0 and by `hash-wasm` 4.12.0 -- two implementations sharing no code -- and
 * agreed byte for byte. They are a cross-check, not an echo of whichever
 * implementation happens to be the default here.
 */
const CONFORMANCE_PASSWORD = "sluice/argon2-conformance/v1";
const CONFORMANCE_SALT = "sluice-conformance-salt-0001";
const CONFORMANCE_VECTORS: ReadonlyArray<{ params: Argon2Params; hex: string }> = [
  {
    params: { m: 64, t: 1, p: 1, dkLen: 32 },
    hex: "16b507db06a8ed4ca008e49c426005d2ad90cbc09b02cf60f68aa970a865b30f",
  },
  {
    params: { m: 128, t: 2, p: 2, dkLen: 16 },
    hex: "93ed9dec6e647ffba61158921e95049b",
  },
];

/**
 * Memoises the conformance check per backend function object.
 *
 * A `WeakMap` rather than a `Map`, so holding a backend alive is the caller's
 * business and not this module's. The stored value is the PROMISE, not the
 * result, which is what makes concurrent first calls share one check instead of
 * racing two. A rejected promise is cached deliberately: a backend that failed
 * conformance must keep failing, loudly, on every subsequent call, rather than
 * being retried until a flake lets it through.
 */
const conformance = new WeakMap<Argon2Backend, Promise<void>>();

/**
 * Proves a backend is really Argon2id and really honours its parameters, once.
 *
 * WHAT THIS BUYS. It catches the failures that actually happen: `argon2i`
 * wired in place of `argon2id` (a one-character import slip that produces a
 * different, weaker-against-GPU key and would orphan every account), a library
 * whose `memorySize` is in bytes rather than KiB, an options object with a
 * misspelled key silently falling back to the library's defaults, a hash
 * returned hex-encoded and then re-read as bytes, a stub left in from a test.
 * Every one of those produces a WRONG MUK, and without this check the first
 * symptom is a user who cannot open their own account.
 *
 * WHAT THIS DOES NOT BUY, SAID OUT LOUD. It does not prove the backend will run
 * the REAL parameters honestly. A backend that answers both vectors correctly
 * and then quietly downgrades `m` when it sees 65536 passes this and is
 * undetectable from here, because verifying that would cost a full derivation.
 * The defence against that is not runtime: it is the full-parameter
 * known-answer vector in the test suite, which every backend must pass before
 * it is allowed anywhere near a user. This function is the cheap half of a
 * two-part gate, not the whole gate.
 *
 * It throws rather than falling back to {@link nobleArgon2}. A silent fallback
 * would be *correct* -- noble derives the right key -- and that is precisely
 * why it is wrong: the broken backend would never be discovered, and every user
 * would pay eleven seconds forever while a green build claimed the WASM path
 * worked. Choosing a fallback is the application's decision, made where it can
 * be reported.
 */
export function assertConformantArgon2(backend: Argon2Backend): Promise<void> {
  const cached = conformance.get(backend);
  if (cached !== undefined) return cached;

  const check = (async () => {
    const password = utf8.encode(CONFORMANCE_PASSWORD);
    const salt = utf8.encode(CONFORMANCE_SALT);
    for (const { params, hex } of CONFORMANCE_VECTORS) {
      const out = await backend(password, salt, Object.freeze({ ...params }));
      assertArgon2Output(out, params.dkLen);
      // Public constants on both sides, so an ordinary comparison is fine here;
      // there is no secret whose position a timing difference could leak.
      if (toHex(out) !== hex) {
        throw new Error(
          "argon2 backend failed conformance: it is not Argon2id at the given " +
            `parameters (m=${params.m} t=${params.t} p=${params.p} dkLen=${params.dkLen}). ` +
            "Refusing to derive a key with it.",
        );
      }
    }
  })();

  conformance.set(backend, check);
  // Nothing awaits the memoised promise until a caller does, and an unawaited
  // rejection is an unhandled rejection that can kill a Node process. This
  // marks it handled without swallowing it: every real caller still awaits the
  // same promise and still sees the rejection.
  check.catch(() => {});
  return check;
}

/**
 * Validates what a backend handed back before it can become a key.
 *
 * `instanceof Uint8Array` is checked rather than assumed because a backend that
 * returned hex -- `hash-wasm` does exactly that unless told
 * `outputType: "binary"` -- is a plausible mistake, and a string reaching
 * `MasterUnlockKey` would fail on `.length` in a way that reads like a
 * parameter bug rather than a wiring bug.
 */
export function assertArgon2Output(out: unknown, dkLen: number): asserts out is Uint8Array {
  if (!(out instanceof Uint8Array)) {
    throw new Error(`argon2 backend must return a Uint8Array, got ${typeof out}`);
  }
  if (out.length !== dkLen) {
    throw new Error(`argon2 backend must return ${dkLen} bytes, got ${out.length}`);
  }
}
