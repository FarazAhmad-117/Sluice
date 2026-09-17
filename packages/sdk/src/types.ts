import type { RevocationNotice } from "@sluice/crypto";

/**
 * A decrypted set of secrets at one PDK epoch.
 *
 * `epoch` here is the ENVIRONMENT epoch from section 4.1 -- the counter that
 * bumps when the project data key is re-keyed. It is NOT the revocation epoch,
 * which lives per token id on {@link RevocationNotice}. They are different
 * numbers in different namespaces and conflating them is a live way to break
 * the kill switch; see `SluiceCore.epochFloor` for what that would cost.
 */
export interface SecretBundle {
  readonly epoch: number;
  readonly secrets: Readonly<Record<string, string>>;
}

/**
 * EVERY EVENT CARRIES `now`.
 *
 * The core reads no clock of its own. That is what makes drain deadlines, the
 * boot deadline and `maxOfflineDurationMs` exhaustively testable without a
 * timer, and it is why the entire shutdown decision is a pure function of the
 * event sequence. A host supplies the time; see the monotonicity note on
 * {@link SluiceCore.handle}.
 */
interface Timed {
  readonly now: number;
}

export type SluiceEvent =
  /**
   * The process is starting. `cache` is a bundle read from disk, or `null`.
   * Boot with no cache and no network must fail to start; boot with a cache and
   * no network must start degraded and alarm. Both of those are decided from
   * this event plus what follows it.
   */
  | (Timed & { readonly type: "boot"; readonly cache: SecretBundle | null })
  /** A bundle arrived over the live subscription. */
  | (Timed & { readonly type: "bundle"; readonly bundle: SecretBundle })
  /** The environment's PDK epoch moved; the SDK must re-fetch. Never a crash. */
  | (Timed & { readonly type: "epoch-bump"; readonly epoch: number })
  /** A revocation notice arrived. Authenticity is decided here, not by the host. */
  | (Timed & {
      readonly type: "revocation";
      readonly notice: RevocationNotice;
      readonly signature: Uint8Array;
    })
  /** The transport lost its connection. This must never, ever mean revocation. */
  | (Timed & { readonly type: "disconnected"; readonly cause?: string })
  /** The transport is live again. */
  | (Timed & { readonly type: "reconnected" })
  /** The host's `onRevoke` handler resolved. */
  | (Timed & { readonly type: "drain-complete" })
  /** The host's `onRevoke` handler threw or rejected. */
  | (Timed & { readonly type: "drain-failed"; readonly error: string })
  /** A clock advance. The only way any deadline in this core is ever reached. */
  | (Timed & { readonly type: "tick" });

export type LogLevel = "info" | "warn" | "error";

/**
 * Why a shutdown was ordered.
 *
 * Two causes, kept apart deliberately so that `cause` alone answers "did an
 * outage kill this fleet?" in a log search. `"revocation"` is reachable only
 * from a notice that passed {@link import("@sluice/crypto").verifyRevocation}.
 * `"offline-limit"` is reachable only when a host explicitly opted into
 * `maxOfflineDurationMs`, which defaults to unlimited.
 */
export type ShutdownCause = "revocation" | "offline-limit";

export type SluiceDecision =
  /**
   * Install these secrets. `changed` and `removed` are key NAMES only, never
   * values, so a host can log them.
   */
  | {
      readonly type: "apply-secrets";
      readonly bundle: SecretBundle;
      readonly changed: readonly string[];
      readonly removed: readonly string[];
      /** True when these secrets came from disk and the wire has not confirmed them. */
      readonly degraded: boolean;
    }
  /** The PDK epoch moved. Fetch the bundle again. Do not crash. */
  | { readonly type: "refetch"; readonly epoch: number }
  | { readonly type: "log"; readonly level: LogLevel; readonly code: string; readonly message: string }
  | { readonly type: "metric"; readonly name: string; readonly value: number }
  /**
   * Begin draining, then exit. The host calls `onRevoke`, and MUST NOT let the
   * result of that call decide whether to exit -- only when.
   *
   * `reason` is already sanitised and is the field to log. `signedReason` is
   * the exact text the signature covers, for a host that needs to re-verify.
   */
  | {
      readonly type: "shutdown";
      readonly cause: ShutdownCause;
      readonly reason: string;
      readonly signedReason: string;
      /** Revocation epoch acted on, or `null` for an offline-limit shutdown. */
      readonly epoch: number | null;
      readonly drainMs: number;
    }
  /** Drain is over. Call `host.exit(code)` now. Terminal. */
  | { readonly type: "exit"; readonly code: number; readonly reason: string }
  /**
   * Boot could not complete. Terminal, and reachable ONLY before any
   * `apply-secrets` has ever been emitted, so it can never kill a running
   * process.
   */
  | { readonly type: "fail-to-start"; readonly code: number; readonly reason: string };

export interface SluiceCoreOptions {
  /**
   * The organisation's Ed25519 revocation public key, lowercase hex.
   *
   * REQUIRED, AND THE SDK MUST NEVER FETCH IT. This is the whole kill switch.
   * If this key could arrive from the Sluice server, from Convex, or over the
   * same subscription that delivers notices, then a compromised server serves
   * its own public key, signs its own notices with the matching private key,
   * and kills every customer fleet on the platform simultaneously. It is a
   * constructor argument so that the only way to supply it is from
   * customer-controlled configuration: an environment variable, a config file,
   * or a value baked in at install time.
   *
   * Pinning makes rotation painful by construction. That is the intended
   * trade: rotating this key is a deliberate, customer-driven operation, not
   * something a server can do on a customer's behalf.
   */
  readonly orgRevocationPublicKey: string;

  /**
   * This process's own token id, 32 lowercase hex characters.
   *
   * A notice names the token it revokes, and `verifyRevocation` proves only
   * that the org signed it -- not that it is about us. Without this check, a
   * genuine notice for ANY token in the organisation would kill every process
   * in it. The comparison happens before anything else is trusted.
   */
  readonly tokenId: string;

  /** Drain window in ms before exit. Default 5000, hard maximum 60000. */
  readonly drainMs?: number;

  /**
   * How long the process may run disconnected before shutting down.
   *
   * Default unlimited (`undefined`). Opt-in only, and the one setting in this
   * package that lets an outage kill a fleet. If set it must be at least
   * {@link MIN_MAX_OFFLINE_DURATION_MS}; `0` would mean "die on the first
   * network blip", which is the exact failure the whole design exists to stop.
   */
  readonly maxOfflineDurationMs?: number;

  /** How long boot may wait for a first bundle with no cache. Default 30000. */
  readonly bootTimeoutMs?: number;

  /**
   * The highest revocation epoch this token has already acted on, restored
   * from host storage. Default -1, meaning "nothing seen".
   *
   * A HOST THAT DOES NOT PERSIST THIS IS REPLAYABLE. Ed25519 signatures are
   * deterministic and a notice is a freely copyable pair of bytes, so anyone
   * who ever observed a genuine revocation can resend it verbatim forever. A
   * fresh process with floor -1 accepts it, because it has seen nothing and any
   * genuine epoch is above -1. Persist {@link SluiceCore.epochFloor} after
   * every accepted notice and pass it back here on restart, or accept that a
   * restart re-opens a replay window that lasts until the next genuine notice.
   */
  readonly initialEpochFloor?: number;
}

/**
 * The boundary this package refuses to cross.
 *
 * There is no `process` reference anywhere in `packages/sdk`, and no
 * `@types/node`. Killing a process is the single most destructive thing this
 * code does, so it happens through an interface the caller supplies and the
 * tests replace. `SluiceCore` does not even know this type exists -- it returns
 * decisions -- and {@link applyDecisions} is the only place the two meet.
 */
export interface SluiceHost {
  /** Terminate the process. Implemented as `process.exit(code)` in a Node shell. */
  exit(code: number): void;
  log(level: LogLevel, code: string, message: string): void;
  metric(name: string, value: number): void;
  /** Install secrets into the running application. */
  applySecrets?(bundle: SecretBundle, changed: readonly string[], removed: readonly string[]): void;
  /** Ask the transport for the bundle again after an epoch bump. */
  refetch?(epoch: number): void;
  /**
   * Begin draining. MAY delay the exit up to `drainMs`. MUST NOT cancel it.
   * The shell reports the outcome back as `drain-complete` or `drain-failed`,
   * and must arm an independent timer for `drainMs` that fires regardless.
   */
  beginDrain?(reason: string, drainMs: number): void;
}

/** Floor for `maxOfflineDurationMs`, in ms. See the option's own note. */
export const MIN_MAX_OFFLINE_DURATION_MS = 1_000;

/** Hard ceiling on the drain window, in ms. */
export const MAX_DRAIN_MS = 60_000;

/**
 * The largest clock step, in ms, that one event may contribute to the
 * accumulated timeline behind `maxOfflineDurationMs` and the boot deadline.
 *
 * A HOST MUST EMIT A `tick` AT LEAST THIS OFTEN. Ticking less often makes an
 * opted-in `maxOfflineDurationMs` fire late, which is the safe direction, but
 * it is still wrong. Anything larger than this in a single step is treated as a
 * clock fault rather than as elapsed time; see the header of `core.ts`.
 */
export const MAX_CLOCK_STEP_MS = 60_000;

/** Exit code for a revoked or offline-limited process. Section 4.3 fixes this at 1. */
export const EXIT_CODE = 1;
