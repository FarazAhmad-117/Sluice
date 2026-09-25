import type { LogLevel } from "@sluice/sdk";
import type { RawBundle } from "./bundle";

/**
 * THE FOUR THINGS THE SHELL TALKS TO, AS INTERFACES.
 *
 * `packages/sdk` keeps `process` out of itself structurally, by having no
 * `@types/node`. This package cannot: injecting an environment into a child
 * process is the whole job, so the Node built-ins are here and that is correct.
 * The discipline that replaces the structural one is this file. Every timer,
 * every socket, every signal and every clock reading in `shell.ts` goes through
 * one of these, so the shell's behaviour under a hostile sequence is decided by
 * a test rather than by how fast a machine happened to be.
 *
 * That matters most for the timer. The kill switch is a deadline, the core owns
 * no clock, and an assertion about a deadline that depends on real time is an
 * assertion that is either slow or flaky. A virtual clock makes "the process
 * exits even though the drain handler never returned" an exact statement.
 */

/** Opaque to the shell. A real implementation returns whatever its runtime uses. */
export type TimerHandle = unknown;

export interface Timers {
  /** Unix milliseconds. Every event the shell builds carries this value. */
  now(): number;
  setTimeout(callback: () => void, ms: number): TimerHandle;
  setInterval(callback: () => void, ms: number): TimerHandle;
  clear(handle: TimerHandle): void;
}

export interface SubscriptionHandlers {
  /** A bundle arrived. The argument is untrusted data straight off the wire. */
  onResult(raw: RawBundle): void;
  /**
   * The query threw, or the credential expired.
   *
   * THIS IS NEVER A REVOCATION and the shell must never treat it as one. It is
   * reported to the core as `disconnected`, which by design cannot reach a
   * shutdown decision.
   */
  onError(message: string): void;
}

export interface BundleSource {
  /** Starts one live subscription. The returned function stops that one. */
  subscribe(bundleToken: string, handlers: SubscriptionHandlers): () => void;
  /** Whether the transport believes it currently has a socket. */
  isConnected(): boolean;
  /** Stops everything. Called once, on the way out. */
  close(): void;
}

export interface ChildProcessSupervisor {
  /** Starts the child with exactly this environment. Called at most once. */
  spawn(env: Record<string, string>): void;
  /** True once `spawn` has been called, whether or not the child still lives. */
  readonly started: boolean;
  readonly running: boolean;
  /** Delivers a signal. A no-op if the child is not running. */
  signal(signal: NodeJS.Signals): void;
  /** Registered once, before `spawn`. */
  onExit(callback: (code: number | null, signal: NodeJS.Signals | null) => void): void;
}

export interface Logger {
  log(level: LogLevel, code: string, message: string): void;
  metric(name: string, value: number): void;
}
