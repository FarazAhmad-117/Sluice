import { spawn, type ChildProcess } from "node:child_process";
import { ConvexClient } from "convex/browser";
import { makeFunctionReference } from "convex/server";
import { sanitiseForLog } from "@sluice/sdk";
import type { RawBundle } from "./bundle";
import type {
  BundleSource,
  ChildProcessSupervisor,
  Logger,
  SubscriptionHandlers,
  TimerHandle,
  Timers,
} from "./ports";
import type { LogLevel } from "@sluice/sdk";

/**
 * THE REAL IMPLEMENTATIONS OF THE FOUR PORTS. THE ONLY FILE IN THIS PACKAGE
 * THAT TOUCHES A SOCKET, A PROCESS OR A CLOCK.
 *
 * `shell.ts` is where the kill switch lives and it is testable because none of
 * this is in it. What is here is the part a test cannot prove and a reader has
 * to be able to check by eye, so each piece is small and says what it is doing.
 */

/**
 * Real timers, and DELIBERATELY NOT `unref`'d.
 *
 * `host.ts` is explicit about this: the drain timer must keep the process
 * alive, or an otherwise idle process can exit 0 in the middle of a drain and
 * look like a clean shutdown in every dashboard. The tick is the same argument
 * over a longer window, so neither is unref'd and the process stays alive for
 * exactly as long as Sluice is supervising something.
 */
export class NodeTimers implements Timers {
  now(): number {
    return Date.now();
  }

  setTimeout(callback: () => void, ms: number): TimerHandle {
    return setTimeout(callback, ms);
  }

  setInterval(callback: () => void, ms: number): TimerHandle {
    return setInterval(callback, ms);
  }

  clear(handle: TimerHandle): void {
    // One `clear` for both kinds. Node's `clearTimeout` and `clearInterval` are
    // interchangeable on a `Timeout`, and a single method keeps the port small
    // enough that a fake cannot get it subtly wrong.
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  }
}

/**
 * The child, supervised.
 *
 * `shell: false`, ALWAYS, AND ON EVERY PLATFORM. Putting a shell between this
 * process and the command re-parses an argument vector the operator's own shell
 * has already parsed once, so a command containing a metacharacter runs as
 * something other than what was typed. On a tool whose job is handing out
 * production credentials, "ran a slightly different command" is not a class of
 * bug worth accepting for convenience. See the note on {@link spawnFailure} for
 * what this costs on Windows, which is real and is stated rather than hidden.
 *
 * `stdio: "inherit"`, so the child owns the terminal exactly as it would
 * without Sluice in front of it. Sluice's own lines go to stderr, so a pipeline
 * reading the child's stdout sees the child and nothing else.
 */
export class NodeChildProcessSupervisor implements ChildProcessSupervisor {
  readonly #command: string;
  readonly #args: readonly string[];
  readonly #logger: Logger;
  #child: ChildProcess | null = null;
  #started = false;
  #running = false;
  #onExit: ((code: number | null, signal: NodeJS.Signals | null) => void) | null = null;

  constructor(command: string, args: readonly string[], logger: Logger) {
    this.#command = command;
    this.#args = args;
    this.#logger = logger;
  }

  get started(): boolean {
    return this.#started;
  }

  get running(): boolean {
    return this.#running;
  }

  onExit(callback: (code: number | null, signal: NodeJS.Signals | null) => void): void {
    this.#onExit = callback;
  }

  spawn(env: Record<string, string>): void {
    if (this.#started) return;
    this.#started = true;
    this.#running = true;

    let child: ChildProcess;
    try {
      child = spawn(this.#command, [...this.#args], {
        env,
        stdio: "inherit",
        shell: false,
        windowsHide: true,
      });
    } catch (error) {
      this.#running = false;
      this.#logger.log("error", "child-spawn-failed", spawnFailure(this.#command, error));
      // Reported as an exit rather than thrown. The shell treats the child
      // going away as the supervised process ending, which is what happened,
      // and every timer and socket is torn down through the one path that
      // already does it correctly.
      this.#onExit?.(1, null);
      return;
    }
    this.#child = child;

    child.on("error", (error: NodeJS.ErrnoException) => {
      if (!this.#running) return;
      this.#running = false;
      this.#logger.log("error", "child-spawn-failed", spawnFailure(this.#command, error));
      this.#onExit?.(1, null);
    });
    child.on("exit", (code, signal) => {
      if (!this.#running) return;
      this.#running = false;
      this.#onExit?.(code, signal);
    });
  }

  signal(signal: NodeJS.Signals): void {
    if (!this.#running || this.#child === null) return;
    try {
      this.#child.kill(signal);
    } catch {
      // The child is already gone, or the platform refused the signal. Either
      // way the exit handler is what decides, and there is nothing to retry.
    }
  }
}

/**
 * Why a spawn failed, in terms the operator can act on.
 *
 * ON WINDOWS THIS IS A REAL LIMITATION AND IT IS NAMED RATHER THAN PAPERED
 * OVER. `npm`, `pnpm`, `yarn` and most Node tooling are `.cmd` shims there, and
 * since the 2024 hardening Node refuses to spawn a `.cmd` or a `.bat` without a
 * shell. So `sluice run -- npm start` fails on Windows with EINVAL or ENOENT
 * and would need a shell to work. This build will not silently put one there;
 * the message says what to run instead.
 */
function spawnFailure(command: string, error: unknown): string {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  const named = sanitiseForLog(command);
  if (process.platform === "win32" && (code === "EINVAL" || code === "ENOENT")) {
    return (
      `could not start ${named} (${String(code)}). On Windows, Node refuses to start a .cmd ` +
      "or .bat file without a shell, and Sluice will not put a shell between you and your " +
      "command, because that re-parses an argument vector your own shell has already read. " +
      "Name the real executable instead, for example: sluice run -- node server.js"
    );
  }
  return `could not start ${named}: ${String(code ?? "unknown error")}`;
}

/**
 * THE REACTIVE SUBSCRIPTION.
 *
 * `bundle.getBundle` takes the credential as its one ARGUMENT rather than as a
 * header, because a Convex query is called from a client that carries no
 * headers. That is why rotating a credential means opening a new subscription
 * rather than refreshing one, and why `shell.ts` owns the overlap.
 *
 * THE FUNCTION REFERENCE IS BUILT BY NAME, not imported from
 * `convex/_generated/api`. The generated module belongs to the deployment in
 * this repository, and this package must build and run against a deployment it
 * was not compiled beside. The cost of that is real: a rename on the server
 * turns into a runtime failure here rather than a compile error, which is why
 * the name is written once, here, and the query's own return shape is validated
 * in `bundle.ts` before anything is trusted.
 */
const GET_BUNDLE = makeFunctionReference<"query", { token: string }, RawBundle>(
  "bundle:getBundle",
);

export class ConvexBundleSource implements BundleSource {
  readonly #client: ConvexClient;

  constructor(deploymentUrl: string, logger?: Logger) {
    this.#client = new ConvexClient(deploymentUrl, {
      // There is no window here and nothing to warn anybody about.
      unsavedChangesWarning: false,
      // ROUTED THROUGH SLUICE'S OWN LOGGER RATHER THAN LEFT ON `console`. By
      // default this client writes straight to the console, on stdout for some
      // levels, in its own format, with whatever characters the server sent. On
      // a supervisor that is three problems at once: it pollutes the child's
      // stdout, it is indistinguishable from the child's own output, and it is
      // an unsanitised path from a remote string to an operator's terminal
      // during the incident. Everything it says still gets said.
      ...(logger === undefined ? {} : { logger: convexLogger(logger) }),
    });
  }

  subscribe(bundleToken: string, handlers: SubscriptionHandlers): () => void {
    const unsubscribe = this.#client.onUpdate(
      GET_BUNDLE,
      { token: bundleToken },
      (result) => handlers.onResult(result),
      // WITHOUT THIS CALLBACK THE CLIENT THROWS. An expired credential makes
      // the query throw on every re-run, and an unhandled throw from a
      // subscription callback would take the supervisor down with it, turning a
      // stale credential into a dead workload. It is reported as a transport
      // error, which can never mean revocation.
      (error: Error) => handlers.onError(error.message),
    );
    return () => {
      unsubscribe.unsubscribe();
    };
  }

  isConnected(): boolean {
    try {
      return this.#client.connectionState().isWebSocketConnected;
    } catch {
      return false;
    }
  }

  close(): void {
    // Fire and forget. `close` returns a promise that settles when the socket
    // is shut, and the caller is on its way to `process.exit`; waiting for a
    // clean close during a revocation would be waiting on the network to agree
    // that the process may stop running.
    void this.#client.close().catch(() => undefined);
  }
}

/**
 * A Convex logger that writes through Sluice's.
 *
 * `logVerbose` is dropped on the floor. It is the client's per-message trace,
 * it is off unless `verbose` is set, and this build never sets it: a trace of
 * every query re-run on a subscription that carries revocation notices is a
 * high-volume log of exactly the moments an operator cares about, drowning the
 * four lines that matter.
 */
function convexLogger(logger: Logger): {
  logVerbose(...args: unknown[]): void;
  log(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
} {
  const write = (level: LogLevel) => (...args: unknown[]) => {
    logger.log(level, "transport", args.map(describeArgument).join(" "));
  };
  return {
    logVerbose: () => undefined,
    log: write("info"),
    warn: write("warn"),
    error: write("error"),
  };
}

/**
 * One argument of a transport log line, without running anything hostile.
 *
 * `String(value)` calls `toString`, and these values come off a wire. A string
 * is taken verbatim, because `ConsoleLogger` strips control characters from
 * every line it writes; anything else is reported by its type alone.
 */
function describeArgument(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return String(value);
  }
  const message = (value as { message?: unknown } | null)?.message;
  if (typeof message === "string") return message;
  return `<${typeof value}>`;
}

/**
 * Operator-facing output, on stderr, one line each.
 *
 * STDERR RATHER THAN STDOUT, so that a pipeline consuming the child's stdout
 * sees the child and nothing else. A supervisor that writes its own chatter
 * into a data stream is a supervisor nobody can put in a pipe.
 *
 * NOTHING IS FORMATTED WITH COLOUR OR CURSOR CONTROL. This logger prints text
 * that includes attacker-influenced fragments, already sanitised upstream, and
 * the last thing that should be true of it is that it emits escape sequences of
 * its own for a reader to have to tell apart.
 */
export class ConsoleLogger implements Logger {
  readonly #write: (line: string) => void;

  constructor(write: (line: string) => void = (line) => process.stderr.write(line)) {
    this.#write = write;
  }

  log(level: LogLevel, code: string, message: string): void {
    this.#write(`sluice ${level} ${code}: ${stripControls(message)}\n`);
  }

  metric(name: string, value: number): void {
    // Metrics are not printed. A supervisor that wrote a line per metric would
    // bury the four lines that matter, and this package has no sink to send
    // them to. The method exists so the core's metric decisions are consumed
    // rather than silently dropped by a missing handler, and so a future build
    // has one place to wire a real sink.
    void name;
    void value;
  }
}

/**
 * Removes the characters that let text rewrite a terminal.
 *
 * THE SAME CHARACTER CLASSES AS `sanitiseForLog` IN `@sluice/sdk`, WITHOUT ITS
 * LENGTH CAP, and `logger.test.ts` pins the agreement between the two on every
 * input short enough for both to handle. The cap cannot apply here: these are
 * Sluice's own operator messages, several are longer than 256 characters
 * because they explain what to do next, and truncating them would hide the
 * instruction. Every attacker-influenced FRAGMENT inside them has already been
 * through the SDK's version, cap and all, at the point it was interpolated.
 * This pass is the last line of defence for a fragment somebody forgets.
 */
export function stripControls(text: string): string {
  if (typeof text !== "string") return "<non-string message>";
  let out = "";
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    out += codePoint === undefined || isHostile(codePoint) ? "�" : character;
  }
  return out;
}

function isHostile(codePoint: number): boolean {
  return (
    codePoint <= 0x1f ||
    codePoint === 0x7f ||
    (codePoint >= 0x80 && codePoint <= 0x9f) ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069) ||
    (codePoint >= 0xd800 && codePoint <= 0xdfff)
  );
}
