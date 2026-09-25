import { NO_PERSISTED_FLOOR, SluiceCore } from "@sluice/sdk";
import { loadConfig, type RunConfig } from "./config";
import { defaultStateDir, FileEpochFloorStore } from "./floor";
import { HttpHandshaker } from "./handshake";
import {
  ConsoleLogger,
  ConvexBundleSource,
  NodeChildProcessSupervisor,
  NodeTimers,
} from "./node-runtime";
import type { BundleSource, Logger } from "./ports";
import { Shell } from "./shell";

/**
 * THE COMPOSITION ROOT FOR `sluice run`.
 *
 * Everything decided here is a wiring decision. There is no policy in this
 * file: the core decides when the process dies, `shell.ts` decides when it is
 * told, and this decides which objects those two are handed.
 *
 * WHAT HAPPENS BEFORE ANY OF IT. Configuration is validated first, and a
 * failure exits 2 rather than 1. Exit 1 is the revoked code, fixed by section
 * 4.3, and an operator who sees it should be able to conclude something about
 * their fleet rather than about their `.env` file.
 */

/** Configuration was wrong. Deliberately not 1, which means revoked. */
export const CONFIG_EXIT_CODE = 2;

export interface RunDependencies {
  readonly env: Record<string, string | undefined>;
  readonly exit: (code: number) => void;
  readonly logger?: Logger;
  /** Signals the operator sends us, relayed to the child. See below. */
  readonly onSignal?: (handler: (signal: NodeJS.Signals) => void) => void;
  /**
   * How the subscription is built.
   *
   * A SEAM, AND NOT ONLY FOR TESTS. The default opens a real socket the moment
   * it is constructed, which makes every assertion about the steps BEFORE that
   * socket, and there are four of them that can refuse to start, either a live
   * network call or untested. It is also the one substitution an embedder on a
   * different transport would need. Nothing else about this wiring is
   * overridable, deliberately.
   */
  readonly sourceFactory?: (deploymentUrl: string) => BundleSource;
}

export function run(
  command: string,
  args: readonly string[],
  dependencies: RunDependencies,
): void {
  const logger = dependencies.logger ?? new ConsoleLogger();

  const loaded = loadConfig(dependencies.env);
  if (!loaded.ok) {
    logger.log("error", "config-invalid", loaded.message);
    dependencies.exit(CONFIG_EXIT_CODE);
    return;
  }
  const config: RunConfig = loaded.config;

  const stateDir = config.stateDir ?? defaultStateDir();
  if (stateDir === null) {
    logger.log(
      "error",
      "no-state-dir",
      "Sluice has nowhere to persist the revocation epoch floor, because this process has no " +
        "home directory. Set SLUICE_STATE_DIR to a writable path that survives a restart. " +
        "Without it, every restart would accept a replay of any revocation notice this token " +
        "has already acted on.",
    );
    dependencies.exit(CONFIG_EXIT_CODE);
    return;
  }

  const floorStore = new FileEpochFloorStore(stateDir, config.identity.tokenIdHashHex);
  const restored = floorStore.load();
  if (!restored.ok) {
    // See the long note in `floor.ts`. Refusing to start is the deliberate
    // answer: falling back to the sentinel would silently reopen a replay
    // window, and the whole point of the sentinel is that it cannot be
    // confused with a restored floor.
    logger.log("error", "epoch-floor-unreadable", restored.message);
    dependencies.exit(CONFIG_EXIT_CODE);
    return;
  }
  if (restored.floor === NO_PERSISTED_FLOOR) {
    logger.log(
      "info",
      "first-boot",
      "no revocation epoch floor is stored for this token yet, so this process will accept " +
        "any genuine notice for it, including one captured earlier and replayed now. That is " +
        "unavoidable on a first boot and is closed as soon as one notice is acted on.",
    );
  }

  const timers = new NodeTimers();
  const child = new NodeChildProcessSupervisor(command, args, logger);

  const core = new SluiceCore({
    orgRevocationPublicKey: config.orgRevocationPublicKey,
    tokenId: config.identity.tokenIdHex,
    initialEpochFloor: restored.floor,
    drainMs: config.drainMs,
    bootTimeoutMs: config.bootTimeoutMs,
    ...(config.maxOfflineDurationMs === undefined
      ? {}
      : { maxOfflineDurationMs: config.maxOfflineDurationMs }),
  });

  const shell = new Shell({
    core,
    identity: config.identity,
    timers,
    logger,
    handshaker: new HttpHandshaker({
      url: config.handshakeUrl,
      identity: config.identity,
      fetch: (url, init) => fetch(url, init),
      now: () => timers.now(),
    }),
    source: (dependencies.sourceFactory ?? ((url: string) => new ConvexBundleSource(url, logger)))(
      config.convexUrl,
    ),
    child,
    floorStore,
    exit: dependencies.exit,
    killGraceMs: config.killGraceMs,
    bootTimeoutMs: config.bootTimeoutMs,
    baseEnv: dependencies.env,
  });

  /**
   * THE OPERATOR'S OWN SIGNAL, RELAYED TO THE CHILD.
   *
   * THIS IS THE SECOND AND LAST PLACE IN THIS PACKAGE THAT SIGNALS THE CHILD,
   * AND IT ORIGINATES NOTHING. Somebody pressed Ctrl+C, or an orchestrator sent
   * SIGTERM to this process; a supervisor that swallowed that would leave the
   * child running with the secrets and no parent, which is the worse failure by
   * a distance. On POSIX, Ctrl+C already reaches the whole foreground process
   * group, so this mostly matters for a SIGTERM aimed at this process alone.
   *
   * IT IS NOT A SLUICE DECISION AND IT IS NOT A SHUTDOWN. The core is not told,
   * the epoch floor is not touched, and the exit code is the child's. The rule
   * the grep in `shell.test.ts` enforces is about Sluice never inventing a
   * termination; forwarding one somebody else sent is the opposite of
   * inventing one.
   */
  dependencies.onSignal?.((signal) => {
    logger.log(
      "info",
      "operator-signal",
      `received ${signal}; forwarding it to the child and waiting for it to exit`,
    );
    child.signal(signal);
  });

  shell.start();
}
