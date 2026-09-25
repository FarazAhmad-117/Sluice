/**
 * THE PUBLIC SURFACE OF @sluice/cli.
 *
 * Everything a consumer can reach is named here and nowhere else, and
 * `test/index.test.ts` pins the exact list, for the same reason
 * `packages/crypto` and `packages/sdk` do it: on a package that decides when a
 * customer's process dies, an export added without argument is how a future
 * caller acquires a back door into the state machine, so adding one has to show
 * up in a diff as an edit to two files.
 *
 * WHAT IS NOT EXPORTED IS AS CONSIDERED AS WHAT IS. There is no way to build a
 * shutdown, no way to kill the child and no way to reach a timer from outside
 * `Shell`. The only path to a dead child is a decision `SluiceCore` returned
 * from a revocation whose signature verified against the organisation key the
 * customer pinned.
 *
 * `Shell` IS exported, and that is deliberate rather than an oversight: it is
 * the thing an embedder with a different transport or a different supervisor
 * would reuse, and every one of its dependencies is an interface in `ports.ts`.
 * What it exposes is a constructor, `start`, and two read-only numbers.
 *
 * ON THE EXTENSIONLESS IMPORT SPECIFIERS BELOW: same reasoning as
 * `packages/crypto/src/index.ts` and `packages/sdk/src/index.ts`.
 * `tsconfig.base.json` sets `moduleResolution: "bundler"`, this package ships
 * TypeScript source with no build step, and writing `./shell.js` breaks any
 * bundler applying strict ESM resolution.
 */
export const VERSION = "sluice-cli/v1";

export { parseArgv } from "./argv";
export type { ParsedArgv } from "./argv";

export { loadConfig, TokenIdentity } from "./config";
export type { ConfigResult, RunConfig } from "./config";

export { decryptSecrets, readRevocation, BundleDecryptError } from "./bundle";
export type {
  BundleDecryptCode,
  ParsedRevocation,
  RawBundle,
  RawRevocationNotice,
  RawSecretRow,
} from "./bundle";

export { defaultStateDir, FileEpochFloorStore, floorFilePath } from "./floor";
export type { EpochFloorStore, FloorLoad } from "./floor";

export { HandshakeError, HttpHandshaker } from "./handshake";
export type { BundleCredential, FetchLike, Handshaker, HttpHandshakerOptions } from "./handshake";

export {
  ConsoleLogger,
  ConvexBundleSource,
  NodeChildProcessSupervisor,
  NodeTimers,
  stripControls,
} from "./node-runtime";

export type {
  BundleSource,
  ChildProcessSupervisor,
  Logger,
  SubscriptionHandlers,
  TimerHandle,
  Timers,
} from "./ports";

export { Shell } from "./shell";
export type { ShellOptions } from "./shell";

export { CONFIG_EXIT_CODE, run } from "./run";
export type { RunDependencies } from "./run";

export { HELP, main } from "./main";
export type { MainDependencies } from "./main";
