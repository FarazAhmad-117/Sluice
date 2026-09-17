/**
 * THE PUBLIC SURFACE OF @sluice/sdk.
 *
 * Everything a consumer can reach is named here and nowhere else, and
 * `test/index.test.ts` pins the exact list. On a package whose job is deciding
 * when a process dies, an export added without argument is how a future
 * transport acquires a private back door into the state machine, so adding one
 * must show up in a diff as an edit to both files.
 *
 * WHAT IS NOT EXPORTED IS AS CONSIDERED AS WHAT IS. There is no `shutdown()`,
 * no `exit()`, no `forceRevoke()` and no way to construct a shutdown decision
 * from outside. The ONLY way to obtain one is to feed `SluiceCore.handle` a
 * revocation whose signature verifies against the pinned organisation key. A
 * convenience helper that skipped that check would be a kill switch with no
 * lock on it, however carefully it was documented.
 *
 * `RevocationNotice` is re-exported as a type so a transport can annotate what
 * it pulled off a subscription without depending on `@sluice/crypto` directly.
 *
 * ON THE EXTENSIONLESS IMPORT SPECIFIERS BELOW: same reasoning as
 * `packages/crypto/src/index.ts`. `tsconfig.base.json` sets
 * `moduleResolution: "bundler"`, this package ships TypeScript source with no
 * build step, and writing `./core.js` breaks any bundler applying strict ESM
 * resolution. Do not add the extensions back without adding a build step.
 */
export const VERSION = "sluice-sdk/v1";

export { SluiceCore } from "./core";
export { applyDecisions } from "./host";
export { sanitiseForLog } from "./sanitise";
export {
  EXIT_CODE,
  MAX_CLOCK_STEP_MS,
  MAX_DRAIN_MS,
  MIN_MAX_OFFLINE_DURATION_MS,
  NO_PERSISTED_FLOOR,
} from "./types";

export type {
  EpochFloor,
  LogLevel,
  SecretBundle,
  ShutdownCause,
  SluiceCoreOptions,
  SluiceDecision,
  SluiceEvent,
  SluiceHost,
} from "./types";

export type { RevocationNotice } from "@sluice/crypto";
