/**
 * ERRORS SHARED ACROSS LAYERS, AND NOTHING ELSE.
 *
 * A file of its own so that `node-runtime.ts`, the adapter, can recognise an
 * error raised by `shell.ts`, the application layer, without importing a value
 * from it. The dependency points from both of them to here, never from the
 * adapter to the shell. Deliberately not exported from `index.ts`: it is an
 * internal signal between two files of this package, not an API.
 */

/**
 * The shutdown logic failed and no `onFatal` was supplied. Thrown by the
 * shell's `#pump` so the failure reaches a process-level hook, and recognised
 * by both transport guards so it is never logged and dropped on the way.
 */
export class ShellFatalError extends Error {
  constructor(cause: unknown) {
    super("the Sluice shutdown logic failed", { cause });
    this.name = "ShellFatalError";
  }
}
