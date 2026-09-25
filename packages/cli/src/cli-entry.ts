import { main } from "./main";

/**
 * THE ONE FILE WITH SIDE EFFECTS.
 *
 * Everything else in this package exports and nothing runs. This reads the real
 * argv, the real environment and the real signals, and hands them to
 * {@link main}, which is a pure function of its dependencies and is therefore
 * testable without a process.
 *
 * `process.exitCode` THEN A RETURN, RATHER THAN `process.exit`, IS NOT WHAT
 * HAPPENS HERE, and the difference matters. `process.exit` is immediate and
 * truncates pending writes; `exitCode` waits for the event loop to drain, and
 * the event loop is exactly what a revoked process must not be waiting on. A
 * revocation that exits when the last socket agrees to close is a revocation an
 * attacker can delay by holding a connection open. So the exit is immediate,
 * and stdout and stderr are flushed by the child's inherited handles rather
 * than by ours.
 */
main({
  // `slice(2)` drops the node binary and this script. Nothing else is stripped:
  // `parseArgv` refuses anything it does not recognise rather than guessing.
  argv: process.argv.slice(2),
  env: process.env,
  exit: (code: number) => {
    process.exit(code);
  },
  stdout: (text: string) => {
    process.stdout.write(text);
  },
  onSignal: (handler) => {
    // Only the two an operator or an orchestrator actually sends. SIGKILL
    // cannot be caught, and catching anything else would mean this supervisor
    // changing the meaning of a signal its child might have handled itself.
    process.on("SIGINT", () => handler("SIGINT"));
    process.on("SIGTERM", () => handler("SIGTERM"));
  },
});
