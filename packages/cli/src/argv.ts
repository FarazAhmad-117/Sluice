import { sanitiseForLog } from "@sluice/sdk";

/**
 * ARGUMENT PARSING FOR `sluice run`, AND NOTHING ELSE.
 *
 * WHY THE DOUBLE DASH IS REQUIRED RATHER THAN INFERRED. `sluice run npm start`
 * reads perfectly and is refused anyway. The moment this command accepts flags
 * of its own -- and it will, the day somebody wants `--drain-ms` on the command
 * line -- an inferring parser has to decide whether `--verbose` belongs to
 * sluice or to the child, and it will decide wrongly for somebody. Worse, the
 * wrong answer is silent: a flag swallowed here never reaches the child, and
 * the child starts subtly misconfigured. The double dash is the POSIX answer
 * and it is unambiguous forever.
 *
 * A SECOND DOUBLE DASH IS THE CHILD'S. `sluice run -- npm run build -- --prod`
 * passes `run build -- --prod` through untouched, because `npm` has its own
 * separator convention and this parser has no business editing it.
 *
 * EVERYTHING ELSE COMES FROM THE ENVIRONMENT, see `config.ts`. A service token
 * on a command line lands in shell history, in `ps` output readable by every
 * user on the box, and in any process listing a monitoring agent scrapes. There
 * is deliberately no `--token` flag and there must never be one.
 */
export type ParsedArgv =
  | { readonly kind: "run"; readonly command: string; readonly args: readonly string[] }
  | { readonly kind: "help" }
  | { readonly kind: "version" }
  | { readonly kind: "usage-error"; readonly message: string };

const RUN_USAGE = "sluice run -- npm start";

export function parseArgv(argv: readonly string[]): ParsedArgv {
  const first = argv[0];
  if (first === undefined || first === "--help" || first === "-h" || first === "help") {
    return { kind: "help" };
  }
  if (first === "--version" || first === "-v" || first === "version") {
    return { kind: "version" };
  }
  if (first !== "run") {
    // The value is echoed because a typo is the likeliest cause and naming it
    // is the only thing that helps. It goes through the SDK's sanitiser first:
    // argv reaches this process from a shell script, a Dockerfile CMD or a
    // supervisor config, any of which an attacker who can write one file can
    // fill with escape sequences aimed at the operator reading the failure.
    return {
      kind: "usage-error",
      message: `unknown command "${sanitiseForLog(first)}". The only command is: sluice run -- <command>`,
    };
  }

  const separator = argv.indexOf("--", 1);
  if (separator === -1) {
    return {
      kind: "usage-error",
      message: `sluice run needs a double dash before the command to run: ${RUN_USAGE}`,
    };
  }
  const rest = argv.slice(separator + 1);
  const command = rest[0];
  if (command === undefined || command.length === 0) {
    return {
      kind: "usage-error",
      message: `sluice run needs a command after the double dash: ${RUN_USAGE}`,
    };
  }
  return { kind: "run", command, args: rest.slice(1) };
}
