import { parseArgv } from "./argv";
import { ConsoleLogger } from "./node-runtime";
import { CONFIG_EXIT_CODE, run } from "./run";

/**
 * THE ENTRY POINT. ARGV IN, ONE OF FOUR THINGS OUT.
 *
 * Kept separate from `run.ts` so that the only thing this file decides is which
 * of help, version, a usage error or a supervised run happens. `bin/sluice.js`
 * is three lines on top of it.
 */

export const VERSION = "sluice-cli/v1";

export const HELP = `sluice, the secrets manager with a kill switch that works.

  sluice run -- <command> [args...]

Fetches this environment's secrets, decrypts them with a key the Sluice server
has never held, injects them into the command's environment, supervises it, and
kills it when a signed revocation notice arrives.

Environment:
  SLUICE_TOKEN                      required. The service token, slc_...
  SLUICE_ORG_REVOCATION_PUBLIC_KEY  required. Your organisation's Ed25519
                                    revocation public key, 64 lowercase hex
                                    characters. Sluice never fetches this: a
                                    server that could supply it could sign its
                                    own notices and kill every process you run.
  SLUICE_CONVEX_URL                 required. Your deployment address.
  SLUICE_CONVEX_SITE_URL            optional. The HTTP actions origin, derived
                                    from the above for convex.cloud addresses.
  SLUICE_STATE_DIR                  optional. Where the revocation epoch floor
                                    is persisted. Defaults to ~/.sluice, and it
                                    must survive a restart.
  SLUICE_DRAIN_MS                   optional, default 5000, maximum 60000.
  SLUICE_KILL_GRACE_MS              optional, default 5000. SIGTERM to SIGKILL.
  SLUICE_BOOT_TIMEOUT_MS            optional, default 30000.
  SLUICE_MAX_OFFLINE_MS             optional, default unlimited. THE ONLY
                                    setting that lets an outage stop your
                                    workload. Leave it unset unless you mean it.

Exit codes:
  0   the supervised command exited 0
  1   revoked by a signed notice, or the offline limit was reached, or the
      command failed to start with no secrets to run with
  2   configuration is wrong
  n   whatever the supervised command exited with

The service token is removed from the child's environment. Sluice never writes
a decrypted secret to disk and never prints one.
`;

export interface MainDependencies {
  readonly argv: readonly string[];
  readonly env: Record<string, string | undefined>;
  readonly exit: (code: number) => void;
  readonly stdout: (text: string) => void;
  readonly onSignal?: (handler: (signal: NodeJS.Signals) => void) => void;
}

export function main(dependencies: MainDependencies): void {
  const parsed = parseArgv(dependencies.argv);
  switch (parsed.kind) {
    case "help":
      dependencies.stdout(HELP);
      dependencies.exit(0);
      return;
    case "version":
      dependencies.stdout(`${VERSION}\n`);
      dependencies.exit(0);
      return;
    case "usage-error":
      new ConsoleLogger().log("error", "usage", parsed.message);
      dependencies.exit(CONFIG_EXIT_CODE);
      return;
    case "run":
      run(parsed.command, parsed.args, {
        env: dependencies.env,
        exit: dependencies.exit,
        ...(dependencies.onSignal === undefined ? {} : { onSignal: dependencies.onSignal }),
      });
      return;
    default:
      return;
  }
}
