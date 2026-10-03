/**
 * THE COMMAND THE DASHBOARD TELLS A PERSON TO RUN, IN ONE PLACE.
 *
 * Shown on the Overview ("Run locally", and step three of the checklist) and
 * at the foot of the secret detail panel. Kept in one function so that when
 * the CLI's interface changes, every place that prints the command changes
 * with it.
 *
 * It names no project and no environment because the CLI takes neither: the
 * service token in `SLUICE_TOKEN` IS the environment (`packages/cli/src/argv.ts`
 * parses `run -- <command>` and nothing else). Each environment's setup page
 * hands out that token and the lines that set it.
 */
export function runCommand(): string {
  return "sluice run -- npm run dev";
}
