/**
 * THE COMMAND THE DASHBOARD TELLS A PERSON TO RUN, IN ONE PLACE.
 *
 * Shown on the Overview ("Run locally", and step three of the checklist) and
 * at the foot of the secret detail panel, as the approved Round 3 mocks draw
 * it. Kept in one function so that when the CLI's flags change, every place
 * that prints the command changes with them.
 *
 * KNOWN GAP, STATED HERE SO IT IS NOT FORGOTTEN: `packages/cli` today reads
 * its project and environment from a service token (`SLUICE_TOKEN`) and does
 * not parse `--project` or `--env`; and the dashboard cannot mint a token yet.
 */
export function runCommand(projectSlug: string, environmentName: string): string {
  return `sluice run --project ${projectSlug} --env ${environmentName} -- npm run dev`;
}
