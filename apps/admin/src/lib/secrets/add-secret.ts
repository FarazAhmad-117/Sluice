import type { ProjectDataKeyState } from "./environment-key";
import { environmentsWithName } from "./project-secrets";

/**
 * THE ADD-SECRET DRAWER'S RULES, PURE.
 *
 * The server never sees a name, so it cannot refuse a duplicate one; this is
 * the only place that can. It compares against names this browser has
 * opened, which is why an environment whose names are not open makes the
 * check impossible and is reported as unavailable instead of being skipped.
 */

/** The same rule the .env parser applies, so an imported name and a typed one agree. */
const SECRET_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function secretKeyProblem(name: string): string | null {
  if (name.length === 0) return "Enter a key.";
  if (!SECRET_KEY.test(name)) {
    return "Use letters, digits and underscores, not starting with a digit.";
  }
  return null;
}

/** "a", "a and b", "a, b and c". */
function listOf(names: readonly string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** `NAME already exists in development.`, or `null`. */
export function duplicateProblem(
  name: string,
  environments: readonly { readonly environmentId: string; readonly name: string }[],
  namesByEnvironment: ReadonlyMap<string, ReadonlyMap<string, string>>,
): string | null {
  const taken = environmentsWithName(name, environments, namesByEnvironment);
  return taken.length === 0 ? null : `${name} already exists in ${listOf(taken)}.`;
}

/**
 * Environments a secret cannot be written to right now, each with the reason:
 * no key in hand, or names not yet open (so a duplicate cannot be ruled out).
 */
export function unavailableEnvironments(
  environments: readonly { readonly environmentId: string; readonly name: string }[],
  keys: ReadonlyMap<string, ProjectDataKeyState>,
  namesByEnvironment: ReadonlyMap<string, ReadonlyMap<string, string>>,
): { readonly name: string; readonly reason: string }[] {
  const out: { name: string; reason: string }[] = [];
  for (const environment of environments) {
    const state = keys.get(environment.environmentId);
    if (state === undefined || state.status === "idle" || state.status === "locked") {
      out.push({ name: environment.name, reason: "Its key is not open." });
    } else if (state.status === "loading") {
      out.push({ name: environment.name, reason: "Its key is still opening." });
    } else if (state.status !== "ready") {
      out.push({ name: environment.name, reason: state.message });
    } else if (!namesByEnvironment.has(environment.environmentId)) {
      out.push({ name: environment.name, reason: "Its secrets are still loading." });
    }
  }
  return out;
}
