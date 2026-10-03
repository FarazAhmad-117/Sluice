import { listOf } from "@/lib/list-of";
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

/**
 * THE SERVER'S SIZE LIMITS, CHECKED BEFORE ANYTHING IS SEALED.
 *
 * `convex/secrets.ts` refuses a value over 64 KiB and a name over 256 bytes,
 * both measured on the PLAINTEXT in UTF-8 (it derives the plaintext length
 * from the ciphertext). The same numbers, the same unit, here: a character
 * outside ASCII counts for two to four bytes, so an emoji-heavy value hits the
 * limit sooner than its length suggests. Saying so before sealing beats
 * sealing and being refused.
 */
export const MAX_VALUE_BYTES = 64 * 1024;
export const MAX_NAME_BYTES = 256;

const encoder = new TextEncoder();

export function utf8Bytes(text: string): number {
  return encoder.encode(text).length;
}

/** "Values can be up to 64 KB.", or `null`. */
export function secretValueProblem(value: string): string | null {
  return utf8Bytes(value) > MAX_VALUE_BYTES ? "Values can be up to 64 KB." : null;
}

export function secretKeyProblem(name: string): string | null {
  if (name.length === 0) return "Enter a key.";
  // Before the pattern, so an over-long key gets the sentence that fixes it.
  // Keys are ASCII once they pass the pattern, so bytes and characters agree.
  if (utf8Bytes(name) > MAX_NAME_BYTES) return "Names can be up to 256 characters.";
  if (!SECRET_KEY.test(name)) {
    return "Use letters, digits and underscores, not starting with a digit.";
  }
  return null;
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
