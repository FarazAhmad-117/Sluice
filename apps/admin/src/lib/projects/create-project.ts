import { newId } from "@sluice/crypto";
import type { MasterUnlockKey } from "@sluice/crypto";
import { MAX_SLUG_LENGTH } from "@/lib/naming";
import { createProjectDataKey, wrapProjectDataKey } from "@/lib/secrets/pdk";
import type { EnvironmentKey } from "@/lib/secrets/pdk";

/**
 * A NEW PROJECT, AND THE KEYS OF EVERY ENVIRONMENT IT STARTS WITH.
 *
 * `projects.createProjectWithEnvironments` creates the project and its
 * environments in one mutation, so every environment's key must be minted and
 * wrapped BEFORE the call, here, in the browser. The server receives hex it
 * cannot open; this module is the only place the keys exist in plaintext.
 */

/** The environments a person may add beside `development`, in display order. */
export const OPTIONAL_ENVIRONMENTS = ["production", "staging"] as const;

export type OptionalEnvironment = (typeof OPTIONAL_ENVIRONMENTS)[number];

/**
 * A slug suggested from a display name, for the live preview under the field.
 *
 * This is a canonicalisation and it is not injective (see `lib/naming.ts`): it
 * is only ever shown to the person, who sees the exact slug before submitting,
 * and the server still rejects anything that is not a slug. Characters outside
 * `[a-z0-9]` are not transliterated, so "café" suggests "caf" rather than
 * guessing at "cafe".
 */
export function slugFromName(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  // Cut, then trim again: the cut can land just after a hyphen.
  return slug.slice(0, MAX_SLUG_LENGTH).replace(/-+$/, "");
}

/** `development` first, always, then the chosen extras in display order, once each. */
export function environmentNames(extra: readonly OptionalEnvironment[]): string[] {
  return ["development", ...OPTIONAL_ENVIRONMENTS.filter((name) => extra.includes(name))];
}

/** One environment as `createProjectWithEnvironments` takes it, named as it names them. */
export interface SealedEnvironment {
  readonly environmentUid: string;
  readonly name: string;
  readonly wrappedPDK: string;
  readonly pdkNonce: string;
  readonly pdkVersion: 1;
}

/**
 * Mints and wraps one project data key per environment name.
 *
 * Per name this does exactly what creating a single environment does: a fresh
 * permanent `env_` uid BEFORE the wrap (the wrap's associated data names it),
 * a fresh 32 byte key, and a wrap to the creator at key version 1.
 *
 * The opened keys come back beside the payload, index for index, so a caller
 * importing a .env can seal into the new development environment without a
 * round trip to fetch and unwrap the grant it just wrote. They are memory only:
 * never log, persist or serialise `keys`, and never spread it into a request.
 *
 * Call it once per submit attempt. A retry after a refusal must mint new uids
 * and keys rather than reuse a wrap that belonged to a failed attempt.
 */
export async function sealProjectEnvironments(
  muk: MasterUnlockKey,
  userUid: string,
  names: readonly string[],
): Promise<{ payload: SealedEnvironment[]; keys: EnvironmentKey[] }> {
  const payload: SealedEnvironment[] = [];
  const keys: EnvironmentKey[] = [];
  for (const name of names) {
    const environmentUid = newId("env");
    const pdkVersion = 1;
    const pdk = createProjectDataKey();
    const wrapped = await wrapProjectDataKey(muk, pdk, {
      environmentUid,
      pdkVersion,
      granteeType: "user",
      granteeId: userUid,
    });
    payload.push({ environmentUid, name, pdkVersion, ...wrapped });
    keys.push({ pdk, environmentUid, pdkVersion });
  }
  return { payload, keys };
}
