import { newId } from "@sluice/crypto";
import type { EnvironmentKey } from "./pdk";
import { newSecretSlot, sealSecret } from "./seal";
import type { SealedSecretFields } from "./seal";

/**
 * ONE SECRET FOR "ALL ENVIRONMENTS", SEALED ONCE PER ENVIRONMENT.
 *
 * Every environment keeps its own project data key, so there is no single
 * ciphertext that several environments can share. A shared secret is instead N
 * independent rows, one per environment, each with its own fresh `sec_` uid and
 * sealed under THAT environment's key for THAT environment's uid (both carried
 * by its {@link EnvironmentKey}, never read off a row). A row copied into
 * another environment does not open there.
 *
 * The rows are linked by a fresh `shr_` share id. That link is plaintext
 * metadata bound into no ciphertext (see `shr_` in
 * `packages/crypto/src/ids.ts`): the server could regroup rows, which changes
 * how the dashboard labels them, and could not make any row open under the
 * wrong environment, secret or version.
 *
 * An environment with an `override` gets its own value sealed in place of the
 * shared one and is marked `overridden`. An empty string is a real override
 * (an environment that deliberately sets the variable to nothing), so the test
 * is `!== undefined`, never truthiness.
 */

export interface SharedSecretEnvironment {
  /** The Convex `environmentId` the row is written to. Not bound into anything. */
  readonly environmentId: string;
  readonly key: EnvironmentKey;
  /** This environment's own value, in place of the shared one. */
  readonly override?: string;
}

export interface SharedSecretInput {
  readonly name: string;
  /** The shared value. */
  readonly value: string;
  readonly environments: readonly SharedSecretEnvironment[];
}

export interface SharedSecretRow extends SealedSecretFields {
  readonly environmentId: string;
  readonly secretUid: string;
  readonly version: 1;
  readonly pdkVersion: number;
  readonly overridden: boolean;
}

/** Named exactly as `secrets.createSharedSecret` names its arguments. */
export interface SharedSecretPayload {
  readonly shareUid: string;
  readonly rows: readonly SharedSecretRow[];
}

export async function sealSharedSecret(input: SharedSecretInput): Promise<SharedSecretPayload> {
  const { name, value, environments } = input;
  // The server refuses each of these too; refusing here means nothing is
  // sealed for a call that cannot succeed.
  if (environments.length === 0) {
    throw new Error("A shared secret needs at least one environment.");
  }
  if (environments.every((environment) => environment.override !== undefined)) {
    throw new Error("At least one environment must use the shared value.");
  }
  const seen = new Set<string>();
  for (const environment of environments) {
    if (seen.has(environment.environmentId)) {
      throw new Error("An environment is listed more than once.");
    }
    seen.add(environment.environmentId);
  }

  const shareUid = newId("shr");
  const rows: SharedSecretRow[] = [];
  for (const environment of environments) {
    const slot = newSecretSlot();
    const overridden = environment.override !== undefined;
    const sealed = await sealSecret(environment.key, {
      ...slot,
      name,
      value: environment.override ?? value,
    });
    rows.push({
      environmentId: environment.environmentId,
      secretUid: slot.secretUid,
      version: 1,
      // The generation this row was sealed under, which the server checks
      // against the environment's current one.
      pdkVersion: environment.key.pdkVersion,
      overridden,
      ...sealed,
    });
  }
  return { shareUid, rows };
}
