import { fromHex, secretAssociatedData, unseal } from "@sluice/crypto";
import type { SecretField } from "@sluice/crypto";
import type { EnvironmentKey } from "./pdk";

/**
 * CLIENT SIDE DECRYPTION OF A SECRET ROW.
 *
 * THE CHAIN, END TO END. Every secret is sealed under the project data key for
 * its ENVIRONMENT. The wrapped copies of that key live in `pdkGrants`, one per
 * user and per service token, each sealed under something only its grantee
 * holds; for a user that is the MASTER UNLOCK KEY, derived from their password
 * in this browser and never sent anywhere. `environments.getMyPdkGrant` returns
 * the caller's own grant and no one else's, `unwrapProjectDataKey` in `pdk.ts`
 * opens it, and the functions here open the rows.
 *
 * WHAT IS STILL MISSING, STATED PLAINLY BECAUSE IT DETERMINES WHAT THIS PAGE
 * CAN SHOW. Nothing wraps an existing project data key to a SECOND member of an
 * org. `createEnvironment` mints exactly one grant, to its creator, so every
 * other member of the org is a member who can list an environment's rows and
 * open none of them. `getMyPdkGrant` refuses them with the shared refusal, and
 * the surface above must treat that as "no key for this environment" rather
 * than as an error, because it is the normal state of a colleague.
 *
 * EACH CIPHERTEXT OPENS ONLY IN THE SLOT IT WAS SEALED FOR. The associated
 * data names the environment's permanent uid, the secret's permanent uid, the
 * version and the field (`"name"` or `"value"`); `seal.ts` sets out what each
 * one stops. The environment uid comes from the {@link EnvironmentKey}, the
 * value the grant was verified under, and is never read off the row: a row's
 * `environmentId` is a Convex document id, which is not bound and must not be,
 * and the row's columns are exactly what an attacker with write access edits.
 * The row's `secretUid` and `version` ARE read off it, and that is safe for
 * the opposite reason: they are claims the ciphertext is checked against, so
 * an edited column produces a rejection rather than a wrong plaintext.
 *
 * ASSOCIATED DATA COMES FROM `@sluice/crypto`, NEVER FROM THE SERVER.
 * `secretAssociatedData` is the one definition of the rule, and the prefix it
 * joins is deliberately not exported, so the only way to obtain those bytes is
 * to call the function. This file used to quote that prefix in a comment, and
 * the quotation outlived the rule it described by a whole version. It is gone,
 * and `convex/lib/protocol.test.ts` now fails if any file under
 * `apps/admin/src` spells a crypto-owned label by hand. A client must pin the
 * rule rather than fetch it: a server that could choose the associated data
 * could hand a client the associated data of a different slot and undo the
 * binding entirely.
 */

/**
 * The fields an open needs. Nothing here reads anything else off a row, and in
 * particular nothing reads an environment from it.
 */
export interface OpenableSecretRow {
  /** The secret's permanent `sec_` id, as the server stored it. */
  readonly secretUid: string;
  /** The version this row claims to be. */
  readonly version: number;
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly valueCiphertext: string;
  readonly valueNonce: string;
}

/** A row exactly as `secrets.listSecrets` returns it. */
export interface SealedSecretRow extends OpenableSecretRow {
  /** The Convex document id. Addresses the row in mutations; bound into nothing. */
  readonly secretId: string;
  /** The Convex id of the row's environment. Display only; bound into nothing. */
  readonly environmentId: string;
  readonly pdkVersion: number;
  readonly supersededAt?: number;
}

export interface OpenedSecret {
  readonly name: string;
  readonly value: string;
}

export class SecretOpenError extends Error {
  constructor() {
    // No detail about which of key, nonce, ciphertext or associated data was
    // wrong, because WebCrypto reports a bare `OperationError` and inventing a
    // distinction would turn this into a decryption oracle. Any rejection means
    // "this data is not authentic" and the undecrypted bytes are never used.
    // It echoes no input: an error string travels into places a plaintext, and
    // even a ciphertext, should not.
    super("This secret could not be opened with the key this client holds.");
    this.name = "SecretOpenError";
  }
}

// `fatal: true`, so a plaintext that is not valid UTF-8 throws rather than
// rendering replacement characters that look like a corrupted secret and are
// really a decoding bug.
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * The associated data for one field of one row.
 *
 * The environment uid comes from the KEY, the secret uid and the version from
 * the ROW, and the field from the caller. The NAMED fields, not a joined
 * string, so that a diff which swaps one id for another is visible.
 *
 * It throws on a malformed uid or version, which a hostile row can supply, so
 * it is called INSIDE the `try` below: a row this client did not write fails
 * as "not authentic" like every other such row, rather than as an argument
 * error describing the offending column.
 */
function aadFor(key: EnvironmentKey, row: OpenableSecretRow, field: SecretField): Uint8Array {
  return secretAssociatedData({
    environmentUid: key.environmentUid,
    secretUid: row.secretUid,
    version: row.version,
    field,
  });
}

async function open(
  key: EnvironmentKey,
  row: OpenableSecretRow,
  field: SecretField,
): Promise<string> {
  const ciphertext = field === "name" ? row.nameCiphertext : row.valueCiphertext;
  const nonce = field === "name" ? row.nameNonce : row.valueNonce;
  try {
    const plaintext = await unseal(
      key.pdk,
      { ciphertext: fromHex(ciphertext), nonce: fromHex(nonce) },
      aadFor(key, row, field),
    );
    return decoder.decode(plaintext);
  } catch {
    // `aadFor`, `fromHex` and `decoder.decode` are inside the `try` on purpose.
    // A row whose uid or version is malformed, a row that is not hex, and a
    // plaintext that is not UTF-8 are all rows this client did not write, and
    // all must fail as "not authentic" rather than as an error carrying the
    // offending bytes in its message.
    throw new SecretOpenError();
  }
}

/**
 * Opens one row's NAME under the project data key for its environment.
 *
 * Names and values open separately, and that is a privacy decision rather than
 * a convenience. The dashboard lists every name and reveals a value only when
 * somebody asks. If a name could only be had by opening the whole row, every
 * value in the environment would be decrypted into memory to render a list
 * nobody asked to reveal, and would live for as long as that list did. The two
 * fields are also sealed under different associated data, so a value moved
 * into the name slot, where this list would show it unasked, does not open.
 *
 * `key.pdk` is 32 raw bytes. It is NOT logged, NOT stored, and is held only in
 * memory for as long as the vault is unlocked.
 */
export async function openSecretName(
  key: EnvironmentKey,
  row: OpenableSecretRow,
): Promise<string> {
  return await open(key, row, "name");
}

/**
 * Opens one row's VALUE. Call it at the moment a value is revealed and let the
 * result go out of scope when it is hidden again.
 */
export async function openSecretValue(
  key: EnvironmentKey,
  row: OpenableSecretRow,
): Promise<string> {
  return await open(key, row, "value");
}

/**
 * Opens both fields of one row.
 *
 * The complete round trip, and what the end-to-end test asserts. Surfaces that
 * show a list should prefer {@link openSecretName}, so that a value is
 * decrypted only when it is asked for.
 */
export async function openSecret(
  key: EnvironmentKey,
  row: OpenableSecretRow,
): Promise<OpenedSecret> {
  const [name, value] = await Promise.all([open(key, row, "name"), open(key, row, "value")]);
  return { name, value };
}

/**
 * A mask that does not leak the length of the value.
 *
 * Rendering one dot per character would publish the length of every secret to
 * anyone looking over a shoulder or at a screen share, and a length is a real
 * hint about what a value is. The mask is therefore a fixed width regardless of
 * the secret, and it is what the table shows until a row is explicitly
 * revealed.
 */
export const VALUE_MASK = "••••••••••••";
