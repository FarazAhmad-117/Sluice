import { fromHex, secretAssociatedData, unseal } from "@sluice/crypto";

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
 * That chain is complete and these functions run against real rows. An earlier
 * revision of this comment said the opposite, and said it correctly at the
 * time: `createEnvironment` then took a project and a name, no Convex function
 * read or wrote `pdkGrants`, and every secret in the product was ciphertext
 * under a key no client could obtain. `createEnvironment` now mints the
 * creator's grant in the same transaction that creates the environment.
 *
 * WHAT IS STILL MISSING, STATED PLAINLY BECAUSE IT DETERMINES WHAT THIS PAGE
 * CAN SHOW. Nothing wraps an existing project data key to a SECOND member of an
 * org. `createEnvironment` mints exactly one grant, to its creator, so every
 * other member of the org is a member who can list an environment's rows and
 * open none of them. `getMyPdkGrant` refuses them with the shared refusal, and
 * the surface above must treat that as "no key for this environment" rather
 * than as an error, because it is the normal state of a colleague.
 *
 * ASSOCIATED DATA COMES FROM `@sluice/crypto`, NEVER FROM THE SERVER. The rule
 * is `utf8("sluice/secret/v1|" + environmentId)`, it is defined once on
 * `secretAssociatedData`, and the prefix it joins is deliberately not exported
 * so that the only way to obtain those bytes is to call the function. A client
 * must pin it rather than fetch it: a server that could choose the associated
 * data could hand a client the associated data of a different environment and
 * undo the environment binding entirely, which is the one property that binding
 * exists to provide. `convex/lib/aad.ts` used to carry a second, laxer copy of
 * this rule and has been deleted; the package is the only authority.
 */

/** The fields an open needs. Nothing here reads anything else off a row. */
export interface OpenableSecretRow {
  readonly environmentId: string;
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly valueCiphertext: string;
  readonly valueNonce: string;
}

/** A row exactly as `secrets.listSecrets` returns it. */
export interface SealedSecretRow extends OpenableSecretRow {
  readonly secretId: string;
  readonly lineageId: string;
  readonly version: number;
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
 * The associated data for one row.
 *
 * The environment id comes from the ROW, not from an argument beside it. Taking
 * it separately would let a caller pass the wrong one and silently bind the
 * wrong associated data, which fails as an opaque rejection at some later date.
 *
 * The NAMED field, not a bare string: `secretAssociatedData` takes an object so
 * that a diff which swaps a project id for an environment id is visible.
 */
function aadFor(row: OpenableSecretRow): Uint8Array {
  return secretAssociatedData({ environmentId: row.environmentId });
}

async function open(
  pdk: Uint8Array,
  aad: Uint8Array,
  ciphertext: string,
  nonce: string,
): Promise<string> {
  try {
    const plaintext = await unseal(
      pdk,
      { ciphertext: fromHex(ciphertext), nonce: fromHex(nonce) },
      aad,
    );
    return decoder.decode(plaintext);
  } catch {
    // `fromHex` and `decoder.decode` are inside the `try` on purpose. A row
    // that is not hex, and a plaintext that is not UTF-8, are both rows this
    // client did not write, and both must fail as "not authentic" rather than
    // as a parse error carrying the offending bytes in its message.
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
 * nobody asked to reveal, and would live for as long as that list did.
 *
 * `pdk` is 32 raw bytes. It is NOT logged, NOT stored, and is held only in
 * memory for as long as the vault is unlocked.
 */
export async function openSecretName(pdk: Uint8Array, row: OpenableSecretRow): Promise<string> {
  return await open(pdk, aadFor(row), row.nameCiphertext, row.nameNonce);
}

/**
 * Opens one row's VALUE. Call it at the moment a value is revealed and let the
 * result go out of scope when it is hidden again.
 */
export async function openSecretValue(pdk: Uint8Array, row: OpenableSecretRow): Promise<string> {
  return await open(pdk, aadFor(row), row.valueCiphertext, row.valueNonce);
}

/**
 * Opens both fields of one row.
 *
 * The complete round trip, and what the end-to-end test asserts. Surfaces that
 * show a list should prefer {@link openSecretName}, so that a value is
 * decrypted only when it is asked for.
 */
export async function openSecret(
  pdk: Uint8Array,
  row: OpenableSecretRow,
): Promise<OpenedSecret> {
  const aad = aadFor(row);
  const [name, value] = await Promise.all([
    open(pdk, aad, row.nameCiphertext, row.nameNonce),
    open(pdk, aad, row.valueCiphertext, row.valueNonce),
  ]);
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
