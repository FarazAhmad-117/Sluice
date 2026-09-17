import { fromHex, secretAssociatedData, unseal } from "@sluice/crypto";

/**
 * CLIENT SIDE DECRYPTION OF A SECRET ROW.
 *
 * READ THIS BEFORE BELIEVING THE SECRETS TABLE. The functions here are correct
 * and unit tested against a round trip, and AS OF THIS COMMIT THERE IS NO WAY
 * FOR THE DASHBOARD TO OBTAIN A PROJECT DATA KEY, so they have never run
 * against a real row.
 *
 * The chain is: every secret is sealed under the project data key for its
 * ENVIRONMENT. The wrapped copies of that key live in the `pdkGrants` table,
 * one per user and per service token, each wrapped to the grantee's X25519
 * public key. The dashboard holds the X25519 private key after unlock, so it
 * has everything it needs except the grant itself.
 *
 * `convex/` exports no function that reads or writes `pdkGrants`. Grep for it:
 * the table is defined in `schema.ts`, the repository helpers exist in
 * `repo/environments.ts`, and NOTHING IN `environments.ts`, `projects.ts` OR
 * `orgs.ts` CALLS THEM. `createEnvironment` takes `projectId` and `name` and
 * nothing else, so no grant is ever created, and there is no query to fetch one.
 *
 * The consequence for this surface, stated plainly rather than hidden behind a
 * spinner: the secrets table lists real rows with real metadata and shows every
 * name and value as sealed, because they are. It does not invent plaintext and
 * it does not pretend a key is loading. When a `getMyPdkGrant` style query
 * lands, `openSecret` is what the table will call, and the only new code needed
 * is the unwrap of the grant with the account's X25519 private key.
 *
 * ASSOCIATED DATA COMES FROM `@sluice/crypto`, NEVER FROM THE SERVER. The rule
 * is `utf8("sluice/secret/v1|" + environmentId)` and `convex/lib/aad.ts` is
 * emphatic that a client must pin it rather than fetch it: a server that could
 * choose the associated data could hand a client the associated data of a
 * different environment and undo the environment binding entirely, which is the
 * one property that binding exists to provide. `secretAssociatedData` is the
 * only way to obtain those bytes, which is why the prefix itself is not
 * exported.
 */

/** A row exactly as `secrets.listSecrets` returns it. */
export interface SealedSecretRow {
  readonly secretId: string;
  readonly environmentId: string;
  readonly lineageId: string;
  readonly version: number;
  readonly pdkVersion: number;
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly valueCiphertext: string;
  readonly valueNonce: string;
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
    super("This secret could not be opened with the key this client holds.");
    this.name = "SecretOpenError";
  }
}

const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Opens one row's name and value under the project data key for its
 * environment.
 *
 * `pdk` is 32 raw bytes. It is NOT logged, NOT stored, and must be held only in
 * memory for as long as the vault is unlocked.
 */
export async function openSecret(pdk: Uint8Array, row: SealedSecretRow): Promise<OpenedSecret> {
  // The environment id on the ROW, not one passed in beside it. Taking it as a
  // separate argument would let a caller pass the wrong one and silently bind
  // the wrong associated data, which fails as an opaque rejection.
  //
  // The NAMED FIELD, not a bare string. `secretAssociatedData` takes an object
  // so that a diff which swaps a project id for an environment id is visible at
  // the call site. `convex/lib/aad.ts` still carries an older copy of this
  // function that takes a plain string and is no longer called by anything; the
  // package is the authority and the server's copy is stale.
  const aad = secretAssociatedData({ environmentId: row.environmentId });
  try {
    const [name, value] = await Promise.all([
      unseal(pdk, { ciphertext: fromHex(row.nameCiphertext), nonce: fromHex(row.nameNonce) }, aad),
      unseal(
        pdk,
        { ciphertext: fromHex(row.valueCiphertext), nonce: fromHex(row.valueNonce) },
        aad,
      ),
    ]);
    // `fatal: true`, so a plaintext that is not valid UTF-8 throws here rather
    // than rendering replacement characters that look like a corrupted secret
    // and are really a decoding bug.
    return { name: decoder.decode(name), value: decoder.decode(value) };
  } catch {
    throw new SecretOpenError();
  }
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
