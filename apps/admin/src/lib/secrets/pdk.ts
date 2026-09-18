import { fromHex, pdkAssociatedData, randomBytes, seal, toHex, unseal } from "@sluice/crypto";
import type { MasterUnlockKey, PDKGranteeType } from "@sluice/crypto";

/**
 * THE PROJECT DATA KEY, MINTED AND WRAPPED IN THE BROWSER.
 *
 * A project data key is the AES-256 key every secret in one environment is
 * sealed under. It is generated HERE, on the client, and this application is
 * the only place it ever exists in plaintext. The server receives two hex
 * strings, has never held the key inside them, and must never be able to: that
 * is the zero-knowledge property, and it is the reason
 * `environments.createEnvironment` takes key material as an argument instead of
 * producing it.
 *
 * ASSOCIATED DATA COMES FROM `@sluice/crypto` AND NEVER FROM A SERVER.
 * `pdkAssociatedData` is the single definition of the rule, it is shared with
 * the backend and the SDK, and the prefix it joins is deliberately not
 * exported, so the only way to obtain those bytes is to call it. A server that
 * could choose the associated data could hand a client the bytes of a different
 * grant.
 *
 * WHAT IT BINDS, AND WHAT IT CANNOT. The wrap names the GRANTEE, because
 * `granteeType` and `granteeId` are database columns and a column is not
 * authenticated: a row whose grantee fields were edited must stop opening
 * rather than claim to belong to somebody it does not. It does NOT name the
 * environment, and that is not an oversight. The grant is written in the same
 * transaction that creates its environment, so at wrap time the environment has
 * no id yet; the environment binding that matters is carried by every secret
 * ciphertext through `secretAssociatedData`. The full argument is on
 * `pdkAssociatedData` itself.
 */

/**
 * 32 bytes. AES-GCM also accepts 16 and 24 byte keys, so a short key would
 * silently import as AES-128 rather than failing, which is why `@sluice/crypto`
 * checks the width and why this constant is stated rather than implied.
 */
export const PDK_BYTES = 32;

/** Who a grant is wrapped to, in the exact shape `pdkAssociatedData` takes. */
export interface PdkGrantee {
  readonly granteeType: PDKGranteeType;
  readonly granteeId: string;
}

/**
 * The two fields `environments.createEnvironment` takes, named exactly as it
 * names them.
 *
 * The names are not cosmetic. The MUTATION calls the nonce `pdkNonce` and the
 * QUERY that reads the grant back calls it `nonce`, because the query returns
 * the row's own column. A wrapper that invented a third spelling would make it
 * possible to pair a blob with the wrong nonce at one of the two call sites,
 * and the result would be a grant that never opens.
 */
export interface WrappedProjectDataKey {
  readonly wrappedPDK: string;
  readonly pdkNonce: string;
}

/** The two fields `environments.getMyPdkGrant` returns, named as it names them. */
export interface ProjectDataKeyGrant {
  readonly wrappedPDK: string;
  readonly nonce: string;
}

export class PdkUnwrapError extends Error {
  constructor() {
    // Deliberately silent about which input was wrong. AES-GCM reports a bare
    // `OperationError`, and a wrong master unlock key, a tampered blob and a
    // grantee that does not match all look identical. Inventing a distinction
    // would turn this into a decryption oracle. It also echoes none of its
    // inputs: an error string travels into places key material must not.
    super("The project data key for this environment could not be opened.");
    this.name = "PdkUnwrapError";
  }
}

/**
 * A fresh project data key, from the platform CSPRNG.
 *
 * One key per environment, generated once, at creation. Nothing re-derives it:
 * it is random rather than derived precisely so that it can be wrapped to a new
 * grantee later without anybody having to reproduce a derivation.
 */
export function createProjectDataKey(): Uint8Array {
  return randomBytes(PDK_BYTES);
}

/**
 * Wraps a project data key to one grantee under their master unlock key.
 *
 * The MUK is the root of the account's key hierarchy and is passed as a
 * `MasterUnlockKey` instance rather than as bytes, so that it cannot be
 * serialised into a log by accident on the way here. `.bytes` is the one
 * deliberate unwrap and the array is handed straight to `seal`.
 */
export async function wrapProjectDataKey(
  muk: MasterUnlockKey,
  pdk: Uint8Array,
  grantee: PdkGrantee,
): Promise<WrappedProjectDataKey> {
  // Checked here as well as inside `seal`, because `seal` checks the KEY width
  // and nothing would otherwise check the PLAINTEXT. A 16 byte project data key
  // wraps and stores perfectly and fails on the day something tries to use it
  // as an AES-256 key.
  if (pdk.length !== PDK_BYTES) {
    throw new Error(`a project data key must be ${PDK_BYTES} bytes, got ${pdk.length}`);
  }
  const box = await seal(muk.bytes, pdk, pdkAssociatedData(grantee));
  return { wrappedPDK: toHex(box.ciphertext), pdkNonce: toHex(box.nonce) };
}

/**
 * Opens a grant read back from `environments.getMyPdkGrant`.
 *
 * `grantee` must be the CALLER'S OWN identity, because the only grant anybody
 * can read is their own: `granteeType` is `"user"` and `granteeId` is the
 * caller's `users` document id, spelled exactly as the server stores it.
 *
 * A rejection means the data is not authentic and the undecrypted bytes are
 * never used. It must not be swallowed and it must not be retried against a
 * second construction.
 */
export async function unwrapProjectDataKey(
  muk: MasterUnlockKey,
  grant: ProjectDataKeyGrant,
  grantee: PdkGrantee,
): Promise<Uint8Array> {
  // Outside the `try`, so that a malformed grantee is reported as the argument
  // error it is rather than being folded into the opaque AEAD failure.
  const aad = pdkAssociatedData(grantee);
  try {
    return await unseal(
      muk.bytes,
      { ciphertext: fromHex(grant.wrappedPDK), nonce: fromHex(grant.nonce) },
      aad,
    );
  } catch {
    throw new PdkUnwrapError();
  }
}
