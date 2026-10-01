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
 * WHAT IT BINDS: THE ENVIRONMENT, THE KEY VERSION, AND THE GRANTEE. All four
 * of `environmentUid`, `pdkVersion`, `granteeType` and `granteeId` are
 * database columns or values a server hands back, and none of them is
 * authenticated on its own. Naming each inside the associated data is what
 * turns an edit to any of them into a grant that stops opening, instead of a
 * grant that opens and claims to be something it is not:
 *
 *   environmentUid  a grant copied from environment A onto environment B
 *                   would otherwise unwrap there and hand B's reader A's key.
 *                   The secrets it then failed to open would look like
 *                   corruption rather than the splice they are.
 *   pdkVersion      a server could otherwise roll a grant back to the wrap of
 *                   an earlier key generation, or serve an old wrap under a
 *                   newer version number, and the client would seal new
 *                   secrets under a key the environment has moved on from.
 *   grantee         a row whose grantee fields were edited must stop opening
 *                   rather than claim to belong to somebody it does not.
 *
 * An earlier revision of this file could not bind the environment, because
 * the grant is written in the same transaction that creates its environment
 * and the Convex document id did not exist at wrap time. The environment's
 * PERMANENT id, `env_` plus 32 hex from `newId("env")`, is minted by this
 * client BEFORE the wrap and sent to `createEnvironment` as an argument, so the
 * id the grant is bound to is known at the moment it is sealed. The Convex
 * document id is still not bound and must never be: it is local to one
 * deployment and is re-minted when an org moves cells.
 *
 * A SUCCESSFUL UNWRAP AUTHENTICATES THE ENVIRONMENT UID. That is the property
 * the rest of this directory leans on. The uid a reader passes here comes from
 * `environments.getEnvironment`, which a hostile server could answer with any
 * well formed string; if it lies, the AEAD rejects and nothing opens. So once
 * a grant has opened under a uid, that uid is the one its wrapper bound it to,
 * and {@link EnvironmentKey} carries it beside the key so every secret sealed
 * or opened afterwards is bound to the same, now verified, value.
 */

/**
 * 32 bytes. AES-GCM also accepts 16 and 24 byte keys, so a short key would
 * silently import as AES-128 rather than failing, which is why `@sluice/crypto`
 * checks the width and why this constant is stated rather than implied.
 */
export const PDK_BYTES = 32;

/**
 * Which grant a wrap is, in the exact shape `pdkAssociatedData` takes.
 *
 * `granteeId` is the user's permanent `usr_` uid (`session.userUid`) for a
 * user grant, NEVER their Convex `users` document id (`session.userId`), and
 * the token id hash for a token grant. `pdkAssociatedData` refuses anything
 * else by shape, so passing the document id fails at the call rather than
 * sealing a grant nobody can rebuild the associated data for.
 */
export interface PdkGrantee {
  /** The environment's permanent `env_` id. Never the Convex `environmentId`. */
  readonly environmentUid: string;
  /** The key generation this wrap is of. A new environment starts at 1. */
  readonly pdkVersion: number;
  readonly granteeType: PDKGranteeType;
  readonly granteeId: string;
}

/**
 * AN OPENED PROJECT DATA KEY, TOGETHER WITH THE SLOT IT WAS OPENED FOR.
 *
 * The key alone is not enough to seal or open a secret: the associated data
 * also names the environment's permanent uid, and that uid must come from the
 * ENVIRONMENT, never from a column on the secret row being opened (a row's
 * columns are exactly what an attacker with write access edits). Carrying the
 * uid beside the key, as the value the grant was just verified under, makes
 * the right source the only one available: nothing in `seal.ts` or
 * `decrypt.ts` takes an environment uid from anywhere else.
 *
 * `pdkVersion` is the version the grant was opened under, and is what a write
 * states to the server as the key generation it sealed with.
 *
 * Held in memory only. `pdk` is 32 raw bytes and is never logged, persisted or
 * serialised; this object is never spread into a request.
 */
export interface EnvironmentKey {
  readonly pdk: Uint8Array;
  readonly environmentUid: string;
  readonly pdkVersion: number;
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
 * caller's permanent `usr_` uid, `session.userUid`. `environmentUid` is the
 * environment's `uid` as `environments.getEnvironment` returns it, and
 * `pdkVersion` is the grant's own `pdkVersion` as `getMyPdkGrant` returns it.
 * Both are untrusted on arrival and both are authenticated by this call: if
 * either is not what the wrapper bound, the open fails.
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
