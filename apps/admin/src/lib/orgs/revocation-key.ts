import { ed25519 } from "@noble/curves/ed25519";
import {
  fromHex,
  revocationKeyAssociatedData,
  seal,
  toHex,
  unseal,
} from "@sluice/crypto";
import type { MasterUnlockKey } from "@sluice/crypto";

/**
 * THE ORGANISATION REVOCATION KEY, MINTED AND WRAPPED IN THE BROWSER.
 *
 * This is the product's wedge, in one file. An organisation's revocation key is
 * the ONLY thing that can sign a notice an SDK will honour, and it is generated
 * HERE: this application is the only place its private half ever exists in
 * plaintext. The server receives a public key and two opaque hex strings, has
 * never held the seed inside them, and must never be able to.
 *
 * That is not a nicety. It is what stops a compromised Sluice deployment, a
 * compromised Convex instance or a network attacker from mass-killing customer
 * production fleets: they can deliver any bytes they like down a live
 * subscription and they cannot produce this signature.
 *
 * ASSOCIATED DATA COMES FROM `@sluice/crypto` AND NEVER FROM A SERVER.
 * `revocationKeyAssociatedData` is the single definition of the rule, shared
 * with the backend and the SDK, and the prefix it joins is deliberately not
 * exported, so the only way to obtain those bytes is to call it.
 *
 * WHAT IT BINDS: THE ORG AND THE GRANTEE. Both `revocationGrants.orgId` and
 * `revocationGrants.granteeId` are database columns, and a column is not
 * authenticated. The wrap names the org's permanent `org_` uid and the
 * grantee's permanent `usr_` uid, so a grant moved onto another org, or
 * re-filed under another member, stops opening rather than handing that org's
 * signer somebody else's kill switch.
 *
 * An earlier revision could not bind the org: the grant is written in the same
 * transaction that creates its org, and the Convex document id did not exist at
 * wrap time. The permanent uid is minted by this client with `newId("org")`
 * BEFORE the wrap and sent to `createOrg` as `orgUid`, so the value the grant
 * is bound to is known when it is sealed. The Convex document id is still not
 * bound and must never be: it is local to one deployment and is re-minted when
 * an org moves cells.
 *
 * WHAT THE ASSOCIATED DATA STILL CANNOT BIND is `orgs.revocationPublicKey`,
 * the column the server publishes and every SDK verifies notices against.
 * {@link revocationKeyMatches} closes that gap, which is why it is in this
 * file rather than in a component: a caller that has just unwrapped a seed
 * must check it against the public key the org actually publishes. That is the
 * same call `identity.ts` makes with `identityMatches`, for the same reason:
 * AEAD proves the blob was not tampered with and was filed under this org and
 * this grantee, and says nothing about whether the blob and the public column
 * belong together.
 */

/**
 * 32 bytes. An Ed25519 SEED, not the 64 byte expanded secret and not a
 * signature. `signRevocation` accepts this width and no other, and a wrong
 * width would wrap and store perfectly and fail on the day somebody tried to
 * sign with it.
 */
export const REVOCATION_KEY_BYTES = 32;

/** Who a grant is wrapped to, in the exact shape `revocationKeyAssociatedData` takes. */
export interface RevocationGrantee {
  /** The org's permanent `org_` uid. Never the Convex `orgId`. */
  readonly orgUid: string;
  /**
   * The grantee's permanent `usr_` uid, `session.userUid`. Never the Convex
   * `users` document id, `session.userId`, which `revocationKeyAssociatedData`
   * refuses by shape.
   */
  readonly granteeUid: string;
}

/**
 * A fresh organisation revocation keypair.
 *
 * The private half is SECRET and the public half is the value customers pin in
 * their own configuration, so they are returned under names that say which is
 * which. `revocationPublicKey` is spelled as `orgs.createOrg` spells it.
 */
export interface RevocationKeypair {
  /** Ed25519 seed, 32 bytes. Never serialise, log or persist this. */
  readonly privateKey: Uint8Array;
  /** Ed25519 public key, 64 lowercase hex. PUBLIC by design. */
  readonly revocationPublicKey: string;
}

/**
 * The two fields `orgs.createOrg` takes, named exactly as it names them.
 *
 * The names are not cosmetic. The MUTATION calls the nonce
 * `revocationKeyNonce` and the QUERY that reads the row back calls it `nonce`,
 * because the query returns the row's own column. A wrapper that invented a
 * third spelling would make it possible to pair a blob with the wrong nonce at
 * one of the two call sites, and the result is a grant that never opens.
 */
export interface WrappedRevocationKey {
  readonly wrappedRevocationKey: string;
  readonly revocationKeyNonce: string;
}

/** The two blob fields `orgs.getMyRevocationGrant` returns, named as it names them. */
export interface RevocationKeyGrant {
  readonly wrappedRevocationKey: string;
  readonly nonce: string;
}

export class RevocationKeyUnwrapError extends Error {
  constructor() {
    // Deliberately silent about which input was wrong. AES-GCM reports a bare
    // `OperationError`, and a wrong master unlock key, a tampered blob and a
    // grantee that does not match all look identical. Inventing a distinction
    // would turn this into a decryption oracle. It also echoes none of its
    // inputs: an error string travels into places key material must not.
    super("The revocation key for this organisation could not be opened.");
    this.name = "RevocationKeyUnwrapError";
  }
}

/**
 * Generates a fresh revocation keypair from the platform CSPRNG.
 *
 * `@noble/curves` draws from `crypto.getRandomValues`, exactly as
 * `identity.ts` does for the account keypairs. One keypair per organisation,
 * generated once, at creation: it is random rather than derived precisely so
 * that it can be wrapped to a second signer later without anybody having to
 * reproduce a derivation, which is the whole reason `revocationGrants` is a
 * table and not a column.
 */
export function createRevocationKeypair(): RevocationKeypair {
  const privateKey = ed25519.utils.randomPrivateKey();
  return {
    privateKey,
    // `toHex` is the only encoder used, because `createOrg` and
    // `verifyRevocation` both demand canonical lowercase hex and REJECT an
    // uppercase spelling of the same bytes rather than folding it.
    revocationPublicKey: toHex(ed25519.getPublicKey(privateKey)),
  };
}

/**
 * Wraps a revocation signing key to one grantee under their master unlock key.
 *
 * The MUK is passed as a `MasterUnlockKey` instance rather than as bytes, so
 * that it cannot be serialised into a log by accident on the way here.
 * `.bytes` is the one deliberate unwrap and the array is handed straight to
 * `seal`.
 */
export async function wrapRevocationKey(
  muk: MasterUnlockKey,
  privateKey: Uint8Array,
  grantee: RevocationGrantee,
): Promise<WrappedRevocationKey> {
  // Checked here as well as inside `seal`, because `seal` checks the KEY width
  // and nothing would otherwise check the PLAINTEXT. Anything other than a 32
  // byte seed wraps and stores perfectly and fails at the one moment it is
  // needed.
  if (privateKey.length !== REVOCATION_KEY_BYTES) {
    throw new Error(
      `a revocation key must be ${REVOCATION_KEY_BYTES} bytes, got ${privateKey.length}`,
    );
  }
  const box = await seal(muk.bytes, privateKey, revocationKeyAssociatedData(grantee));
  return {
    wrappedRevocationKey: toHex(box.ciphertext),
    revocationKeyNonce: toHex(box.nonce),
  };
}

/**
 * Opens a grant read back from `orgs.getMyRevocationGrant`.
 *
 * `grantee` must be the CALLER'S OWN identity, because the only grant anybody
 * can read is their own: that query takes no grantee argument at all, which is
 * its authorisation. `orgUid` is the one `getMyRevocationGrant` returns; it is
 * untrusted on arrival and authenticated by this call, because a grant filed
 * under another org does not open.
 *
 * A rejection means the data is not authentic and the undecrypted bytes are
 * never used. It must not be swallowed and it must not be retried against a
 * second construction.
 */
export async function unwrapRevocationKey(
  muk: MasterUnlockKey,
  grant: RevocationKeyGrant,
  grantee: RevocationGrantee,
): Promise<Uint8Array> {
  // Outside the `try`, so that a malformed grantee is reported as the argument
  // error it is rather than being folded into the opaque AEAD failure.
  const aad = revocationKeyAssociatedData(grantee);
  try {
    return await unseal(
      muk.bytes,
      {
        ciphertext: fromHex(grant.wrappedRevocationKey),
        nonce: fromHex(grant.nonce),
      },
      aad,
    );
  } catch {
    throw new RevocationKeyUnwrapError();
  }
}

/**
 * Checks that an unwrapped seed really is the private half of the public key
 * the organisation publishes.
 *
 * THIS IS THE CHECK THE ASSOCIATED DATA CANNOT MAKE, and it is cheap. The
 * associated data binds the org's uid and the grantee's uid, and it cannot
 * bind `orgs.revocationPublicKey`: the public key is a column the server
 * publishes, not an input to the wrap. An operator who edits that column on
 * its own, or replaces it with a key they hold, leaves a seed that unwraps
 * perfectly and signs notices this deployment and every SDK pinned to the
 * edited key would judge differently. Without this, that surfaces as "this
 * revocation notice is not signed by the organisation's revocation key" at
 * the moment somebody is trying to kill a stolen token.
 *
 * Returns `false` rather than throwing, matching `verifyRevocation`: `fromHex`
 * throws on non-hex input and a caller deciding whether to trust a key should
 * not have to distinguish that from a mismatch.
 */
export function revocationKeyMatches(privateKey: Uint8Array, revocationPublicKey: string): boolean {
  try {
    // Compared as canonical hex on both sides, so an uppercase spelling of the
    // right bytes is a mismatch here exactly as it is in `verifyRevocation`.
    // One org with two spellings is two orgs to anything that caches.
    return toHex(ed25519.getPublicKey(privateKey)) === revocationPublicKey;
  } catch {
    return false;
  }
}
