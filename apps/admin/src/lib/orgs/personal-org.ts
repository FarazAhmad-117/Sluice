import { newId, randomBytes, toHex } from "@sluice/crypto";
import type { MasterUnlockKey } from "@sluice/crypto";
import { createRevocationKeypair, wrapRevocationKey } from "./revocation-key";

/**
 * THE ORG A NEW ACCOUNT LANDS IN, MINTED IN THE BROWSER.
 *
 * A personal org is an ordinary org: it has a revocation key, generated here,
 * wrapped to its creator here, and published as a public key. The server gets
 * exactly what `orgs.createOrg` gets from the create-org form, and holds the
 * seed inside it no more than it does for any other org. See
 * `revocation-key.ts` for what the wrap binds.
 *
 * The slug is `personal-` and 8 random hex digits, because slugs are unique
 * and every account has a "Personal" org. 32 bits makes a collision rare, not
 * impossible; the server refuses a duplicate, and the caller retries with a
 * fresh payload (call this again: the uid and the keypair are minted per call
 * for the same reason the form mints them per submit).
 */
export async function personalOrgPayload(
  muk: MasterUnlockKey,
  userUid: string,
): Promise<{
  orgUid: string;
  name: "Personal";
  slug: string;
  revocationPublicKey: string;
  wrappedRevocationKey: string;
  revocationKeyNonce: string;
}> {
  // Minted before the wrap, because the wrap's associated data names it.
  const orgUid = newId("org");
  const keypair = createRevocationKeypair();
  const wrapped = await wrapRevocationKey(muk, keypair.privateKey, {
    orgUid,
    granteeUid: userUid,
  });
  return {
    orgUid,
    name: "Personal",
    slug: `personal-${toHex(randomBytes(4))}`,
    revocationPublicKey: keypair.revocationPublicKey,
    ...wrapped,
  };
}
