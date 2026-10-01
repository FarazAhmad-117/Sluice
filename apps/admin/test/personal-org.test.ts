import { describe, expect, it } from "vitest";
import { MasterUnlockKey, newId } from "@sluice/crypto";
import { isSlug } from "../src/lib/naming";
import {
  RevocationKeyUnwrapError,
  revocationKeyMatches,
  unwrapRevocationKey,
} from "../src/lib/orgs/revocation-key";
import { personalOrgPayload } from "../src/lib/orgs/personal-org";

/**
 * THE ORG A NEW ACCOUNT LANDS IN.
 *
 * It is an ordinary org, with an ordinary revocation key minted in this
 * browser, so the same two properties hold as for any org: the wrap opens for
 * this org and this user only, and the seed inside it is the private half of
 * the public key the org will publish.
 */

/** A deterministic stand-in for a real derivation. Not a real key. */
function fixedKey(fill = 7): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(fill));
}

const USER_UID = newId("usr");

describe("personalOrgPayload", () => {
  it("is named Personal with a personal- slug the server accepts", async () => {
    const payload = await personalOrgPayload(fixedKey(), USER_UID);
    expect(payload.name).toBe("Personal");
    expect(payload.slug).toMatch(/^personal-[0-9a-f]{8}$/);
    expect(isSlug(payload.slug)).toBe(true);
    expect(payload.orgUid).toMatch(/^org_[0-9a-f]{32}$/);
  });

  it("mints a different org, slug and key every time", async () => {
    const [a, b] = await Promise.all([
      personalOrgPayload(fixedKey(), USER_UID),
      personalOrgPayload(fixedKey(), USER_UID),
    ]);
    expect(a.orgUid).not.toBe(b.orgUid);
    expect(a.slug).not.toBe(b.slug);
    expect(a.revocationPublicKey).not.toBe(b.revocationPublicKey);
  });

  it("wraps a revocation key that opens for this org and user and matches its public key", async () => {
    const muk = fixedKey();
    const payload = await personalOrgPayload(muk, USER_UID);
    const seed = await unwrapRevocationKey(
      muk,
      { wrappedRevocationKey: payload.wrappedRevocationKey, nonce: payload.revocationKeyNonce },
      { orgUid: payload.orgUid, granteeUid: USER_UID },
    );
    expect(revocationKeyMatches(seed, payload.revocationPublicKey)).toBe(true);
  });

  it("does not open for another user", async () => {
    const muk = fixedKey();
    const payload = await personalOrgPayload(muk, USER_UID);
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: payload.wrappedRevocationKey, nonce: payload.revocationKeyNonce },
        { orgUid: payload.orgUid, granteeUid: newId("usr") },
      ),
    ).rejects.toBeInstanceOf(RevocationKeyUnwrapError);
  });
});
