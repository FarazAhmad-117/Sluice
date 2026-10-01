import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import {
  MasterUnlockKey,
  newId,
  randomBytes,
  signRevocation,
  toHex,
  verifyRevocation,
} from "@sluice/crypto";
import {
  REVOCATION_KEY_BYTES,
  RevocationKeyUnwrapError,
  createRevocationKeypair,
  revocationKeyMatches,
  unwrapRevocationKey,
  wrapRevocationKey,
} from "../src/lib/orgs/revocation-key";

/**
 * THE CLIENT HALF OF THE ORGANISATION REVOCATION KEY.
 *
 * This is the key the whole product is sold on: the only thing that can sign a
 * notice an SDK will honour, generated in a browser, wrapped under the master
 * unlock key, and never held by the server. Every assertion below stands for a
 * state that creates, stores and lists perfectly and fails exactly once --
 * during the incident revocation exists for.
 *
 * The associated data names the org's permanent `org_` uid and the grantee's
 * permanent `usr_` uid. Both are minted before the wrap (the org uid by the
 * creating browser, the user uid at signup), which is what lets the org be
 * bound at all: the Convex document id does not exist when the wrap is made,
 * the permanent uid does. What the associated data still cannot bind is the
 * published public key, which is why `revocationKeyMatches` is tested below.
 */

/** A deterministic stand-in for a real derivation. Not a real key. */
function fixedKey(fill = 9): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(fill));
}

const GRANTEE = { orgUid: newId("org"), granteeUid: newId("usr") } as const;
const OTHER_GRANTEE = { ...GRANTEE, granteeUid: newId("usr") } as const;
/** The same member, filed under another org. */
const OTHER_ORG = { ...GRANTEE, orgUid: newId("org") } as const;

describe("createRevocationKeypair", () => {
  it("produces a 32 byte Ed25519 seed and its public key in canonical hex", () => {
    const pair = createRevocationKeypair();
    expect(REVOCATION_KEY_BYTES).toBe(32);
    expect(pair.privateKey).toHaveLength(REVOCATION_KEY_BYTES);
    // `createOrg` checks exactly this shape, and `verifyRevocation` rejects an
    // uppercase spelling of the same bytes rather than folding it.
    expect(pair.revocationPublicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is different every time", () => {
    // One repeated keypair across two orgs would let either org's admin revoke
    // the other's fleet, and nothing anywhere would report it.
    const keys = new Set(Array.from({ length: 8 }, () => createRevocationKeypair().revocationPublicKey));
    expect(keys.size).toBe(8);
  });

  it("returns halves that actually belong together", () => {
    const pair = createRevocationKeypair();
    expect(toHex(ed25519.getPublicKey(pair.privateKey))).toBe(pair.revocationPublicKey);
  });

  it("signs notices its own public key verifies", () => {
    const pair = createRevocationKeypair();
    const notice = {
      tokenId: "ab".repeat(16),
      epoch: 1,
      revokedAt: 1_800_000_000_000,
      reason: "Laptop stolen.",
    };
    const signature = signRevocation(pair.privateKey, notice);
    expect(verifyRevocation(pair.revocationPublicKey, notice, signature)).toBe(true);
  });
});

describe("wrapRevocationKey", () => {
  it("produces exactly the two fields createOrg takes", async () => {
    // Named to match `orgs.createOrg`'s arguments so a call site cannot pair
    // the blob with the wrong field. The server checks the nonce width, because
    // AES-GCM accepts any width and derives its counter block through GHASH for
    // anything other than 96 bits, and checks only non-empty on the blob.
    const wrapped = await wrapRevocationKey(
      fixedKey(),
      createRevocationKeypair().privateKey,
      GRANTEE,
    );
    expect(Object.keys(wrapped).sort()).toEqual(["revocationKeyNonce", "wrappedRevocationKey"]);
    expect(wrapped.revocationKeyNonce).toMatch(/^[0-9a-f]{24}$/);
    expect(wrapped.wrappedRevocationKey).toMatch(/^[0-9a-f]{96}$/);
  });

  it("never emits the plaintext seed", async () => {
    const pair = createRevocationKeypair();
    const wrapped = await wrapRevocationKey(fixedKey(), pair.privateKey, GRANTEE);
    expect(JSON.stringify(wrapped)).not.toContain(toHex(pair.privateKey));
  });

  it("uses a fresh nonce every time, so one key never wraps twice under one nonce", async () => {
    const muk = fixedKey();
    const pair = createRevocationKeypair();
    const nonces = new Set<string>();
    for (let i = 0; i < 8; i += 1) {
      nonces.add(
        (await wrapRevocationKey(muk, pair.privateKey, GRANTEE))
          .revocationKeyNonce,
      );
    }
    expect(nonces.size).toBe(8);
  });

  it("refuses to wrap anything that is not a 32 byte seed", async () => {
    // A short seed wraps and stores perfectly and fails on the day somebody
    // tries to sign with it, which is the day it mattered.
    for (const length of [0, 16, 31, 33, 64]) {
      await expect(
        wrapRevocationKey(fixedKey(), new Uint8Array(length), GRANTEE),
      ).rejects.toThrow(/32 bytes/);
    }
  });

  /**
   * A Convex document id is in the list on purpose: it is what `session.userId`
   * and `orgId` hold, and passing one where the permanent uid belongs must fail
   * at the call rather than seal a grant keyed by nothing the server stores.
   */
  it("refuses a Convex document id as the org", async () => {
    await expect(
      wrapRevocationKey(fixedKey(), randomBytes(32), { ...GRANTEE, orgUid: "jd7abcorgid0000000000000" }),
    ).rejects.toThrow(/orgUid must be a well-formed org id/);
  });

  it("refuses a malformed grantee id rather than binding to the domain alone", async () => {
    for (const bad of ["", "a|b", "user id", "\uD800", "k17abcuserid00000000000000"]) {
      await expect(
        wrapRevocationKey(fixedKey(), randomBytes(32), { ...GRANTEE, granteeUid: bad }),
      ).rejects.toThrow(/granteeUid/);
    }
  });
});

describe("unwrapRevocationKey", () => {
  it("round trips the seed the browser generated", async () => {
    const muk = fixedKey();
    const pair = createRevocationKeypair();
    const wrapped = await wrapRevocationKey(muk, pair.privateKey, GRANTEE);

    // Field names change across the wire: the MUTATION calls the nonce
    // `revocationKeyNonce` and the QUERY that reads the row back calls it
    // `nonce`, because the query returns the row's own column.
    const opened = await unwrapRevocationKey(
      muk,
      { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
      GRANTEE,
    );
    expect(toHex(opened)).toBe(toHex(pair.privateKey));
  });

  /**
   * THE BINDING THAT EARNS THE ASSOCIATED DATA. `revocationGrants.granteeId` is
   * a column, and a column is not authenticated: without this, a row whose
   * grantee was edited would keep opening and claim to belong to somebody it
   * does not.
   */
  it("refuses a grant addressed to a different grantee", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), GRANTEE);
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
        OTHER_GRANTEE,
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  /**
   * THE BINDING THIS REVISION ADDS. `revocationGrants.orgId` is a column too: a
   * grant moved onto another org must not open there and hand that org's
   * signer this org's kill switch.
   */
  it("refuses a grant filed under a different org", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), GRANTEE);
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
        OTHER_ORG,
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  it("refuses a different master unlock key", async () => {
    const wrapped = await wrapRevocationKey(fixedKey(1), randomBytes(32), GRANTEE);
    await expect(
      unwrapRevocationKey(
        fixedKey(2),
        { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
        GRANTEE,
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  it("refuses a tampered blob", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), GRANTEE);
    const flipped = `${wrapped.wrappedRevocationKey.slice(0, -1)}${
      wrapped.wrappedRevocationKey.endsWith("0") ? "1" : "0"
    }`;
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: flipped, nonce: wrapped.revocationKeyNonce },
        GRANTEE,
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  /**
   * A PROJECT DATA KEY IS WRAPPED UNDER THE SAME MASTER UNLOCK KEY, so the
   * domain in the associated data is the only thing keeping the two blobs
   * apart. A `pdkGrants.wrappedPDK` written into `revocationGrants` must fail
   * rather than open as a signing key.
   */
  it("refuses a project data key wrap presented as a revocation grant", async () => {
    const muk = fixedKey();
    const { wrapProjectDataKey } = await import("../src/lib/secrets/pdk");
    const pdkWrap = await wrapProjectDataKey(muk, randomBytes(32), {
      environmentUid: newId("env"),
      pdkVersion: 1,
      granteeType: "user",
      granteeId: GRANTEE.granteeUid,
    });
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: pdkWrap.wrappedPDK, nonce: pdkWrap.pdkNonce },
        GRANTEE,
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  it("says nothing about which input was wrong", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), GRANTEE);
    const error: unknown = await unwrapRevocationKey(
      fixedKey(2),
      { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
      GRANTEE,
    ).then(
      () => null,
      (cause: unknown) => cause,
    );

    expect(error).toBeInstanceOf(RevocationKeyUnwrapError);
    // Distinguishing a wrong key from a wrong grantee would make this a
    // decryption oracle, and echoing the blob would put ciphertext in a log.
    const message = (error as Error).message;
    expect(message).not.toContain(wrapped.wrappedRevocationKey);
    expect(message).not.toContain(GRANTEE.granteeUid);
    expect(message).not.toContain(GRANTEE.orgUid);
  });

  it("reports a malformed grantee id as the argument error it is", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), GRANTEE);
    // Outside the AEAD `try`, so a caller can tell "you passed nonsense" from
    // "this did not authenticate".
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
        { ...GRANTEE, granteeUid: "" },
      ),
    ).rejects.toThrow(/granteeUid/);
  });
});

describe("revocationKeyMatches", () => {
  /**
   * AES-GCM authenticates the blob. It says NOTHING about whether the blob and
   * the `orgs.revocationPublicKey` column belong together, because that column
   * is not in the associated data and cannot be: it is a separate row an
   * operator can edit on its own. Without this check the failure is a signature
   * the server rejects with "not signed by the organisation's revocation key",
   * during the incident, with no clue why.
   */
  it("accepts the pair it was generated as", () => {
    const pair = createRevocationKeypair();
    expect(revocationKeyMatches(pair.privateKey, pair.revocationPublicKey)).toBe(true);
  });

  it("rejects a seed that belongs to another org's public key", () => {
    const mine = createRevocationKeypair();
    const theirs = createRevocationKeypair();
    expect(revocationKeyMatches(mine.privateKey, theirs.revocationPublicKey)).toBe(false);
  });

  it("rejects an uppercase spelling of the right key, as verifyRevocation does", () => {
    const pair = createRevocationKeypair();
    expect(revocationKeyMatches(pair.privateKey, pair.revocationPublicKey.toUpperCase())).toBe(
      false,
    );
  });

  it("returns false rather than throwing on junk", () => {
    const pair = createRevocationKeypair();
    for (const bad of ["", "zz".repeat(32), "ab", "ab".repeat(31)]) {
      expect(revocationKeyMatches(pair.privateKey, bad)).toBe(false);
    }
  });
});
