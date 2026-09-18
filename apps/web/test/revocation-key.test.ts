import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import {
  MasterUnlockKey,
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
 * `granteeId` is the `users` document id the grant is wrapped to, spelled
 * exactly as `revocationGrants.granteeId` stores it. It is the ONLY thing bound
 * into the associated data besides the domain, and the reason the org id is not
 * there is on `revocationKeyAssociatedData` in `@sluice/crypto`: `createOrg`
 * takes this wrap as an argument, so at wrap time the org does not exist.
 */

/** A deterministic stand-in for a real derivation. Not a real key. */
function fixedKey(fill = 9): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(fill));
}

const GRANTEE = "k17abcuserid00000000000000";
const OTHER_GRANTEE = "k17abcuserid00000000000001";

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
    const wrapped = await wrapRevocationKey(fixedKey(), createRevocationKeypair().privateKey, {
      granteeId: GRANTEE,
    });
    expect(Object.keys(wrapped).sort()).toEqual(["revocationKeyNonce", "wrappedRevocationKey"]);
    expect(wrapped.revocationKeyNonce).toMatch(/^[0-9a-f]{24}$/);
    expect(wrapped.wrappedRevocationKey).toMatch(/^[0-9a-f]{96}$/);
  });

  it("never emits the plaintext seed", async () => {
    const pair = createRevocationKeypair();
    const wrapped = await wrapRevocationKey(fixedKey(), pair.privateKey, { granteeId: GRANTEE });
    expect(JSON.stringify(wrapped)).not.toContain(toHex(pair.privateKey));
  });

  it("uses a fresh nonce every time, so one key never wraps twice under one nonce", async () => {
    const muk = fixedKey();
    const pair = createRevocationKeypair();
    const nonces = new Set<string>();
    for (let i = 0; i < 8; i += 1) {
      nonces.add(
        (await wrapRevocationKey(muk, pair.privateKey, { granteeId: GRANTEE }))
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
        wrapRevocationKey(fixedKey(), new Uint8Array(length), { granteeId: GRANTEE }),
      ).rejects.toThrow(/32 bytes/);
    }
  });

  it("refuses a malformed grantee id rather than binding to the domain alone", async () => {
    for (const bad of ["", "a|b", "user id", "\uD800"]) {
      await expect(
        wrapRevocationKey(fixedKey(), randomBytes(32), { granteeId: bad }),
      ).rejects.toThrow(/granteeId/);
    }
  });
});

describe("unwrapRevocationKey", () => {
  it("round trips the seed the browser generated", async () => {
    const muk = fixedKey();
    const pair = createRevocationKeypair();
    const wrapped = await wrapRevocationKey(muk, pair.privateKey, { granteeId: GRANTEE });

    // Field names change across the wire: the MUTATION calls the nonce
    // `revocationKeyNonce` and the QUERY that reads the row back calls it
    // `nonce`, because the query returns the row's own column.
    const opened = await unwrapRevocationKey(
      muk,
      { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
      { granteeId: GRANTEE },
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
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), { granteeId: GRANTEE });
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
        { granteeId: OTHER_GRANTEE },
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  it("refuses a different master unlock key", async () => {
    const wrapped = await wrapRevocationKey(fixedKey(1), randomBytes(32), { granteeId: GRANTEE });
    await expect(
      unwrapRevocationKey(
        fixedKey(2),
        { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
        { granteeId: GRANTEE },
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  it("refuses a tampered blob", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), { granteeId: GRANTEE });
    const flipped = `${wrapped.wrappedRevocationKey.slice(0, -1)}${
      wrapped.wrappedRevocationKey.endsWith("0") ? "1" : "0"
    }`;
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: flipped, nonce: wrapped.revocationKeyNonce },
        { granteeId: GRANTEE },
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
      granteeType: "user",
      granteeId: GRANTEE,
    });
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: pdkWrap.wrappedPDK, nonce: pdkWrap.pdkNonce },
        { granteeId: GRANTEE },
      ),
    ).rejects.toThrow(RevocationKeyUnwrapError);
  });

  it("says nothing about which input was wrong", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), { granteeId: GRANTEE });
    const error: unknown = await unwrapRevocationKey(
      fixedKey(2),
      { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
      { granteeId: GRANTEE },
    ).then(
      () => null,
      (cause: unknown) => cause,
    );

    expect(error).toBeInstanceOf(RevocationKeyUnwrapError);
    // Distinguishing a wrong key from a wrong grantee would make this a
    // decryption oracle, and echoing the blob would put ciphertext in a log.
    const message = (error as Error).message;
    expect(message).not.toContain(wrapped.wrappedRevocationKey);
    expect(message).not.toContain(GRANTEE);
  });

  it("reports a malformed grantee id as the argument error it is", async () => {
    const muk = fixedKey();
    const wrapped = await wrapRevocationKey(muk, randomBytes(32), { granteeId: GRANTEE });
    // Outside the AEAD `try`, so a caller can tell "you passed nonsense" from
    // "this did not authenticate".
    await expect(
      unwrapRevocationKey(
        muk,
        { wrappedRevocationKey: wrapped.wrappedRevocationKey, nonce: wrapped.revocationKeyNonce },
        { granteeId: "" },
      ),
    ).rejects.toThrow(/granteeId/);
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
