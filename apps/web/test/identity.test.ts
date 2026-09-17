import { describe, expect, it } from "vitest";
import { MasterUnlockKey, randomBytes, secretAssociatedData, seal, toHex } from "@sluice/crypto";
import {
  createIdentity,
  deriveAuthVerifier,
  identityMatches,
  unwrapIdentity,
} from "../src/lib/auth/identity";
import { normaliseEmail } from "../src/lib/auth/email";
import { openSecret } from "../src/lib/secrets/decrypt";

/**
 * THE CONSTRAINTS THAT FAIL SILENTLY, TESTED.
 *
 * Every assertion here corresponds to a failure that produces no error at the
 * moment it happens:
 *
 *  - a verifier that is not canonical hex is rejected by the server with a
 *    message about a field, after the user has filled in the form;
 *  - a wrapped blob that does not round trip produces an account whose keys
 *    cannot be opened, discovered at the first secret read;
 *  - an associated-data mismatch produces an opaque AEAD rejection months
 *    later.
 */

/** A deterministic stand-in for a real derivation. Not a real key. */
function fixedKey(): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(7));
}

const CANONICAL_HEX_32 = /^[0-9a-f]{64}$/;

describe("deriveAuthVerifier", () => {
  it("produces exactly 64 lowercase hex characters", () => {
    // `assertCanonicalHex32` on the server rejects anything else, including
    // uppercase hex and base64, and its message names only the field. This is
    // the check that stops that being discovered at signup.
    return deriveAuthVerifier(fixedKey()).then((verifier) => {
      expect(verifier).toMatch(CANONICAL_HEX_32);
    });
  });

  it("is deterministic for one key", async () => {
    const [first, second] = await Promise.all([
      deriveAuthVerifier(fixedKey()),
      deriveAuthVerifier(fixedKey()),
    ]);
    expect(first).toBe(second);
  });

  it("is not the master unlock key, nor any prefix of it", async () => {
    // The single property this construction has to have: the server learns the
    // verifier and must not thereby learn the key that unwraps everything.
    const key = fixedKey();
    const verifier = await deriveAuthVerifier(key);
    expect(verifier).not.toBe(toHex(key.bytes));
    expect(toHex(key.bytes).startsWith(verifier.slice(0, 16))).toBe(false);
  });

  it("differs for different keys", async () => {
    const a = await deriveAuthVerifier(new MasterUnlockKey(new Uint8Array(32).fill(1)));
    const b = await deriveAuthVerifier(new MasterUnlockKey(new Uint8Array(32).fill(2)));
    expect(a).not.toBe(b);
  });
});

describe("createIdentity and unwrapIdentity", () => {
  it("round trips both private keys under the same master unlock key", async () => {
    const key = fixedKey();
    const { wrapped, priv } = await createIdentity(key);

    const restored = await unwrapIdentity(key, wrapped);
    expect(toHex(restored.privateKey)).toBe(toHex(priv.privateKey));
    expect(toHex(restored.signingKey)).toBe(toHex(priv.signingKey));
  });

  it("emits public halves in canonical hex, which the server enforces", async () => {
    const { wrapped } = await createIdentity(fixedKey());
    expect(wrapped.publicKey).toMatch(CANONICAL_HEX_32);
    expect(wrapped.verifyKey).toMatch(CANONICAL_HEX_32);
  });

  it("wraps the two keys to different blobs", async () => {
    const { wrapped } = await createIdentity(fixedKey());
    expect(wrapped.wrappedPrivateKey).not.toBe(wrapped.wrappedSigningKey);
  });

  it("refuses to open a blob under a different key", async () => {
    const { wrapped } = await createIdentity(fixedKey());
    const wrongKey = new MasterUnlockKey(new Uint8Array(32).fill(9));
    await expect(unwrapIdentity(wrongKey, wrapped)).rejects.toThrow(
      /could not be opened/,
    );
  });

  it("refuses to open the two blobs swapped", async () => {
    // The purpose label in the associated data is what makes this fail. Without
    // it a database operator could exchange the two columns and hand the client
    // an agreement key where it expects a signing key.
    const key = fixedKey();
    const { wrapped } = await createIdentity(key);
    await expect(
      unwrapIdentity(key, {
        wrappedPrivateKey: wrapped.wrappedSigningKey,
        wrappedSigningKey: wrapped.wrappedPrivateKey,
      }),
    ).rejects.toThrow(/could not be opened/);
  });

  it("rejects a blob that is not in this client's format", async () => {
    await expect(
      unwrapIdentity(fixedKey(), {
        wrappedPrivateKey: "not-a-blob",
        wrappedSigningKey: "not-a-blob",
      }),
    ).rejects.toThrow(/format this client understands/);
  });

  it("confirms the private halves match the public ones", async () => {
    const { priv, pub } = await createIdentity(fixedKey());
    expect(identityMatches(priv, pub)).toBe(true);
    expect(
      identityMatches(priv, { ...pub, publicKey: "0".repeat(64) }),
    ).toBe(false);
  });
});

describe("normaliseEmail", () => {
  it("agrees with the server: trimmed and lowercased", () => {
    expect(normaliseEmail("  Faraz@Example.COM ")).toBe("faraz@example.com");
  });

  it("rejects an address with whitespace inside it", () => {
    expect(() => normaliseEmail("a b@example.com")).toThrow();
  });

  it("rejects an address with two at signs", () => {
    expect(() => normaliseEmail("a@b@example.com")).toThrow();
  });
});

describe("openSecret", () => {
  /**
   * THIS IS THE ONLY PLACE THE SECRET DECRYPTION PATH HAS EVER RUN. There is no
   * Convex function that returns a project data key, so the dashboard has never
   * opened a real row. This test seals a row the way the SDK would and proves
   * the client half is correct, which is the most that can be proven today.
   */
  const environmentId = "kg2abcdefghijklmnopqrstuvwx";

  async function sealedRow(pdk: Uint8Array, name: string, value: string) {
    const aad = secretAssociatedData({ environmentId });
    const encoder = new TextEncoder();
    const nameBox = await seal(pdk, encoder.encode(name), aad);
    const valueBox = await seal(pdk, encoder.encode(value), aad);
    return {
      secretId: "s1",
      environmentId,
      lineageId: "ab".repeat(16),
      version: 1,
      pdkVersion: 1,
      nameCiphertext: toHex(nameBox.ciphertext),
      nameNonce: toHex(nameBox.nonce),
      valueCiphertext: toHex(valueBox.ciphertext),
      valueNonce: toHex(valueBox.nonce),
    };
  }

  it("opens a row sealed under the environment's associated data", async () => {
    const pdk = randomBytes(32);
    const row = await sealedRow(pdk, "STRIPE_SECRET_KEY", "sk_live_not_a_real_key");
    await expect(openSecret(pdk, row)).resolves.toEqual({
      name: "STRIPE_SECRET_KEY",
      value: "sk_live_not_a_real_key",
    });
  });

  it("refuses a row replayed into another environment", async () => {
    // The whole point of binding the environment id into the associated data:
    // a `dev` blob copied into `prod` by someone with database write access
    // must stop decrypting rather than decrypt perfectly.
    const pdk = randomBytes(32);
    const row = await sealedRow(pdk, "A", "b");
    await expect(
      openSecret(pdk, { ...row, environmentId: "kg2zzzzzzzzzzzzzzzzzzzzzzzz" }),
    ).rejects.toThrow(/could not be opened/);
  });

  it("refuses a row under the wrong project data key", async () => {
    const row = await sealedRow(randomBytes(32), "A", "b");
    await expect(openSecret(randomBytes(32), row)).rejects.toThrow(/could not be opened/);
  });
});
