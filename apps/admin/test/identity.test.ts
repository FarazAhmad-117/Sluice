import { describe, expect, it } from "vitest";
import { MasterUnlockKey, randomBytes, secretAssociatedData, seal, toHex } from "@sluice/crypto";
import {
  createIdentity,
  deriveAuthVerifier,
  identityMatches,
  unwrapIdentity,
} from "../src/lib/auth/identity";
import {
  EmailFormatError,
  emailLocalPart,
  isValidEmail,
  normaliseEmail,
} from "../src/lib/auth/email";
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
    expect(deriveAuthVerifier(fixedKey())).toMatch(CANONICAL_HEX_32);
  });

  it("is deterministic for one key", () => {
    expect(deriveAuthVerifier(fixedKey())).toBe(deriveAuthVerifier(fixedKey()));
  });

  it("is not the master unlock key, nor any prefix of it", () => {
    // The single property this construction has to have: the server learns the
    // verifier and must not thereby learn the key that unwraps everything.
    const key = fixedKey();
    const verifier = deriveAuthVerifier(key);
    expect(verifier).not.toBe(toHex(key.bytes));
    expect(toHex(key.bytes).startsWith(verifier.slice(0, 16))).toBe(false);
  });

  it("differs for different keys", () => {
    const a = deriveAuthVerifier(new MasterUnlockKey(new Uint8Array(32).fill(1)));
    const b = deriveAuthVerifier(new MasterUnlockKey(new Uint8Array(32).fill(2)));
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

/**
 * The rule itself is tested once, in `@sluice/crypto`. What is tested here is
 * only what the dashboard wrapper adds: form copy in place of the server's
 * field-named messages, on an error `messageForUser` still recognises.
 */
describe("normaliseEmail (dashboard copy)", () => {
  it("returns the package's canonical form unchanged", () => {
    expect(normaliseEmail("  Faraz@Example.COM ")).toBe("faraz@example.com");
  });

  it("phrases a shape failure as an instruction, without echoing the input", () => {
    expect(() => normaliseEmail("a b@example.com")).toThrow(
      "Enter a single email address with no spaces.",
    );
    expect(() => normaliseEmail("a@b@example.com")).toThrow(EmailFormatError);
  });

  it("phrases a length failure as an instruction", () => {
    expect(() => normaliseEmail("   ")).toThrow(
      "Enter an email address between 1 and 254 characters.",
    );
  });

  it("keeps the error name auth-context matches on", () => {
    try {
      normaliseEmail("");
    } catch (error) {
      expect((error as Error).name).toBe("EmailFormatError");
      return;
    }
    throw new Error("expected normaliseEmail to throw");
  });
});

describe("isValidEmail and emailLocalPart", () => {
  it("never throws", () => {
    expect(isValidEmail("a b@c.d")).toBe(false);
    expect(isValidEmail("ada@example.com")).toBe(true);
  });

  it("extracts the lowercased local part", () => {
    expect(emailLocalPart(" Ada@Example.com")).toBe("ada");
    expect(emailLocalPart("no-at-sign")).toBe("");
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
