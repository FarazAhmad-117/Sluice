import { describe, expect, it } from "vitest";
import { MasterUnlockKey, fromHex, randomBytes, toHex } from "@sluice/crypto";
import {
  PDK_BYTES,
  PdkUnwrapError,
  createProjectDataKey,
  unwrapProjectDataKey,
  wrapProjectDataKey,
} from "../src/lib/secrets/pdk";
import { sealSecret } from "../src/lib/secrets/seal";
import {
  SecretOpenError,
  openSecret,
  openSecretName,
  openSecretValue,
} from "../src/lib/secrets/decrypt";

/**
 * THE CLIENT HALF OF THE PROJECT DATA KEY, TESTED AGAINST THE FAILURES THAT
 * PRODUCE NO ERROR WHEN THEY HAPPEN.
 *
 * Every assertion below stands for a state that stores, lists and syncs
 * perfectly and fails once, opaquely, at read time:
 *
 *  - a wrap whose associated data names the wrong grantee, which a diff cannot
 *    see and which no server can check, because the server never holds the key;
 *  - a secret sealed under the associated data of another environment;
 *  - a nonce repeated across a row's two fields, which is nonce reuse under one
 *    key and total loss of authentication for that key.
 */

/** A deterministic stand-in for a real derivation. Not a real key. */
function fixedKey(fill = 7): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(fill));
}

const USER = { granteeType: "user", granteeId: "k17abcuserid00000000000000" } as const;
const ENVIRONMENT_ID = "j57abcenvironmentid0000000";

describe("createProjectDataKey", () => {
  it("is 32 bytes, which is the only width AES-256-GCM accepts", () => {
    expect(PDK_BYTES).toBe(32);
    expect(createProjectDataKey()).toHaveLength(PDK_BYTES);
  });

  it("is different every time", () => {
    // One repeated key across two environments would make the per-environment
    // key boundary a fiction, and nothing anywhere would report it.
    const keys = new Set(Array.from({ length: 8 }, () => toHex(createProjectDataKey())));
    expect(keys.size).toBe(8);
  });
});

describe("wrapProjectDataKey", () => {
  it("produces exactly the two fields createEnvironment takes", async () => {
    // Named to match `environments.createEnvironment`'s arguments so that a
    // call site cannot pair the blob with the wrong field. The server checks
    // the nonce width (AES-GCM derives its counter block through GHASH for any
    // other width and decrypts happily) and a length floor on the blob.
    const wrapped = await wrapProjectDataKey(fixedKey(), createProjectDataKey(), USER);
    expect(Object.keys(wrapped).sort()).toEqual(["pdkNonce", "wrappedPDK"]);
    expect(wrapped.pdkNonce).toMatch(/^[0-9a-f]{24}$/);
    // 32 bytes of key plus a 16 byte GCM tag, hex encoded.
    expect(wrapped.wrappedPDK).toMatch(/^[0-9a-f]{96}$/);
  });

  it("round trips through the shape getMyPdkGrant returns", async () => {
    const muk = fixedKey();
    const pdk = createProjectDataKey();
    const { wrappedPDK, pdkNonce } = await wrapProjectDataKey(muk, pdk, USER);

    // `nonce`, not `pdkNonce`: the query returns the grant row's own column
    // name and the mutation takes another. Getting that pairing wrong is the
    // one mistake this round trip is here to catch.
    const opened = await unwrapProjectDataKey(muk, { wrappedPDK, nonce: pdkNonce }, USER);
    expect(toHex(opened)).toBe(toHex(pdk));
  });

  it("does not open under another account's master unlock key", async () => {
    const pdk = createProjectDataKey();
    const wrapped = await wrapProjectDataKey(fixedKey(7), pdk, USER);
    await expect(
      unwrapProjectDataKey(
        fixedKey(8),
        { wrappedPDK: wrapped.wrappedPDK, nonce: wrapped.pdkNonce },
        USER,
      ),
    ).rejects.toThrow(PdkUnwrapError);
  });

  /**
   * `granteeType` and `granteeId` are COLUMNS on the grant row, and a column is
   * not authenticated. Naming the grantee inside the associated data is what
   * makes a row whose grantee fields were edited stop opening rather than claim
   * to belong to somebody it does not.
   */
  it("does not open under a different grantee id", async () => {
    const muk = fixedKey();
    const wrapped = await wrapProjectDataKey(muk, createProjectDataKey(), USER);
    await expect(
      unwrapProjectDataKey(muk, { wrappedPDK: wrapped.wrappedPDK, nonce: wrapped.pdkNonce }, {
        granteeType: "user",
        granteeId: "k17abcuserid00000000000001",
      }),
    ).rejects.toThrow(PdkUnwrapError);
  });

  it("does not open under a different grantee type", async () => {
    const muk = fixedKey();
    const wrapped = await wrapProjectDataKey(muk, createProjectDataKey(), USER);
    await expect(
      unwrapProjectDataKey(muk, { wrappedPDK: wrapped.wrappedPDK, nonce: wrapped.pdkNonce }, {
        granteeType: "token",
        granteeId: USER.granteeId,
      }),
    ).rejects.toThrow(PdkUnwrapError);
  });

  it("refuses to wrap anything that is not a 32 byte key", async () => {
    await expect(wrapProjectDataKey(fixedKey(), randomBytes(16), USER)).rejects.toThrow(
      "32 bytes",
    );
  });

  it("reports nothing about which input was wrong", async () => {
    // A message that distinguished a wrong key from a wrong grantee would be a
    // decryption oracle. AES-GCM reports a bare OperationError and there is no
    // honest way to be more specific.
    const wrapped = await wrapProjectDataKey(fixedKey(7), createProjectDataKey(), USER);
    const failure = await unwrapProjectDataKey(
      fixedKey(8),
      { wrappedPDK: wrapped.wrappedPDK, nonce: wrapped.pdkNonce },
      USER,
    ).catch((cause: unknown) => cause);

    expect(failure).toBeInstanceOf(PdkUnwrapError);
    const message = (failure as Error).message;
    for (const leak of [wrapped.wrappedPDK, wrapped.pdkNonce, USER.granteeId]) {
      expect(message).not.toContain(leak);
    }
  });
});

describe("sealSecret", () => {
  it("produces exactly the four fields createSecret takes", async () => {
    const sealed = await sealSecret(createProjectDataKey(), {
      environmentId: ENVIRONMENT_ID,
      name: "DATABASE_URL",
      value: "postgres://redacted",
    });
    expect(Object.keys(sealed).sort()).toEqual([
      "nameCiphertext",
      "nameNonce",
      "valueCiphertext",
      "valueNonce",
    ]);
    for (const nonce of [sealed.nameNonce, sealed.valueNonce]) {
      expect(nonce).toMatch(/^[0-9a-f]{24}$/);
    }
  });

  /**
   * Both fields of a row are sealed under the SAME project data key, so one
   * nonce used twice is nonce reuse under one key: it leaks the XOR of the two
   * plaintexts and the GHASH authentication key. `secrets.ts` refuses such a
   * row, and this is the client side of the same rule.
   */
  it("never uses one nonce for both fields", async () => {
    for (let i = 0; i < 25; i += 1) {
      const sealed = await sealSecret(createProjectDataKey(), {
        environmentId: ENVIRONMENT_ID,
        name: "A",
        value: "B",
      });
      expect(sealed.nameNonce).not.toBe(sealed.valueNonce);
    }
  });

  it("round trips through openSecret", async () => {
    const pdk = createProjectDataKey();
    const sealed = await sealSecret(pdk, {
      environmentId: ENVIRONMENT_ID,
      name: "DATABASE_URL",
      value: "postgres://user:pw@host/db",
    });

    const opened = await openSecret(pdk, { ...sealed, environmentId: ENVIRONMENT_ID });
    expect(opened.name).toBe("DATABASE_URL");
    expect(opened.value).toBe("postgres://user:pw@host/db");
  });

  it("survives a value that is not ASCII", async () => {
    // `TextDecoder` is constructed with `fatal: true`, so a plaintext that is
    // not valid UTF-8 throws rather than rendering replacement characters that
    // look like a corrupted secret.
    const pdk = createProjectDataKey();
    const value = "clé-à-café \u{1F511} 日本語";
    const sealed = await sealSecret(pdk, { environmentId: ENVIRONMENT_ID, name: "n", value });
    const opened = await openSecret(pdk, { ...sealed, environmentId: ENVIRONMENT_ID });
    expect(opened.value).toBe(value);
  });

  /**
   * The environment binding, from the client side. Without it a `dev` row
   * copied into `prod` by anyone with write access to the table would decrypt
   * perfectly, because the key is per environment but the ciphertext would be
   * bound to nothing.
   */
  it("does not open under another environment's associated data", async () => {
    const pdk = createProjectDataKey();
    const sealed = await sealSecret(pdk, {
      environmentId: ENVIRONMENT_ID,
      name: "n",
      value: "v",
    });
    await expect(
      openSecret(pdk, { ...sealed, environmentId: "j57abcenvironmentid0000001" }),
    ).rejects.toThrow(SecretOpenError);
  });

  it("does not open under another environment's key", async () => {
    const sealed = await sealSecret(createProjectDataKey(), {
      environmentId: ENVIRONMENT_ID,
      name: "n",
      value: "v",
    });
    await expect(
      openSecret(createProjectDataKey(), { ...sealed, environmentId: ENVIRONMENT_ID }),
    ).rejects.toThrow(SecretOpenError);
  });
});

/**
 * THE NAME AND THE VALUE OPEN SEPARATELY, AND THAT IS A PRIVACY DECISION
 * RATHER THAN A CONVENIENCE.
 *
 * The dashboard shows every name and reveals a value only when asked. If the
 * only way to get a name were `openSecret`, every value in the environment
 * would be decrypted into memory to render a list nobody asked to reveal, and
 * the plaintext would live for as long as that list did.
 */
describe("opening one field at a time", () => {
  it("opens the name without touching the value", async () => {
    const pdk = createProjectDataKey();
    const sealed = await sealSecret(pdk, {
      environmentId: ENVIRONMENT_ID,
      name: "DATABASE_URL",
      value: "postgres://redacted",
    });
    const row = { ...sealed, environmentId: ENVIRONMENT_ID };

    expect(await openSecretName(pdk, row)).toBe("DATABASE_URL");
    expect(await openSecretValue(pdk, row)).toBe("postgres://redacted");
  });

  it("refuses each field on its own when the key is wrong", async () => {
    const sealed = await sealSecret(createProjectDataKey(), {
      environmentId: ENVIRONMENT_ID,
      name: "n",
      value: "v",
    });
    const row = { ...sealed, environmentId: ENVIRONMENT_ID };
    const wrong = createProjectDataKey();

    await expect(openSecretName(wrong, row)).rejects.toThrow(SecretOpenError);
    await expect(openSecretValue(wrong, row)).rejects.toThrow(SecretOpenError);
  });

  it("says nothing about the ciphertext in its failure", async () => {
    const sealed = await sealSecret(createProjectDataKey(), {
      environmentId: ENVIRONMENT_ID,
      name: "n",
      value: "v",
    });
    const failure = await openSecretValue(createProjectDataKey(), {
      ...sealed,
      environmentId: ENVIRONMENT_ID,
    }).catch((cause: unknown) => cause);

    expect(failure).toBeInstanceOf(SecretOpenError);
    expect((failure as Error).message).not.toContain(sealed.valueCiphertext);
  });

  it("rejects ciphertext that is not hex rather than decoding it loosely", async () => {
    // `fromHex` is the only decoder used, and a row that is not hex is a row
    // this client did not write. It must fail rather than be coerced.
    const pdk = createProjectDataKey();
    await expect(
      openSecretName(pdk, {
        environmentId: ENVIRONMENT_ID,
        nameCiphertext: "not-hex",
        nameNonce: "000102030405060708090a0b",
        valueCiphertext: toHex(fromHex("aa".repeat(32))),
        valueNonce: "0b0a090807060504030201ff",
      }),
    ).rejects.toThrow(SecretOpenError);
  });
});
