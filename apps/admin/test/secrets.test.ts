import { describe, expect, it } from "vitest";
import { ConvexError } from "convex/values";
import { MasterUnlockKey, fromHex, newId, randomBytes, toHex } from "@sluice/crypto";
import {
  PDK_BYTES,
  PdkUnwrapError,
  createProjectDataKey,
  unwrapProjectDataKey,
  wrapProjectDataKey,
} from "../src/lib/secrets/pdk";
import type { EnvironmentKey } from "../src/lib/secrets/pdk";
import { newSecretSlot, nextSecretSlot, sealSecret } from "../src/lib/secrets/seal";
import {
  SecretOpenError,
  openSecret,
  openSecretName,
  openSecretValue,
} from "../src/lib/secrets/decrypt";
import {
  STALE_ENVIRONMENT_KEY,
  STALE_SECRET_VERSION,
  describeWriteFailure,
} from "../src/lib/secrets/write-errors";

/**
 * THE CLIENT HALF OF THE PROJECT DATA KEY, TESTED AGAINST THE FAILURES THAT
 * PRODUCE NO ERROR WHEN THEY HAPPEN.
 *
 * Every assertion below stands for a state that stores, lists and syncs
 * perfectly and fails once, opaquely, at read time:
 *
 *  - a grant whose associated data names the wrong environment, key version or
 *    grantee, which a diff cannot see and which no server can check, because
 *    the server never holds the key;
 *  - a secret ciphertext opened in a slot it was not sealed for: another
 *    environment, another secret, another version, or the other field;
 *  - a nonce repeated across a row's two fields, which is nonce reuse under one
 *    key and total loss of authentication for that key.
 */

/** A deterministic stand-in for a real derivation. Not a real key. */
function fixedKey(fill = 7): MasterUnlockKey {
  return new MasterUnlockKey(new Uint8Array(32).fill(fill));
}

const ENVIRONMENT_UID = newId("env");
const OTHER_ENVIRONMENT_UID = newId("env");
const USER_UID = newId("usr");

/** The creator's grant at the first key version, in the shape `pdkAssociatedData` takes. */
const USER = {
  environmentUid: ENVIRONMENT_UID,
  pdkVersion: 1,
  granteeType: "user",
  granteeId: USER_UID,
} as const;

/** A key in hand for `ENVIRONMENT_UID`, as `useProjectDataKey` hands one out. */
function environmentKey(pdk = createProjectDataKey()): EnvironmentKey {
  return { pdk, environmentUid: ENVIRONMENT_UID, pdkVersion: 1 };
}

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
   * Every field of the grant's slot is a column or a server answer, and none
   * is authenticated on its own. Each one below is changed alone, so a binding
   * that silently dropped any single field fails exactly one of these.
   */
  it.each([
    // A grant copied from one environment onto another must not hand the
    // second environment's reader the first one's key.
    ["environment", { environmentUid: OTHER_ENVIRONMENT_UID }],
    // A grant rolled back to an older key generation, or an old wrap served
    // under a newer version number, must not open as the current key.
    ["key version", { pdkVersion: 2 }],
    // A row whose grantee was edited must stop opening rather than claim to
    // belong to somebody it does not.
    ["grantee id", { granteeId: newId("usr") }],
  ])("does not open under a different %s", async (_label, change) => {
    const muk = fixedKey();
    const wrapped = await wrapProjectDataKey(muk, createProjectDataKey(), USER);
    await expect(
      unwrapProjectDataKey(
        muk,
        { wrappedPDK: wrapped.wrappedPDK, nonce: wrapped.pdkNonce },
        { ...USER, ...change },
      ),
    ).rejects.toThrow(PdkUnwrapError);
  });

  it("does not open as a token grant", async () => {
    // A user uid and a token hash are both opaque strings in one index, and
    // the type is what separates them. The token side needs a hash-shaped id,
    // which is the shape `pdkAssociatedData` checks for that type.
    const muk = fixedKey();
    const wrapped = await wrapProjectDataKey(muk, createProjectDataKey(), USER);
    await expect(
      unwrapProjectDataKey(muk, { wrappedPDK: wrapped.wrappedPDK, nonce: wrapped.pdkNonce }, {
        ...USER,
        granteeType: "token",
        granteeId: "ab".repeat(32),
      }),
    ).rejects.toThrow(PdkUnwrapError);
  });

  /**
   * The grantee is the account's PERMANENT uid. A Convex document id, which is
   * what `session.userId` holds, is refused before anything is sealed, so a
   * call site that passes the wrong one fails loudly at the call instead of
   * writing a grant keyed by nothing the server stores.
   */
  it("refuses a Convex document id as the grantee or the environment", async () => {
    await expect(
      wrapProjectDataKey(fixedKey(), createProjectDataKey(), {
        ...USER,
        granteeId: "k17abcuserid00000000000000",
      }),
    ).rejects.toThrow(/granteeId must be a well-formed usr id/);
    await expect(
      wrapProjectDataKey(fixedKey(), createProjectDataKey(), {
        ...USER,
        environmentUid: "j57abcenvironmentid0000000",
      }),
    ).rejects.toThrow(/environmentUid must be a well-formed env id/);
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
    for (const leak of [wrapped.wrappedPDK, wrapped.pdkNonce, USER.granteeId, ENVIRONMENT_UID]) {
      expect(message).not.toContain(leak);
    }
  });
});

describe("secret slots", () => {
  it("mints a fresh permanent id at version 1 for a new secret", () => {
    const first = newSecretSlot();
    const second = newSecretSlot();
    expect(first.version).toBe(1);
    expect(first.secretUid).toMatch(/^sec_[0-9a-f]{32}$/);
    // One id shared by two new secrets would merge their histories.
    expect(second.secretUid).not.toBe(first.secretUid);
  });

  it("keeps the secret's id and takes the next version for an update", () => {
    const current = { secretUid: newId("sec"), version: 4 };
    expect(nextSecretSlot(current)).toEqual({ secretUid: current.secretUid, version: 5 });
  });
});

describe("sealSecret", () => {
  it("produces exactly the four fields createSecret takes beside the slot", async () => {
    const sealed = await sealSecret(environmentKey(), {
      ...newSecretSlot(),
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
      const sealed = await sealSecret(environmentKey(), {
        ...newSecretSlot(),
        name: "A",
        value: "B",
      });
      expect(sealed.nameNonce).not.toBe(sealed.valueNonce);
    }
  });

  it("round trips the name and the value through openSecret", async () => {
    const key = environmentKey();
    const slot = newSecretSlot();
    const sealed = await sealSecret(key, {
      ...slot,
      name: "DATABASE_URL",
      value: "postgres://user:pw@host/db",
    });

    const opened = await openSecret(key, { ...slot, ...sealed });
    expect(opened.name).toBe("DATABASE_URL");
    expect(opened.value).toBe("postgres://user:pw@host/db");
  });

  it("round trips an update sealed for the next version", async () => {
    const key = environmentKey();
    const first = newSecretSlot();
    const next = nextSecretSlot(first);
    const sealed = await sealSecret(key, { ...next, name: "N", value: "second" });
    expect(await openSecretValue(key, { ...next, ...sealed })).toBe("second");
  });

  it("survives a value that is not ASCII", async () => {
    // `TextDecoder` is constructed with `fatal: true`, so a plaintext that is
    // not valid UTF-8 throws rather than rendering replacement characters that
    // look like a corrupted secret.
    const key = environmentKey();
    const slot = newSecretSlot();
    const value = "clé-à-café \u{1F511} 日本語";
    const sealed = await sealSecret(key, { ...slot, name: "n", value });
    const opened = await openSecret(key, { ...slot, ...sealed });
    expect(opened.value).toBe(value);
  });

  it("refuses a slot it cannot bind instead of sealing it", async () => {
    // A Convex document id where the permanent uid belongs, or a version that
    // is not a positive whole number, would seal bytes no reader rebuilds.
    await expect(
      sealSecret(environmentKey(), { secretUid: "jd7abc123", version: 1, name: "n", value: "v" }),
    ).rejects.toThrow(/secretUid must be a well-formed sec id/);
    await expect(
      sealSecret(environmentKey(), { ...newSecretSlot(), version: 0, name: "n", value: "v" }),
    ).rejects.toThrow(/^version must be/);
  });
});

/**
 * EVERY CIPHERTEXT OPENS ONLY IN THE SLOT IT WAS SEALED FOR.
 *
 * Each case below is a row somebody with write access to the table could
 * build out of real ciphertext, and which would open and show the wrong thing
 * if the associated data did not name that part of the slot.
 */
describe("the slot binding", () => {
  async function sealedRow() {
    const key = environmentKey();
    const slot = newSecretSlot();
    const sealed = await sealSecret(key, { ...slot, name: "API_KEY", value: "sk_live_123" });
    return { key, row: { ...slot, ...sealed } };
  }

  /**
   * The value swapped into the name slot. The list shows every name in the
   * clear, unasked, so a value that opened as a name would be revealed on
   * screen without anybody pressing Reveal.
   */
  it("does not open a value as a name", async () => {
    const { key, row } = await sealedRow();
    await expect(
      openSecretName(key, {
        ...row,
        nameCiphertext: row.valueCiphertext,
        nameNonce: row.valueNonce,
      }),
    ).rejects.toThrow(SecretOpenError);
  });

  it("does not open a name as a value", async () => {
    const { key, row } = await sealedRow();
    await expect(
      openSecretValue(key, {
        ...row,
        valueCiphertext: row.nameCiphertext,
        valueNonce: row.nameNonce,
      }),
    ).rejects.toThrow(SecretOpenError);
  });

  /** Two secrets' values swapped, or one secret's value copied into another's row. */
  it("does not open under another secret's uid", async () => {
    const { key, row } = await sealedRow();
    await expect(openSecretValue(key, { ...row, secretUid: newId("sec") })).rejects.toThrow(
      SecretOpenError,
    );
  });

  /** An old value served as the current version, or a stale write replayed. */
  it("does not open version N's ciphertext as version N+1", async () => {
    const { key, row } = await sealedRow();
    await expect(
      openSecretValue(key, { ...row, version: row.version + 1 }),
    ).rejects.toThrow(SecretOpenError);
  });

  /**
   * A row copied from one environment into another under the SAME key would
   * otherwise decrypt perfectly there. The uid comes from the key, never from
   * the row, which is why the test changes the key's uid and not a column.
   */
  it("does not open a row under another environment's uid", async () => {
    const { key, row } = await sealedRow();
    await expect(
      openSecret({ ...key, environmentUid: OTHER_ENVIRONMENT_UID }, row),
    ).rejects.toThrow(SecretOpenError);
  });

  it("does not open under another environment's key", async () => {
    const { row } = await sealedRow();
    await expect(openSecret(environmentKey(), row)).rejects.toThrow(SecretOpenError);
  });

  /**
   * A malformed uid or version on a row is a row this client did not write.
   * It must fail like every other such row, as `SecretOpenError` with no
   * detail, not as an argument error that describes the offending column.
   */
  it("fails a row with a malformed uid or version as not authentic", async () => {
    const { key, row } = await sealedRow();
    for (const bad of [{ secretUid: "not-an-id" }, { version: 0 }, { version: 1.5 }]) {
      const failure = await openSecretName(key, { ...row, ...bad }).catch(
        (cause: unknown) => cause,
      );
      expect(failure).toBeInstanceOf(SecretOpenError);
    }
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
    const key = environmentKey();
    const slot = newSecretSlot();
    const sealed = await sealSecret(key, {
      ...slot,
      name: "DATABASE_URL",
      value: "postgres://redacted",
    });
    const row = { ...slot, ...sealed };

    expect(await openSecretName(key, row)).toBe("DATABASE_URL");
    expect(await openSecretValue(key, row)).toBe("postgres://redacted");
  });

  it("refuses each field on its own when the key is wrong", async () => {
    const slot = newSecretSlot();
    const sealed = await sealSecret(environmentKey(), { ...slot, name: "n", value: "v" });
    const row = { ...slot, ...sealed };
    const wrong = environmentKey();

    await expect(openSecretName(wrong, row)).rejects.toThrow(SecretOpenError);
    await expect(openSecretValue(wrong, row)).rejects.toThrow(SecretOpenError);
  });

  it("says nothing about the ciphertext in its failure", async () => {
    const slot = newSecretSlot();
    const sealed = await sealSecret(environmentKey(), { ...slot, name: "n", value: "v" });
    const failure = await openSecretValue(environmentKey(), { ...slot, ...sealed }).catch(
      (cause: unknown) => cause,
    );

    expect(failure).toBeInstanceOf(SecretOpenError);
    expect((failure as Error).message).not.toContain(sealed.valueCiphertext);
    expect((failure as Error).message).not.toContain(slot.secretUid);
  });

  it("rejects ciphertext that is not hex rather than decoding it loosely", async () => {
    // `fromHex` is the only decoder used, and a row that is not hex is a row
    // this client did not write. It must fail rather than be coerced.
    await expect(
      openSecretName(environmentKey(), {
        ...newSecretSlot(),
        nameCiphertext: "not-hex",
        nameNonce: "000102030405060708090a0b",
        valueCiphertext: toHex(fromHex("aa".repeat(32))),
        valueNonce: "0b0a090807060504030201ff",
      }),
    ).rejects.toThrow(SecretOpenError);
  });
});

/**
 * A STALE WRITE IS SHOWN AS THE SERVER WROTE IT, WITH A WAY TO RELOAD.
 *
 * Retrying a stale slot is refused the same way for ever, so a generic "try
 * again" would leave somebody pressing Save on a form that can never succeed.
 * `convex/secrets.test.ts` provokes the real refusal through the real mutation
 * and checks it against this mapping, which is what pins the sentence.
 */
describe("describeWriteFailure", () => {
  it.each([STALE_SECRET_VERSION, STALE_ENVIRONMENT_KEY])(
    "passes %j through unchanged and offers a reload",
    (sentence) => {
      expect(describeWriteFailure(new ConvexError(sentence))).toEqual({
        message: sentence,
        reload: true,
      });
    },
  );

  it("passes any other server sentence through without a reload", () => {
    expect(describeWriteFailure(new ConvexError("That slug is taken."))).toEqual({
      message: "That slug is taken.",
      reload: false,
    });
  });

  it("replaces anything that is not a server sentence with a generic one", () => {
    // A thrown value on these paths can carry ciphertext, so it never reaches
    // the screen.
    const failure = describeWriteFailure(new Error(`boom ${"ab".repeat(40)}`));
    expect(failure).toEqual({ message: "That did not work. Try again.", reload: false });
  });
});
