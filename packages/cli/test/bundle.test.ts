import { describe, expect, it } from "vitest";
import {
  mintToken,
  pdkAssociatedData,
  randomBytes,
  seal,
  secretAssociatedData,
  toHex,
  tokenIdHash,
  utf8,
} from "@sluice/crypto";
import { TokenIdentity } from "../src/config";
import {
  BundleDecryptError,
  decryptSecrets,
  readRevocation,
  type RawBundle,
  type RawSecretRow,
} from "../src/bundle";

const ENVIRONMENT_ID = "k17abcdefghijklmnopqrstuvwxyz01";

async function fixture(
  entries: Record<string, string> = { DATABASE_URL: "postgres://real", API_KEY: "sk-live-xyz" },
) {
  const minted = mintToken({ environment: "prod" });
  const identity = TokenIdentity.fromToken(minted.token);
  const pdk = randomBytes(32);

  const wrapped = await seal(
    identity.unwrapKey,
    pdk,
    pdkAssociatedData({
      granteeType: "token",
      granteeId: tokenIdHash({ tokenId: minted.tokenId }),
    }),
  );

  const aad = secretAssociatedData({ environmentId: ENVIRONMENT_ID });
  const secrets: RawSecretRow[] = [];
  let index = 0;
  for (const [name, value] of Object.entries(entries)) {
    const sealedName = await seal(pdk, utf8.encode(name), aad);
    const sealedValue = await seal(pdk, utf8.encode(value), aad);
    secrets.push({
      secretId: `sec${index}`,
      lineageId: `lin${index}`,
      version: 1,
      pdkVersion: 1,
      nameCiphertext: toHex(sealedName.ciphertext),
      nameNonce: toHex(sealedName.nonce),
      valueCiphertext: toHex(sealedValue.ciphertext),
      valueNonce: toHex(sealedValue.nonce),
    });
    index += 1;
  }

  const raw: RawBundle = {
    environmentId: ENVIRONMENT_ID,
    epoch: 4,
    pdkVersion: 1,
    wrappedPDK: toHex(wrapped.ciphertext),
    pdkNonce: toHex(wrapped.nonce),
    secrets,
  };
  return { minted, identity, pdk, raw };
}

describe("decryptSecrets", () => {
  it("opens the whole bundle with the token's own unwrap key", async () => {
    const { identity, raw } = await fixture();
    const bundle = await decryptSecrets(identity, raw);
    expect(bundle.epoch).toBe(4);
    expect(bundle.secrets).toEqual({
      DATABASE_URL: "postgres://real",
      API_KEY: "sk-live-xyz",
    });
  });

  it("refuses a bundle with no grant, and says so by name", async () => {
    const { identity, raw } = await fixture();
    const error = await decryptSecrets(identity, {
      ...raw,
      wrappedPDK: undefined,
      pdkNonce: undefined,
      pdkVersion: undefined,
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("no-grant");
  });

  it("refuses a grant wrapped to somebody else without saying which input was wrong", async () => {
    const { raw } = await fixture();
    const other = TokenIdentity.fromToken(mintToken({ environment: "prod" }).token);
    const error = await decryptSecrets(other, raw).catch((e: unknown) => e);
    expect((error as BundleDecryptError).code).toBe("pdk-unwrap");
  });

  it("refuses a secret sealed for another environment", async () => {
    const { identity, raw } = await fixture();
    const error = await decryptSecrets(identity, {
      ...raw,
      environmentId: "k17zzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    }).catch((e: unknown) => e);
    expect((error as BundleDecryptError).code).toBe("row-open");
  });

  it("refuses the whole bundle when one row is at another key version", async () => {
    const { identity, raw } = await fixture();
    const rows = raw.secrets.map((row, i) => (i === 0 ? { ...row, pdkVersion: 2 } : row));
    const error = await decryptSecrets(identity, { ...raw, secrets: rows }).catch(
      (e: unknown) => e,
    );
    expect((error as BundleDecryptError).code).toBe("pdk-version-mismatch");
  });

  it("refuses two secrets that decrypt to one name rather than picking a winner", async () => {
    const { identity, raw } = await fixture({ SAME: "one" });
    const duplicate = raw.secrets[0]!;
    const error = await decryptSecrets(identity, {
      ...raw,
      secrets: [duplicate, { ...duplicate, secretId: "sec9", lineageId: "lin9" }],
    }).catch((e: unknown) => e);
    expect((error as BundleDecryptError).code).toBe("duplicate-name");
  });

  it("refuses a name that is not a usable environment variable", async () => {
    const { identity, raw } = await fixture({ "not a name": "x" });
    const error = await decryptSecrets(identity, raw).catch((e: unknown) => e);
    expect((error as BundleDecryptError).code).toBe("bad-name");
  });

  it("accepts an empty environment, which is a real state and not a failure", async () => {
    const { identity, raw } = await fixture({});
    await expect(decryptSecrets(identity, raw)).resolves.toEqual({ epoch: 4, secrets: {} });
  });

  it("puts no decrypted value, no key material and no name into any error", async () => {
    const { identity, pdk, raw } = await fixture({ "not a name": "super-secret-value" });
    const error = (await decryptSecrets(identity, raw).catch((e: unknown) => e)) as Error;
    expect(error.message).not.toContain("super-secret-value");
    expect(error.message).not.toContain("not a name");
    expect(error.message).not.toContain(toHex(pdk));
    expect(error.message).not.toContain(toHex(identity.unwrapKey));
    expect(error.message).not.toMatch(/[\u2013\u2014]/);
  });

});

describe("readRevocation", () => {
  it("carries the notice through untouched, because the signature covers those bytes", async () => {
    const { identity, raw } = await fixture();
    const read = readRevocation({
      ...raw,
      revocationNotice: {
        tokenId: identity.tokenIdHex,
        epoch: 3,
        revokedAt: 1_700_000_000_000,
        reason: "leaked in a public repo",
        signature: "0".repeat(128),
      },
    });
    expect(read).toEqual({
      notice: {
        tokenId: identity.tokenIdHex,
        epoch: 3,
        revokedAt: 1_700_000_000_000,
        reason: "leaked in a public repo",
      },
      signature: new Uint8Array(64),
    });
  });

  it("READS THE NOTICE EVEN WHEN THE GRANT IS GONE, or a token could never be told", async () => {
    const { identity, raw } = await fixture();
    const read = readRevocation({
      ...raw,
      wrappedPDK: undefined,
      pdkNonce: undefined,
      pdkVersion: undefined,
      secrets: [],
      revocationNotice: {
        tokenId: identity.tokenIdHex,
        epoch: 3,
        revokedAt: 1,
        reason: "x",
        signature: "0".repeat(128),
      },
    });
    expect(read?.notice.epoch).toBe(3);
  });

  it("drops a notice whose signature is not hex rather than throwing on the shutdown path", async () => {
    const { identity, raw } = await fixture();
    expect(
      readRevocation({
        ...raw,
        revocationNotice: {
          tokenId: identity.tokenIdHex,
          epoch: 3,
          revokedAt: 1,
          reason: "x",
          signature: "not hex",
        },
      }),
    ).toBeUndefined();
  });

  it("never throws, whatever the server sends down the subscription", () => {
    const hostile: unknown[] = [
      null,
      undefined,
      {},
      { revocationNotice: null },
      { revocationNotice: { signature: 42 } },
      { revocationNotice: { tokenId: 1, epoch: "x", revokedAt: null, reason: {}, signature: "" } },
    ];
    for (const value of hostile) {
      expect(() => readRevocation(value as RawBundle)).not.toThrow();
    }
  });
});
