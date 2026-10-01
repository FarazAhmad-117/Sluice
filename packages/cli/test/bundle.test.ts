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

const ENVIRONMENT_UID = "env_000102030405060708090a0b0c0d0e0f";
const OTHER_ENVIRONMENT_UID = "env_f0e0d0c0b0a090807060504030201000";

async function fixture(
  entries: Record<string, string> = { DATABASE_URL: "postgres://real", API_KEY: "sk-live-xyz" },
  // The environment the ROWS are sealed under. Defaults to the one the bundle
  // names and the grant is wrapped under; set it to another to build a bundle
  // whose key opens but whose rows were copied in from a different environment.
  rowEnvironmentUid: string = ENVIRONMENT_UID,
) {
  const minted = mintToken({ environment: "prod" });
  const identity = TokenIdentity.fromToken(minted.token);
  const pdk = randomBytes(32);

  const wrapped = await seal(
    identity.unwrapKey,
    pdk,
    pdkAssociatedData({
      environmentUid: ENVIRONMENT_UID,
      granteeType: "token",
      granteeId: tokenIdHash({ tokenId: minted.tokenId }),
    }),
  );

  const aad = secretAssociatedData({ environmentUid: rowEnvironmentUid });
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
    environmentUid: ENVIRONMENT_UID,
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
    // The grant is genuine and opens; only the rows were sealed elsewhere. This
    // is a `dev` row copied into `prod` by someone with database write access.
    const { identity, raw } = await fixture(undefined, OTHER_ENVIRONMENT_UID);
    const error = await decryptSecrets(identity, raw).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("row-open");
  });

  it("delivers nothing when the bundle names another environment than the one it was sealed under", async () => {
    // v2 binds the environment into the grant as well as the rows, so a bundle
    // relabelled to another environment fails at the first unwrap.
    const { identity, raw } = await fixture();
    const error = await decryptSecrets(identity, {
      ...raw,
      environmentUid: OTHER_ENVIRONMENT_UID,
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("pdk-unwrap");
  });

  it("refuses a bundle with no environmentUid as malformed, never as a raw exception", async () => {
    const { identity, raw } = await fixture();
    const { environmentUid: _dropped, ...withoutUid } = raw;
    const error = await decryptSecrets(identity, withoutUid as unknown as RawBundle).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("malformed");
  });

  it("names an older backend when the bundle carries only the v1 environmentId", async () => {
    // The v1 field, still arriving from a backend that has not moved, must be
    // read as "no permanent id" and not quietly bound into the associated data.
    // It is still `malformed`, but the message says what to do about it.
    const { identity, raw } = await fixture();
    const { environmentUid: _dropped, ...withoutUid } = raw;
    const convexId = "k17dn9q2x4m8p3v6b0zc5t7wgh";
    const error = await decryptSecrets(identity, {
      ...withoutUid,
      environmentId: convexId,
    } as unknown as RawBundle).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("malformed");
    expect((error as Error).message).toContain("older than this CLI");
    expect((error as Error).message).toContain("deploy the backend and the CLI together");
    expect((error as Error).message).not.toContain(convexId);
  });

  it("does not claim an older backend when environmentUid is merely missing", async () => {
    const { identity, raw } = await fixture();
    const { environmentUid: _dropped, ...withoutUid } = raw;
    const error = await decryptSecrets(identity, withoutUid as unknown as RawBundle).catch(
      (e: unknown) => e,
    );
    expect((error as BundleDecryptError).code).toBe("malformed");
    expect((error as Error).message).not.toContain("older than this CLI");
  });

  it("reports a malformed environment id as malformed even when the grant is also missing", async () => {
    // The bad id is the root cause; `no-grant` would send an operator to the
    // dashboard to issue a grant that could never have helped.
    const { identity, raw } = await fixture();
    const error = await decryptSecrets(identity, {
      ...raw,
      environmentUid: "k17dn9q2x4m8p3v6b0zc5t7wgh",
      wrappedPDK: undefined,
      pdkNonce: undefined,
      pdkVersion: undefined,
    }).catch((e: unknown) => e);
    expect((error as BundleDecryptError).code).toBe("malformed");
  });

  it("turns a malformed environmentUid into a named refusal, not the crypto layer's throw", async () => {
    // `secretAssociatedData` and `pdkAssociatedData` THROW a plain Error on a
    // malformed id. Every one of these must surface as a BundleDecryptError so
    // the shell logs it by code and holds the last known good set.
    const { identity, raw } = await fixture();
    const malformed = [
      "k17dn9q2x4m8p3v6b0zc5t7wgh",
      "env_000102030405060708090A0B0C0D0E0F",
      "env_0001",
      "",
      "usr_000102030405060708090a0b0c0d0e0f",
    ];
    for (const environmentUid of malformed) {
      const error = await decryptSecrets(identity, { ...raw, environmentUid }).catch(
        (e: unknown) => e,
      );
      expect(error).toBeInstanceOf(BundleDecryptError);
      expect((error as BundleDecryptError).code).toBe("malformed");
      // The rejected id is never echoed: it arrived from an untrusted row.
      if (environmentUid !== "") {
        expect((error as Error).message).not.toContain(environmentUid);
      }
    }
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

  it("reads the notice off a bundle whose environmentUid is missing or malformed", async () => {
    // The notice does not depend on the environment, and a bundle whose
    // environment id cannot be used must still be able to revoke the token.
    const { identity, raw } = await fixture();
    const notice = {
      tokenId: identity.tokenIdHex,
      epoch: 3,
      revokedAt: 1,
      reason: "x",
      signature: "0".repeat(128),
    };
    const { environmentUid: _dropped, ...withoutUid } = raw;
    for (const bundle of [
      { ...withoutUid, revocationNotice: notice },
      { ...raw, environmentUid: "k17dn9q2x4m8p3v6b0zc5t7wgh", revocationNotice: notice },
      { ...raw, environmentUid: "env_000102030405060708090A0B0C0D0E0F", revocationNotice: notice },
    ]) {
      expect(() => readRevocation(bundle as unknown as RawBundle)).not.toThrow();
      expect(readRevocation(bundle as unknown as RawBundle)?.notice.epoch).toBe(3);
    }
  });

  it("never throws, whatever the server sends down the subscription", () => {
    const hostile: unknown[] = [
      null,
      undefined,
      {},
      { revocationNotice: null },
      { revocationNotice: { signature: 42 } },
      { revocationNotice: { tokenId: 1, epoch: "x", revokedAt: null, reason: {}, signature: "" } },
      { environmentUid: 42, revocationNotice: {} },
      { environmentUid: "k17dn9q2x4m8p3v6b0zc5t7wgh", secrets: [] },
    ];
    for (const value of hostile) {
      expect(() => readRevocation(value as RawBundle)).not.toThrow();
    }
  });
});
