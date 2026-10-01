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

/** A well-formed permanent secret id, distinct per index. */
function secretUid(index: number): string {
  return "sec_" + index.toString(16).padStart(32, "0");
}

/**
 * Seals one row exactly as a client writes it: the name under field "name" and
 * the value under field "value", both bound to the environment, the secret's
 * permanent id and its version. Each binding can be overridden on its own so a
 * test can build the splices a database writer could attempt.
 */
async function sealRow(
  pdk: Uint8Array,
  options: {
    name: string;
    value: string;
    index: number;
    environmentUid?: string;
    secretUid?: string;
    version?: number;
  },
): Promise<RawSecretRow> {
  const environmentUid = options.environmentUid ?? ENVIRONMENT_UID;
  const uid = options.secretUid ?? secretUid(options.index);
  const version = options.version ?? 1;
  const sealedName = await seal(
    pdk,
    utf8.encode(options.name),
    secretAssociatedData({ environmentUid, secretUid: uid, version, field: "name" }),
  );
  const sealedValue = await seal(
    pdk,
    utf8.encode(options.value),
    secretAssociatedData({ environmentUid, secretUid: uid, version, field: "value" }),
  );
  return {
    secretUid: uid,
    lineageId: `lin${options.index}`,
    version,
    pdkVersion: 1,
    nameCiphertext: toHex(sealedName.ciphertext),
    nameNonce: toHex(sealedName.nonce),
    valueCiphertext: toHex(sealedValue.ciphertext),
    valueNonce: toHex(sealedValue.nonce),
  };
}

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
      pdkVersion: 1,
      granteeType: "token",
      granteeId: tokenIdHash({ tokenId: minted.tokenId }),
    }),
  );

  const secrets: RawSecretRow[] = [];
  let index = 0;
  for (const [name, value] of Object.entries(entries)) {
    secrets.push(await sealRow(pdk, { name, value, index, environmentUid: rowEnvironmentUid }));
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

  it("names an older backend when its rows carry only the v1 secretId", async () => {
    // A backend between the two changes: `environmentUid` already, but rows
    // still keyed by the Convex document id. Those rows cannot be bound, and
    // `row-open` would read like tampering; the message names the real cause.
    const { identity, raw } = await fixture();
    const convexId = "j57a8x9w2v3b4n5m6k7l8p9q0r";
    const rows = raw.secrets.map((row) => {
      const { secretUid: _dropped, ...rest } = row;
      return { ...rest, secretId: convexId };
    });
    const error = await decryptSecrets(identity, {
      ...raw,
      secrets: rows as unknown as RawSecretRow[],
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("malformed");
    expect((error as Error).message).toContain("older than this CLI");
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
    // Two genuine rows, each sealed under its own secret id, that carry one
    // name. Copying one row and relabelling its id no longer reaches this
    // check at all: its ciphertext is bound to the first row's id and fails
    // to open first.
    const { identity, pdk, raw } = await fixture({ SAME: "one" });
    const second = await sealRow(pdk, { name: "SAME", value: "two", index: 9 });
    const error = await decryptSecrets(identity, {
      ...raw,
      secrets: [raw.secrets[0]!, second],
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

  // THE SPLICES. Every attack below is one a database writer who holds no key
  // can perform: each moves genuine ciphertext, sealed by a genuine client
  // under the genuine project data key, into a slot it was not sealed for.
  // Before associated data named the secret, its version and the field, every
  // one of them decrypted cleanly and was believed.

  it("refuses a value spliced in from another secret", async () => {
    // STRIPE_KEY's value ciphertext placed in DATABASE_URL's row. Same key,
    // same environment; only the secret id it was sealed under differs.
    const { identity, raw } = await fixture({ DATABASE_URL: "postgres://real", STRIPE_KEY: "sk" });
    const [database, stripe] = raw.secrets as [RawSecretRow, RawSecretRow];
    const spliced: RawSecretRow = {
      ...database,
      valueCiphertext: stripe.valueCiphertext,
      valueNonce: stripe.valueNonce,
    };
    const error = await decryptSecrets(identity, { ...raw, secrets: [spliced, stripe] }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("row-open");
  });

  it("refuses a superseded value served under the current version number", async () => {
    // The rollback splice: version 1's value ciphertext in the version 2 row.
    // Serving the WHOLE version 1 row, with its own version number, still
    // opens; that needs a client-side ratchet and is not claimed here.
    const { identity, pdk, raw } = await fixture({});
    const uid = secretUid(0);
    const v1 = await sealRow(pdk, { name: "API_KEY", value: "old", index: 0, secretUid: uid });
    const v2 = await sealRow(pdk, {
      name: "API_KEY",
      value: "new",
      index: 0,
      secretUid: uid,
      version: 2,
    });
    const rolledBack: RawSecretRow = {
      ...v2,
      valueCiphertext: v1.valueCiphertext,
      valueNonce: v1.valueNonce,
    };
    await expect(decryptSecrets(identity, { ...raw, secrets: [v2] })).resolves.toEqual({
      epoch: 4,
      secrets: { API_KEY: "new" },
    });
    const error = await decryptSecrets(identity, { ...raw, secrets: [rolledBack] }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("row-open");
  });

  it("refuses a whole row relabelled with another secret's id, ciphertexts untouched", async () => {
    // The inverse splice: rather than moving a ciphertext into another row,
    // the attacker rewrites a row's `secretUid` column to claim it belongs to
    // a different secret.
    const { identity, raw } = await fixture({ DATABASE_URL: "postgres://real", STRIPE_KEY: "sk" });
    const [database, stripe] = raw.secrets as [RawSecretRow, RawSecretRow];
    const relabelled: RawSecretRow = { ...database, secretUid: stripe.secretUid };
    const error = await decryptSecrets(identity, { ...raw, secrets: [relabelled] }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("row-open");
  });

  it("refuses a row whose own key version is not a positive whole number, without echoing it", async () => {
    // It used to be interpolated into the `pdk-version-mismatch` message
    // unchecked, so any database writer could put arbitrary text in a log line.
    const { identity, raw } = await fixture();
    const huge = "Z".repeat(10_000);
    for (const pdkVersion of ["1", null, huge, 0, -1, 1.5, Number.NaN, "\u001b[2J"]) {
      const rows = raw.secrets.map((row, i) =>
        i === 0 ? ({ ...row, pdkVersion } as unknown as RawSecretRow) : row,
      );
      const error = await decryptSecrets(identity, { ...raw, secrets: rows }).catch(
        (e: unknown) => e,
      );
      expect(error).toBeInstanceOf(BundleDecryptError);
      expect((error as BundleDecryptError).code).toBe("row-open");
      expect((error as Error).message).not.toContain("ZZZZ");
      expect((error as Error).message).not.toContain("\u001b");
      expect((error as Error).message.length).toBeLessThan(400);
    }
  });

  it("calls a partial or mistyped grant malformed, never no-grant", async () => {
    const { identity, raw } = await fixture();
    for (const partial of [
      { wrappedPDK: undefined },
      { pdkNonce: undefined },
      { pdkVersion: undefined },
      { wrappedPDK: undefined, pdkNonce: undefined },
      { wrappedPDK: undefined, pdkVersion: undefined },
      { pdkNonce: undefined, pdkVersion: undefined },
      { wrappedPDK: 42 },
      { pdkNonce: null },
      { wrappedPDK: null, pdkNonce: null, pdkVersion: null },
    ]) {
      const error = await decryptSecrets(identity, {
        ...raw,
        ...(partial as Partial<RawBundle>),
      }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(BundleDecryptError);
      expect((error as BundleDecryptError).code).toBe("malformed");
    }
  });

  it("names a row by its secretUid when the backend sends no lineageId", async () => {
    const { identity, raw } = await fixture({ "not a name": "x" });
    const { lineageId: _dropped, ...withoutLineage } = raw.secrets[0]!;
    const error = await decryptSecrets(identity, { ...raw, secrets: [withoutLineage] }).catch(
      (e: unknown) => e,
    );
    expect((error as BundleDecryptError).code).toBe("bad-name");
    expect((error as Error).message).toContain(`The secret ${withoutLineage.secretUid}`);

    const unopenable = { ...withoutLineage, valueNonce: "00" };
    const rowError = await decryptSecrets(identity, { ...raw, secrets: [unopenable] }).catch(
      (e: unknown) => e,
    );
    expect((rowError as BundleDecryptError).code).toBe("row-open");
    expect((rowError as Error).message).toContain(`The secret ${withoutLineage.secretUid}`);
  });

  it("names a row by its lineageId when it has one", async () => {
    const { identity, raw } = await fixture({ "not a name": "x" });
    const error = await decryptSecrets(identity, raw).catch((e: unknown) => e);
    expect((error as Error).message).toContain("The secret lin0");
  });

  it("refuses a version number relabelled on an otherwise untouched row", async () => {
    const { identity, raw } = await fixture({ API_KEY: "x" });
    const relabelled = { ...raw.secrets[0]!, version: 2 };
    const error = await decryptSecrets(identity, { ...raw, secrets: [relabelled] }).catch(
      (e: unknown) => e,
    );
    expect((error as BundleDecryptError).code).toBe("row-open");
  });

  it("refuses a name ciphertext moved into the value slot", async () => {
    // Without the field binding this would set API_KEY to the string
    // "API_KEY": a wrong value that decrypts cleanly and reaches the child.
    const { identity, raw } = await fixture({ API_KEY: "sk-live-xyz" });
    const row = raw.secrets[0]!;
    const moved: RawSecretRow = {
      ...row,
      valueCiphertext: row.nameCiphertext,
      valueNonce: row.nameNonce,
    };
    const error = await decryptSecrets(identity, { ...raw, secrets: [moved] }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(BundleDecryptError);
    expect((error as BundleDecryptError).code).toBe("row-open");
  });

  it("refuses the whole bundle, by name, when one row's secret id or version is malformed", async () => {
    // `secretAssociatedData` THROWS a plain Error on these. Each must land as
    // the ordinary unreadable-row failure, never as the crypto layer's throw,
    // and the offending value is never echoed.
    const { identity, raw } = await fixture();
    const good = raw.secrets[1]!;
    const malformedRows: unknown[] = [
      { ...raw.secrets[0]!, secretUid: "sec_000102030405060708090A0B0C0D0E0F" },
      { ...raw.secrets[0]!, secretUid: "env_000102030405060708090a0b0c0d0e0f" },
      { ...raw.secrets[0]!, secretUid: "k17dn9q2x4m8p3v6b0zc5t7wgh" },
      { ...raw.secrets[0]!, secretUid: undefined },
      { ...raw.secrets[0]!, secretUid: 7 },
      { ...raw.secrets[0]!, version: 0 },
      { ...raw.secrets[0]!, version: -1 },
      { ...raw.secrets[0]!, version: 1.5 },
      { ...raw.secrets[0]!, version: "1" },
      { ...raw.secrets[0]!, version: Number.NaN },
      { ...raw.secrets[0]!, version: 2 ** 53 },
      { ...raw.secrets[0]!, version: undefined },
      null,
      "row",
    ];
    for (const row of malformedRows) {
      const error = await decryptSecrets(identity, {
        ...raw,
        secrets: [good, row as RawSecretRow],
      }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(BundleDecryptError);
      expect((error as BundleDecryptError).code).toBe("row-open");
      expect((error as Error).message).not.toContain("k17dn9q2x4m8p3v6b0zc5t7wgh");
      expect((error as Error).message).not.toContain("0A0B0C0D");
    }
  });

  it("refuses a malformed key grant version as malformed, with one fixed message", async () => {
    const { identity, raw } = await fixture();
    const messages = new Set<string>();
    for (const pdkVersion of [0, -1, 1.5, Number.NaN, 2 ** 53, "1", null]) {
      const error = await decryptSecrets(identity, {
        ...raw,
        pdkVersion: pdkVersion as number,
      }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(BundleDecryptError);
      expect((error as BundleDecryptError).code).toBe("malformed");
      messages.add((error as Error).message);
    }
    expect(messages.size).toBe(1);
  });

  it("refuses a genuine grant relabelled to another key version", async () => {
    // Rotation rollback: the old wrap served as version 2. The rows are
    // relabelled too so the per-row version check cannot be what catches it.
    const { identity, raw } = await fixture();
    const error = await decryptSecrets(identity, {
      ...raw,
      pdkVersion: 2,
      secrets: raw.secrets.map((row) => ({ ...row, pdkVersion: 2 })),
    }).catch((e: unknown) => e);
    expect((error as BundleDecryptError).code).toBe("pdk-unwrap");
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

  it("reads the notice off a bundle whose rows or grant version are malformed", async () => {
    const { identity, raw } = await fixture();
    const notice = {
      tokenId: identity.tokenIdHex,
      epoch: 3,
      revokedAt: 1,
      reason: "x",
      signature: "0".repeat(128),
    };
    for (const bundle of [
      { ...raw, secrets: [{ ...raw.secrets[0]!, secretUid: "nope" }], revocationNotice: notice },
      { ...raw, secrets: [{ ...raw.secrets[0]!, version: -1 }], revocationNotice: notice },
      { ...raw, secrets: [null], revocationNotice: notice },
      { ...raw, pdkVersion: 0, revocationNotice: notice },
    ]) {
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
