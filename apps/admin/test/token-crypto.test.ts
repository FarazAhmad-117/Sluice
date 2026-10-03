import { describe, expect, it } from "vitest";
import {
  deriveTokenKeys,
  fromHex,
  mintToken,
  newId,
  parseToken,
  pdkAssociatedData,
  randomBytes,
  toHex,
  tokenIdHash,
  unseal,
  verifyRevocation,
} from "@sluice/crypto";
import {
  TokenMetaOpenError,
  TOKEN_NAME_MAX_BYTES,
  issueToken,
  openTokenMeta,
  signTokenRevocation,
  tokenNameProblem,
} from "../src/lib/tokens/token-crypto";
import type { EnvironmentKey } from "../src/lib/secrets/pdk";

function environmentKey(overrides: Partial<EnvironmentKey> = {}): EnvironmentKey {
  return { pdk: randomBytes(32), environmentUid: newId("env"), pdkVersion: 1, ...overrides };
}

/** The token's unwrap key, rebuilt from the string alone, as a workload does. */
function unwrapKeyOf(token: string): Uint8Array {
  const { tokenId, tokenSecret } = parseToken(token);
  return deriveTokenKeys(tokenId, tokenSecret).unwrapKey;
}

describe("issueToken", () => {
  it("wraps the environment key so the token alone can open it, under the bundle's associated data", async () => {
    const key = environmentKey();
    const issued = await issueToken({ key, environmentName: "production", name: "api-prod-1", target: "server" });

    // What a workload holds is the token string, nothing else.
    const parsed = parseToken(issued.token.reveal());
    expect(parsed.environment).toBe("production");
    expect(issued.args.tokenId).toBe(toHex(parsed.tokenId));

    const opened = await unseal(
      unwrapKeyOf(issued.token.reveal()),
      { ciphertext: fromHex(issued.args.wrappedPDK), nonce: fromHex(issued.args.pdkNonce) },
      pdkAssociatedData({
        environmentUid: key.environmentUid,
        pdkVersion: 1,
        granteeType: "token",
        granteeId: tokenIdHash({ tokenId: parsed.tokenId }),
      }),
    );
    expect(toHex(opened)).toBe(toHex(key.pdk));
    expect(issued.args.pdkVersion).toBe(1);
    expect(issued.args.target).toBe("server");
  });

  it("seals a name and id that open with the environment key and nothing else", async () => {
    const key = environmentKey();
    const issued = await issueToken({ key, environmentName: "staging", name: "  ci main  ", target: "ci" });
    const sealed = { ...issued.args, metaPdkVersion: 1, tokenIdHash: issued.tokenIdHash };

    // Trimmed before sealing: what the person meant, not their whitespace.
    expect(await openTokenMeta(key, sealed)).toEqual({ name: "ci main", tokenIdHex: issued.args.tokenId });

    await expect(openTokenMeta(environmentKey({ environmentUid: key.environmentUid }), sealed)).rejects.toThrow(
      TokenMetaOpenError,
    );
  });

  it("refuses to open a sealed id moved onto another token's row", async () => {
    const key = environmentKey();
    const a = await issueToken({ key, environmentName: "production", name: "a", target: "server" });
    const b = await issueToken({ key, environmentName: "production", name: "b", target: "server" });
    // A's sealed fields, served as if they were B's.
    const moved = { ...a.args, metaPdkVersion: 1, tokenIdHash: b.tokenIdHash };
    await expect(openTokenMeta(key, moved)).rejects.toThrow(TokenMetaOpenError);
  });

  it("never shows the token's secret half in JSON or string form", async () => {
    const issued = await issueToken({ key: environmentKey(), environmentName: "production", name: "x", target: "docker" });
    const secretHalf = issued.token.reveal().split(".")[1] as string;
    expect(JSON.stringify(issued)).not.toContain(secretHalf);
    expect(String(issued.token)).not.toContain(secretHalf);
  });

  it("refuses a bad name before minting anything", async () => {
    const key = environmentKey();
    await expect(issueToken({ key, environmentName: "production", name: "   ", target: "server" })).rejects.toThrow(
      "Give it a name.",
    );
    await expect(
      issueToken({ key, environmentName: "production", name: "x".repeat(TOKEN_NAME_MAX_BYTES + 1), target: "server" }),
    ).rejects.toThrow(`Names can be up to ${TOKEN_NAME_MAX_BYTES} characters.`);
  });
});

describe("tokenNameProblem", () => {
  it("counts UTF-8 bytes, after trimming", () => {
    expect(tokenNameProblem("api-prod-1")).toBeNull();
    expect(tokenNameProblem("  ")).toBe("Give it a name.");
    expect(tokenNameProblem("é".repeat(32))).toBeNull();
    expect(tokenNameProblem("é".repeat(33))).toBe(`Names can be up to ${TOKEN_NAME_MAX_BYTES} characters.`);
  });
});

describe("signTokenRevocation", () => {
  it("signs a notice the org's public key verifies, at epoch 1", () => {
    const org = mintToken({ environment: "revocation" });
    const tokenIdHex = toHex(randomBytes(16));
    const args = signTokenRevocation({
      revocationKey: org.authSeed,
      tokenIdHex,
      reason: "laptop stolen",
      now: 1_700_000_000_000,
    });
    expect(args).toMatchObject({ tokenId: tokenIdHex, epoch: 1, revokedAt: 1_700_000_000_000, reason: "laptop stolen" });
    const { signature, ...notice } = args;
    expect(verifyRevocation(org.upload.publicKey, notice, fromHex(signature))).toBe(true);
  });

  it("uses a plain default reason when none is given", () => {
    const org = mintToken({ environment: "revocation" });
    const args = signTokenRevocation({ revocationKey: org.authSeed, tokenIdHex: toHex(randomBytes(16)), reason: "  ", now: 1 });
    expect(args.reason).toBe("Revoked from the dashboard.");
  });
});
