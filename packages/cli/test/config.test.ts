import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { mintToken, toHex } from "@sluice/crypto";
import { loadConfig, TokenIdentity } from "../src/config";

const ORG_KEY = "a".repeat(64);

function env(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    SLUICE_TOKEN: mintToken({ environment: "prod" }).token,
    SLUICE_ORG_REVOCATION_PUBLIC_KEY: ORG_KEY,
    SLUICE_CONVEX_URL: "https://hearty-butterfly-862.convex.cloud",
    ...overrides,
  };
}

describe("loadConfig", () => {
  it("accepts a minimal environment and derives the site url", () => {
    const result = loadConfig(env());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.handshakeUrl).toBe(
      "https://hearty-butterfly-862.convex.site/handshake",
    );
    expect(result.config.convexUrl).toBe("https://hearty-butterfly-862.convex.cloud");
    expect(result.config.orgRevocationPublicKey).toBe(ORG_KEY);
  });

  it("lets the site url be overridden for a self-hosted deployment", () => {
    const result = loadConfig(env({ SLUICE_CONVEX_SITE_URL: "https://sluice.internal" }));
    expect(result.ok && result.config.handshakeUrl).toBe("https://sluice.internal/handshake");
  });

  it("refuses a missing token without printing anything about it", () => {
    const result = loadConfig(env({ SLUICE_TOKEN: undefined }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.message).toContain("SLUICE_TOKEN");
  });

  it("refuses a malformed token and never echoes it", () => {
    const secretish = "slc_prod_" + "f".repeat(32) + "." + "e".repeat(63);
    const result = loadConfig(env({ SLUICE_TOKEN: secretish }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.message).not.toContain("e".repeat(10));
    expect(!result.ok && result.message).not.toContain("f".repeat(10));
  });

  it("refuses an uppercase organisation key rather than folding it", () => {
    const result = loadConfig(env({ SLUICE_ORG_REVOCATION_PUBLIC_KEY: "A".repeat(64) }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.message).toContain("SLUICE_ORG_REVOCATION_PUBLIC_KEY");
  });

  it("refuses a missing organisation key, because it can never be fetched", () => {
    const result = loadConfig(env({ SLUICE_ORG_REVOCATION_PUBLIC_KEY: undefined }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.message).toContain("never fetched");
  });

  it("refuses a non-https deployment url unless it is loopback", () => {
    expect(loadConfig(env({ SLUICE_CONVEX_URL: "http://evil.example" })).ok).toBe(false);
    expect(loadConfig(env({ SLUICE_CONVEX_URL: "ftp://x" })).ok).toBe(false);
    const local = loadConfig(
      env({
        SLUICE_CONVEX_URL: "http://127.0.0.1:3210",
        SLUICE_CONVEX_SITE_URL: "http://127.0.0.1:3211",
      }),
    );
    expect(local.ok && local.config.handshakeUrl).toBe("http://127.0.0.1:3211/handshake");
  });

  it("refuses a deployment it cannot derive a site origin for, rather than guessing", () => {
    const result = loadConfig(env({ SLUICE_CONVEX_URL: "http://127.0.0.1:3210" }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.message).toContain("SLUICE_CONVEX_SITE_URL");
  });

  it("reads the optional numeric knobs and rejects nonsense", () => {
    const good = loadConfig(env({ SLUICE_DRAIN_MS: "1500", SLUICE_KILL_GRACE_MS: "2000" }));
    expect(good.ok && good.config.drainMs).toBe(1500);
    expect(good.ok && good.config.killGraceMs).toBe(2000);
    expect(loadConfig(env({ SLUICE_DRAIN_MS: "-1" })).ok).toBe(false);
    expect(loadConfig(env({ SLUICE_DRAIN_MS: "abc" })).ok).toBe(false);
    expect(loadConfig(env({ SLUICE_DRAIN_MS: "999999" })).ok).toBe(false);
  });

  it("never emits an em dash or an en dash in any refusal", () => {
    const refusals = [
      loadConfig(env({ SLUICE_TOKEN: undefined })),
      loadConfig(env({ SLUICE_ORG_REVOCATION_PUBLIC_KEY: undefined })),
      loadConfig(env({ SLUICE_CONVEX_URL: undefined })),
      loadConfig(env({ SLUICE_DRAIN_MS: "abc" })),
    ];
    for (const refusal of refusals) {
      expect(refusal.ok).toBe(false);
      expect(!refusal.ok && refusal.message).not.toMatch(/[\u2013\u2014]/);
    }
  });
});

describe("TokenIdentity", () => {
  const minted = mintToken({ environment: "prod" });

  it("derives the same keys the crypto package does", () => {
    const identity = TokenIdentity.fromToken(minted.token);
    expect(identity.tokenIdHex).toBe(toHex(minted.tokenId));
    expect(toHex(identity.unwrapKey)).toBe(toHex(minted.unwrapKey));
    expect(identity.environment).toBe("prod");
  });

  it("redacts itself in JSON and in console.log", () => {
    const identity = TokenIdentity.fromToken(minted.token);
    const json = JSON.stringify({ identity });
    expect(json).not.toContain(toHex(minted.tokenSecret));
    expect(json).not.toContain(toHex(minted.unwrapKey));
    expect(inspect(identity)).toBe("[TokenIdentity redacted]");
    expect(inspect({ identity })).not.toContain(toHex(minted.unwrapKey));
  });
});
