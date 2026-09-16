import { describe, expect, it } from "vitest";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes, toHex, utf8 } from "../src/bytes.js";
import {
  mintToken,
  parseToken,
  deriveTokenKeys,
  signHandshake,
  verifyHandshake,
} from "../src/token.js";

describe("token format", () => {
  it("round-trips through parseToken", () => {
    const minted = mintToken({ environment: "prod" });
    const parsed = parseToken(minted.token);
    expect(toHex(parsed.tokenId)).toBe(toHex(minted.tokenId));
    expect(toHex(parsed.tokenSecret)).toBe(toHex(minted.tokenSecret));
  });

  it("prefixes the token with the environment", () => {
    expect(mintToken({ environment: "prod" }).token.startsWith("slc_prod_")).toBe(true);
    expect(mintToken({ environment: "staging-eu" }).token.startsWith("slc_staging-eu_")).toBe(true);
  });

  it("uses a 16 byte id and a 32 byte secret", () => {
    const minted = mintToken({ environment: "prod" });
    expect(minted.tokenId).toHaveLength(16);
    expect(minted.tokenSecret).toHaveLength(32);
  });

  it("rejects malformed token strings", () => {
    expect(() => parseToken("slc_prod_nope")).toThrow();
    expect(() => parseToken("")).toThrow();
    expect(() => parseToken("prod_" + "a".repeat(32) + "." + "b".repeat(64))).toThrow();
    expect(() => parseToken("slc_prod_" + "a".repeat(30) + "." + "b".repeat(64))).toThrow();
    expect(() => parseToken("slc_prod_" + "a".repeat(32) + "." + "b".repeat(62))).toThrow();
    expect(() => parseToken("slc_prod_" + "A".repeat(32) + "." + "b".repeat(64))).toThrow();
  });
});

describe("the zero-knowledge boundary", () => {
  it("keeps the secret and unwrap key out of the upload payload", () => {
    const minted = mintToken({ environment: "prod" });
    const uploadJson = JSON.stringify(minted.upload);
    expect(uploadJson).not.toContain(toHex(minted.unwrapKey));
    expect(uploadJson).not.toContain(toHex(minted.tokenSecret));
    expect(uploadJson).not.toContain(toHex(minted.authSeed));
  });

  it("uploads only a token id and a public key", () => {
    const minted = mintToken({ environment: "prod" });
    expect(Object.keys(minted.upload).sort()).toEqual(["publicKey", "tokenId"]);
  });

  it("cannot derive the unwrap key from what the server holds", () => {
    const minted = mintToken({ environment: "prod" });
    // Everything the server has: the token id and the Ed25519 public key.
    // Feeding both through the same KDF must not reproduce the unwrap key.
    const serverHeld = [
      minted.upload.tokenId,
      minted.upload.publicKey,
      minted.upload.tokenId + minted.upload.publicKey,
    ];
    for (const material of serverHeld) {
      const attempt = hkdf(
        sha256,
        utf8.encode(material),
        minted.tokenId,
        utf8.encode("sluice/unwrap/v1"),
        32,
      );
      expect(toHex(attempt)).not.toBe(toHex(minted.unwrapKey));
    }
  });

  it("derives auth and unwrap keys that are independent", () => {
    const minted = mintToken({ environment: "prod" });
    expect(toHex(minted.authSeed)).not.toBe(toHex(minted.unwrapKey));
    // Domain separation must come from the info string, not from luck.
    const sameInfo = hkdf(
      sha256,
      minted.tokenSecret,
      minted.tokenId,
      utf8.encode("sluice/auth/v1"),
      32,
    );
    expect(toHex(sameInfo)).toBe(toHex(minted.authSeed));
  });

  it("produces distinct keys for distinct tokens", () => {
    const a = mintToken({ environment: "prod" });
    const b = mintToken({ environment: "prod" });
    expect(toHex(a.unwrapKey)).not.toBe(toHex(b.unwrapKey));
    expect(toHex(a.authSeed)).not.toBe(toHex(b.authSeed));
    expect(toHex(a.tokenId)).not.toBe(toHex(b.tokenId));
  });

  it("is deterministic: the same id and secret rederive the same keys", () => {
    const minted = mintToken({ environment: "prod" });
    const rederived = deriveTokenKeys(minted.tokenId, minted.tokenSecret);
    expect(toHex(rederived.unwrapKey)).toBe(toHex(minted.unwrapKey));
    expect(toHex(rederived.authSeed)).toBe(toHex(minted.authSeed));
  });

  it("binds keys to the token id, so the same secret under a different id differs", () => {
    const secret = randomBytes(32);
    const a = deriveTokenKeys(randomBytes(16), secret);
    const b = deriveTokenKeys(randomBytes(16), secret);
    expect(toHex(a.unwrapKey)).not.toBe(toHex(b.unwrapKey));
  });
});

describe("handshake", () => {
  it("verifies a signature made with the matching secret", () => {
    const minted = mintToken({ environment: "prod" });
    const timestamp = 1_757_000_000;
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, timestamp);
    expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, timestamp, signature)).toBe(true);
  });

  it("rejects a signature over a different timestamp", () => {
    const minted = mintToken({ environment: "prod" });
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, 1_757_000_000);
    expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, 1_757_000_001, signature)).toBe(false);
  });

  it("rejects a signature bound to a different token id", () => {
    const minted = mintToken({ environment: "prod" });
    const timestamp = 1_757_000_000;
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, timestamp);
    expect(verifyHandshake(minted.upload.publicKey, randomBytes(16), timestamp, signature)).toBe(false);
  });

  it("rejects a signature from a different token", () => {
    const a = mintToken({ environment: "prod" });
    const b = mintToken({ environment: "prod" });
    const timestamp = 1_757_000_000;
    const signature = signHandshake(b.tokenId, b.tokenSecret, timestamp);
    expect(verifyHandshake(a.upload.publicKey, a.tokenId, timestamp, signature)).toBe(false);
  });

  it("returns false rather than throwing on a garbage signature", () => {
    const minted = mintToken({ environment: "prod" });
    expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, 1_757_000_000, randomBytes(64))).toBe(false);
    expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, 1_757_000_000, randomBytes(8))).toBe(false);
  });

  it("returns false rather than throwing on a malformed public key", () => {
    const minted = mintToken({ environment: "prod" });
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, 1_757_000_000);
    expect(verifyHandshake("not-hex", minted.tokenId, 1_757_000_000, signature)).toBe(false);
    expect(verifyHandshake("", minted.tokenId, 1_757_000_000, signature)).toBe(false);
  });

  it("does not let a timestamp prefix collide with an adjacent one", () => {
    // Guards against a naive encoding where concat(id, "1") and concat(id, "12")
    // could be confused. 1 and 12 must produce different messages.
    const minted = mintToken({ environment: "prod" });
    const sigOne = signHandshake(minted.tokenId, minted.tokenSecret, 1);
    expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, 12, sigOne)).toBe(false);
  });
});
