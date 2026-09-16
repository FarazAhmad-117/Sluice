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

/**
 * Node's formatter (and therefore `console.log`) looks up exactly this symbol
 * on a value and uses its return in place of the default dump. `util.inspect`
 * itself cannot be imported here: `@types/node` is not a dependency of this
 * package and adding one purely for a test is not worth it. Calling the hook
 * directly exercises the same contract `console.log` would.
 */
const INSPECT_CUSTOM = Symbol.for("nodejs.util.inspect.custom");

function inspectLike(value: object): string {
  const hook = (value as unknown as Record<symbol, unknown>)[INSPECT_CUSTOM];
  // Deliberately fails instead of falling back to String(value). A fallback
  // would make the redaction test pass even when the hook is missing entirely,
  // which is the exact "proves nothing" trap called out above.
  if (typeof hook !== "function") throw new Error("no inspect hook: value is not redacted");
  return String((hook as () => unknown).call(value));
}

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

  it("rejects environments that parseToken could not read back", () => {
    for (const bad of ["my_env", "Prod", "", "-", "-prod", "prod-", "pro.d", "pr od"]) {
      expect(() => mintToken({ environment: bad })).toThrow();
    }
  });

  it("names the offending environment in the error", () => {
    expect(() => mintToken({ environment: "my_env" })).toThrow(/my_env/);
  });

  it("accepts well-formed environments", () => {
    for (const good of ["prod", "staging-eu", "a"]) {
      expect(() => mintToken({ environment: good })).not.toThrow();
    }
  });

  it("guarantees every environment it accepts survives a round trip", () => {
    for (const env of ["prod", "staging-eu", "a", "eu-west-1"]) {
      const minted = mintToken({ environment: env });
      expect(toHex(parseToken(minted.token).tokenId)).toBe(toHex(minted.tokenId));
      expect(toHex(parseToken(minted.token).tokenSecret)).toBe(toHex(minted.tokenSecret));
    }
  });
});

describe("input validation", () => {
  it("rejects a token id that is not 16 bytes", () => {
    const secret = randomBytes(32);
    for (const n of [0, 15, 17, 32]) {
      expect(() => deriveTokenKeys(randomBytes(n), secret)).toThrow(/16 bytes/);
      expect(() => signHandshake(randomBytes(n), secret, 1_757_000_000)).toThrow(/16 bytes/);
    }
  });

  it("returns false rather than throwing for a bad token id in verifyHandshake", () => {
    const minted = mintToken({ environment: "prod" });
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, 1_757_000_000);
    for (const n of [0, 15, 17, 32]) {
      expect(
        verifyHandshake(minted.upload.publicKey, randomBytes(n), 1_757_000_000, signature),
      ).toBe(false);
    }
  });

  it("rejects timestamps that are not non-negative safe integers", () => {
    const minted = mintToken({ environment: "prod" });
    const bad = [-0, -1, 1.5, NaN, Infinity, -Infinity, 1e21, Number.MAX_SAFE_INTEGER + 1];
    for (const timestamp of bad) {
      expect(() => signHandshake(minted.tokenId, minted.tokenSecret, timestamp)).toThrow(
        /timestamp/,
      );
    }
  });

  it("returns false rather than throwing for a bad timestamp in verifyHandshake", () => {
    const minted = mintToken({ environment: "prod" });
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, 1_757_000_000);
    const bad = [-0, -1, 1.5, NaN, Infinity, -Infinity, 1e21, Number.MAX_SAFE_INTEGER + 1];
    for (const timestamp of bad) {
      expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, timestamp, signature)).toBe(
        false,
      );
    }
  });

  it("still accepts zero and the largest safe integer as timestamps", () => {
    const minted = mintToken({ environment: "prod" });
    for (const timestamp of [0, Number.MAX_SAFE_INTEGER]) {
      const signature = signHandshake(minted.tokenId, minted.tokenSecret, timestamp);
      expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, timestamp, signature)).toBe(
        true,
      );
    }
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

  // NOTE ON WHAT THIS PROVES, WHICH IS LESS THAN IT LOOKS.
  //
  // This assertion passes for ANY implementation, including a catastrophically
  // broken one, because an accidental 256-bit collision is impossible whatever
  // the code does. It documents intent; it is not a proof and must not be read
  // as one during an audit.
  //
  // The real guarantee rests on the preimage resistance of HMAC-SHA256: the
  // server holds only the token id and a public key, and recovering the unwrap
  // key from those would require inverting the KDF.
  //
  // The load-bearing test in this file is "uploads only a token id and a public
  // key" -- that one actually fails when the boundary is breached.
  it("documents that server-held material is not the KDF input", () => {
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

describe("minted token redaction", () => {
  it("does not expose secrets through JSON.stringify", () => {
    const minted = mintToken({ environment: "prod" });
    const json = JSON.stringify(minted);
    expect(json).not.toContain(toHex(minted.unwrapKey));
    expect(json).not.toContain(toHex(minted.tokenSecret));
    expect(json).not.toContain(toHex(minted.authSeed));
    expect(json).not.toContain(minted.token);
  });

  it("does not expose secrets when nested inside a logged object", () => {
    const minted = mintToken({ environment: "prod" });
    const json = JSON.stringify({ event: "token.minted", minted });
    expect(json).not.toContain(toHex(minted.unwrapKey));
    expect(json).not.toContain(toHex(minted.tokenSecret));
    expect(json).not.toContain(toHex(minted.authSeed));
    expect(json).not.toContain(minted.token);
  });

  it("does not expose raw byte arrays, which JSON would otherwise dump", () => {
    // A bare Uint8Array serialises to {"0":12,"1":244,...}, which is a complete
    // and reversible dump. Guard against a regression that drops toJSON.
    const minted = mintToken({ environment: "prod" });
    const json = JSON.stringify(minted);
    expect(json).not.toContain(`"0":${minted.tokenSecret[0] as number}`);
    expect(json).not.toContain("unwrapKey");
    expect(json).not.toContain("tokenSecret");
    expect(json).not.toContain("authSeed");
  });

  it("does not expose secrets through the console.log inspect hook", () => {
    const minted = mintToken({ environment: "prod" });
    const shown = inspectLike(minted);
    expect(shown).not.toContain(toHex(minted.unwrapKey));
    expect(shown).not.toContain(toHex(minted.tokenSecret));
    expect(shown).not.toContain(toHex(minted.authSeed));
    expect(shown).not.toContain(minted.token);
  });

  it("still surfaces the upload payload through JSON", () => {
    const minted = mintToken({ environment: "prod" });
    const parsed = JSON.parse(JSON.stringify(minted)) as {
      upload: { tokenId: string; publicKey: string };
    };
    expect(parsed.upload.tokenId).toBe(minted.upload.tokenId);
    expect(parsed.upload.publicKey).toBe(minted.upload.publicKey);
  });

  it("keeps the secret fields readable to code that asks for them directly", () => {
    const minted = mintToken({ environment: "prod" });
    expect(minted.tokenSecret).toHaveLength(32);
    expect(minted.unwrapKey).toHaveLength(32);
    expect(minted.authSeed).toHaveLength(32);
    expect(minted.token.startsWith("slc_prod_")).toBe(true);
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
