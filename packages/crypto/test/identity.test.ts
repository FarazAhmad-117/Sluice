import { describe, expect, it } from "vitest";
import { toHex } from "../src/bytes";
import { MasterUnlockKey } from "../src/muk";
import {
  decodeWrappedKey,
  deriveAuthVerifier,
  encodeWrappedKey,
  userKeyAssociatedData,
  WrappedKeyFormatError,
} from "../src/identity";
import type { KeyPurpose } from "../src/identity";

describe("userKeyAssociatedData", () => {
  it("matches the independent vectors", () => {
    expect(toHex(userKeyAssociatedData("x25519"))).toBe(
      "736c756963652f757365722d6b65792f76317c783235353139",
    );
    expect(toHex(userKeyAssociatedData("ed25519"))).toBe(
      "736c756963652f757365722d6b65792f76317c65643235353139",
    );
  });
  it("refuses a purpose outside the two, even behind a cast", () => {
    expect(() => userKeyAssociatedData("X25519" as KeyPurpose)).toThrow(
      "purpose must be x25519 or ed25519",
    );
  });
});

describe("deriveAuthVerifier", () => {
  it("matches the independent HMAC vector", () => {
    const muk = new MasterUnlockKey(Uint8Array.from({ length: 32 }, (_, i) => i));
    expect(deriveAuthVerifier(muk)).toBe(
      "0abfe45dead6265934bc56753b7cd9f2f782e9f801e7279e4a5451453bcbff61",
    );
  });
});

describe("wrapped key codec", () => {
  // 48 bytes: a 32-byte key plus the 16-byte GCM tag, the only k1 width.
  const box = { nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array(48).fill(2) };
  const nonceHex = "01".repeat(12);
  const ctHex = "02".repeat(48);

  it("round-trips", () => {
    expect(decodeWrappedKey(encodeWrappedKey(box))).toEqual(box);
  });
  it("uses the ratified format", () => {
    expect(encodeWrappedKey(box)).toBe(`sluice.k1.${nonceHex}.${ctHex}`);
  });
  it.each([
    ["empty", ""],
    ["a later version", `sluice.k2.${nonceHex}.${ctHex}`],
    ["95 hex ciphertext", `sluice.k1.${nonceHex}.${ctHex.slice(0, 95)}`],
    ["97 hex (odd) ciphertext", `sluice.k1.${nonceHex}.${ctHex}0`],
    ["98 hex ciphertext", `sluice.k1.${nonceHex}.${ctHex}00`],
    ["uppercase hex", `sluice.k1.${nonceHex}.${"AB".repeat(48)}`],
    ["a 23 hex nonce", `sluice.k1.${nonceHex.slice(0, 23)}.${ctHex}`],
  ])("rejects %s", (_label, blob) => {
    expect(() => decodeWrappedKey(blob)).toThrow(WrappedKeyFormatError);
  });

  it("refuses to encode a nonce that is not 12 bytes", () => {
    expect(() => encodeWrappedKey({ ...box, nonce: new Uint8Array(11) })).toThrow(
      WrappedKeyFormatError,
    );
  });
  it("refuses to encode a ciphertext that is not 48 bytes, without echoing it", () => {
    const ciphertext = new Uint8Array(47).fill(0xab);
    expect(() => encodeWrappedKey({ ...box, ciphertext })).toThrow(WrappedKeyFormatError);
    expect(() => encodeWrappedKey({ ...box, ciphertext })).not.toThrow(/abab/);
  });
});
