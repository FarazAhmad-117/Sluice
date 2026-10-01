import { describe, expect, it } from "vitest";
import { toHex } from "../src/bytes";
import { MasterUnlockKey } from "../src/muk";
import {
  decodeWrappedKey,
  deriveAuthVerifier,
  encodeWrappedKey,
  userKeyAssociatedData,
} from "../src/identity";

describe("userKeyAssociatedData", () => {
  it("matches the independent vectors", () => {
    expect(toHex(userKeyAssociatedData("x25519"))).toBe(
      "736c756963652f757365722d6b65792f76317c783235353139",
    );
    expect(toHex(userKeyAssociatedData("ed25519"))).toBe(
      "736c756963652f757365722d6b65792f76317c65643235353139",
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
  const box = { nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array(16).fill(2) };

  it("round-trips", () => {
    expect(decodeWrappedKey(encodeWrappedKey(box))).toEqual(box);
  });
  it("uses the ratified format", () => {
    expect(encodeWrappedKey(box)).toBe(`sluice.k1.${"01".repeat(12)}.${"02".repeat(16)}`);
  });
  it.each(["", "sluice.k2.00.00", `sluice.k1.${"01".repeat(12)}.${"02".repeat(15)}`])(
    "rejects %j",
    (blob) => {
      expect(() => decodeWrappedKey(blob)).toThrow();
    },
  );
});
