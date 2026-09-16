import { describe, expect, it } from "vitest";
import { concat, constantTimeEqual, fromHex, toHex, randomBytes, utf8 } from "../src/bytes.js";

describe("hex", () => {
  it("round-trips a known vector", () => {
    expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe("deadbeef");
    expect(fromHex("deadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("pads single-digit bytes", () => {
    expect(toHex(new Uint8Array([0x00, 0x0f]))).toBe("000f");
  });

  it("rejects odd-length hex", () => {
    expect(() => fromHex("abc")).toThrow();
  });

  it("rejects non-hex characters", () => {
    expect(() => fromHex("zz")).toThrow();
  });

  it("handles the empty case", () => {
    expect(toHex(new Uint8Array())).toBe("");
    expect(fromHex("")).toEqual(new Uint8Array());
  });
});

describe("concat", () => {
  it("joins in order", () => {
    const out = concat(new Uint8Array([1, 2]), new Uint8Array([3]));
    expect(out).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("handles no arguments", () => {
    expect(concat()).toEqual(new Uint8Array());
  });
});

describe("constantTimeEqual", () => {
  it("is true for identical arrays", () => {
    expect(constantTimeEqual(fromHex("00ff"), fromHex("00ff"))).toBe(true);
  });

  it("is false for different content", () => {
    expect(constantTimeEqual(fromHex("00ff"), fromHex("00fe"))).toBe(false);
  });

  it("is false for different lengths", () => {
    expect(constantTimeEqual(fromHex("00ff"), fromHex("00"))).toBe(false);
  });

  it("is true for two empty arrays", () => {
    expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true);
  });
});

describe("randomBytes", () => {
  it("returns the requested length", () => {
    expect(randomBytes(32)).toHaveLength(32);
  });

  it("does not repeat across calls", () => {
    expect(toHex(randomBytes(32))).not.toBe(toHex(randomBytes(32)));
  });
});

describe("randomBytes bounds", () => {
  it("rejects a negative length", () => {
    expect(() => randomBytes(-1)).toThrow(/non-negative integer/);
  });

  it("rejects a fractional length", () => {
    expect(() => randomBytes(1.5)).toThrow(/non-negative integer/);
  });

  it("rejects a length above the ceiling", () => {
    expect(() => randomBytes(65537)).toThrow(/at most 65536/);
  });

  it("accepts exactly the ceiling", () => {
    expect(randomBytes(65536)).toHaveLength(65536);
  });

  it("accepts zero", () => {
    expect(randomBytes(0)).toEqual(new Uint8Array());
  });
});

describe("utf8", () => {
  it("round-trips ascii", () => {
    expect(utf8.decode(utf8.encode("hello"))).toBe("hello");
  });

  it("round-trips multi-byte characters", () => {
    const s = "café 🔐";
    expect(utf8.decode(utf8.encode(s))).toBe(s);
    // c,a,f = 1 each, é = 2, space = 1, padlock = 4 -> 10
    expect(utf8.encode(s)).toHaveLength(10);
  });

  it("throws on invalid UTF-8 rather than substituting U+FFFD", () => {
    expect(() => utf8.decode(new Uint8Array([0xff, 0xfe]))).toThrow();
  });

  it("handles the empty string", () => {
    expect(utf8.decode(utf8.encode(""))).toBe("");
  });
});
