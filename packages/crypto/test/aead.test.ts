import { describe, expect, it } from "vitest";
import { randomBytes, utf8 } from "../src/bytes.js";
import { seal, open } from "../src/aead.js";

describe("seal and open", () => {
  it("round-trips a payload", async () => {
    const key = randomBytes(32);
    const message = utf8.encode("sk_live_not_a_real_key");
    const box = await seal(key, message);
    expect(await open(key, box)).toEqual(message);
  });

  it("round-trips an empty payload", async () => {
    const key = randomBytes(32);
    const box = await seal(key, new Uint8Array());
    expect(await open(key, box)).toEqual(new Uint8Array());
  });

  it("produces a fresh nonce on every call", async () => {
    const key = randomBytes(32);
    const message = utf8.encode("same input");
    const a = await seal(key, message);
    const b = await seal(key, message);
    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });

  it("uses a 12 byte nonce", async () => {
    const box = await seal(randomBytes(32), utf8.encode("x"));
    expect(box.nonce).toHaveLength(12);
  });

  it("appends a 16 byte tag to the ciphertext", async () => {
    const box = await seal(randomBytes(32), new Uint8Array());
    expect(box.ciphertext).toHaveLength(16);
  });

  it("rejects a wrong key", async () => {
    const box = await seal(randomBytes(32), utf8.encode("secret"));
    await expect(open(randomBytes(32), box)).rejects.toThrow();
  });

  it("rejects a tampered ciphertext", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"));
    const tampered = new Uint8Array(box.ciphertext);
    tampered[0] = (tampered[0] as number) ^ 0x01;
    await expect(open(key, { ...box, ciphertext: tampered })).rejects.toThrow();
  });

  it("rejects a tampered nonce", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"));
    const tampered = new Uint8Array(box.nonce);
    tampered[0] = (tampered[0] as number) ^ 0x01;
    await expect(open(key, { ...box, nonce: tampered })).rejects.toThrow();
  });

  it("binds associated data", async () => {
    const key = randomBytes(32);
    const aad = utf8.encode("environment:prod");
    const box = await seal(key, utf8.encode("secret"), aad);
    await expect(open(key, box, utf8.encode("environment:dev"))).rejects.toThrow();
    expect(await open(key, box, aad)).toEqual(utf8.encode("secret"));
  });

  it("rejects opening AAD-bound data with no AAD", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"), utf8.encode("environment:prod"));
    await expect(open(key, box)).rejects.toThrow();
  });

  it("rejects a key that is not 32 bytes", async () => {
    await expect(seal(randomBytes(16), utf8.encode("x"))).rejects.toThrow(/32 bytes/);
    const box = await seal(randomBytes(32), utf8.encode("x"));
    await expect(open(randomBytes(16), box)).rejects.toThrow(/32 bytes/);
  });
});
