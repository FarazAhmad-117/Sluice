import { describe, expect, it } from "vitest";
import { randomBytes, utf8 } from "../src/bytes.js";
import { seal, unseal } from "../src/aead.js";

describe("seal and unseal", () => {
  it("round-trips a payload", async () => {
    const key = randomBytes(32);
    const message = utf8.encode("sk_live_not_a_real_key");
    const box = await seal(key, message);
    expect(await unseal(key, box)).toEqual(message);
  });

  it("round-trips an empty payload", async () => {
    const key = randomBytes(32);
    const box = await seal(key, new Uint8Array());
    expect(await unseal(key, box)).toEqual(new Uint8Array());
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
    await expect(unseal(randomBytes(32), box)).rejects.toThrow();
  });

  it("rejects a tampered ciphertext", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"));
    const tampered = new Uint8Array(box.ciphertext);
    tampered[0] = (tampered[0] as number) ^ 0x01;
    await expect(unseal(key, { ...box, ciphertext: tampered })).rejects.toThrow();
  });

  it("rejects a tampered nonce", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"));
    const tampered = new Uint8Array(box.nonce);
    tampered[0] = (tampered[0] as number) ^ 0x01;
    await expect(unseal(key, { ...box, nonce: tampered })).rejects.toThrow();
  });

  it("binds associated data", async () => {
    const key = randomBytes(32);
    const aad = utf8.encode("environment:prod");
    const box = await seal(key, utf8.encode("secret"), aad);
    await expect(unseal(key, box, utf8.encode("environment:dev"))).rejects.toThrow();
    expect(await unseal(key, box, aad)).toEqual(utf8.encode("secret"));
  });

  it("rejects opening AAD-bound data with no AAD", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"), utf8.encode("environment:prod"));
    await expect(unseal(key, box)).rejects.toThrow();
  });

  it("rejects a key that is not 32 bytes", async () => {
    await expect(seal(randomBytes(16), utf8.encode("x"))).rejects.toThrow(/32 bytes/);
    const box = await seal(randomBytes(32), utf8.encode("x"));
    await expect(unseal(randomBytes(16), box)).rejects.toThrow(/32 bytes/);
  });

  // Matched on the message, not a bare rejection: GCM accepts arbitrary IV
  // lengths, so an over-long nonce fails authentication anyway and a bare
  // toThrow() would pass without the guard ever being written.
  it("rejects a nonce that is not 12 bytes", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"));
    await expect(unseal(key, { ...box, nonce: randomBytes(16) })).rejects.toThrow(/12 bytes/);
    await expect(unseal(key, { ...box, nonce: randomBytes(32) })).rejects.toThrow(/12 bytes/);
  });

  it("rejects empty associated data rather than silently binding nothing", async () => {
    const key = randomBytes(32);
    await expect(seal(key, utf8.encode("x"), new Uint8Array())).rejects.toThrow(/must not be empty/);
    const box = await seal(key, utf8.encode("x"));
    await expect(unseal(key, box, new Uint8Array())).rejects.toThrow(/must not be empty/);
  });
});
