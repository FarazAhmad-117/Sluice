import { describe, expect, it } from "vitest";
import { randomBytes, utf8 } from "../src/bytes";
import { seal, unseal } from "../src/aead";

/**
 * Every call in this file passes associated data, because `seal` and `unseal`
 * now require it. That is the shape of a real Sluice call: a secret always
 * belongs to an environment, and binding the ciphertext to that environment is
 * what stops a `dev` blob being replayed into `prod` by someone with database
 * write access.
 */
const AAD = utf8.encode("environment:prod");

describe("seal and unseal", () => {
  it("round-trips a payload", async () => {
    const key = randomBytes(32);
    const message = utf8.encode("sk_live_not_a_real_key");
    const box = await seal(key, message, AAD);
    expect(await unseal(key, box, AAD)).toEqual(message);
  });

  it("round-trips an empty payload", async () => {
    const key = randomBytes(32);
    const box = await seal(key, new Uint8Array(), AAD);
    expect(await unseal(key, box, AAD)).toEqual(new Uint8Array());
  });

  it("produces a fresh nonce on every call", async () => {
    const key = randomBytes(32);
    const message = utf8.encode("same input");
    const a = await seal(key, message, AAD);
    const b = await seal(key, message, AAD);
    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });

  it("uses a 12 byte nonce", async () => {
    const box = await seal(randomBytes(32), utf8.encode("x"), AAD);
    expect(box.nonce).toHaveLength(12);
  });

  it("appends a 16 byte tag to the ciphertext", async () => {
    const box = await seal(randomBytes(32), new Uint8Array(), AAD);
    expect(box.ciphertext).toHaveLength(16);
  });

  it("rejects a wrong key", async () => {
    const box = await seal(randomBytes(32), utf8.encode("secret"), AAD);
    await expect(unseal(randomBytes(32), box, AAD)).rejects.toThrow();
  });

  it("rejects a tampered ciphertext", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"), AAD);
    const tampered = new Uint8Array(box.ciphertext);
    tampered[0] = (tampered[0] as number) ^ 0x01;
    await expect(unseal(key, { ...box, ciphertext: tampered }, AAD)).rejects.toThrow();
  });

  it("rejects a tampered nonce", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"), AAD);
    const tampered = new Uint8Array(box.nonce);
    tampered[0] = (tampered[0] as number) ^ 0x01;
    await expect(unseal(key, { ...box, nonce: tampered }, AAD)).rejects.toThrow();
  });

  it("binds associated data", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"), AAD);
    await expect(unseal(key, box, utf8.encode("environment:dev"))).rejects.toThrow();
    expect(await unseal(key, box, AAD)).toEqual(utf8.encode("secret"));
  });

  /**
   * Replaces an older test that opened AAD-bound data "with no AAD". That call
   * is no longer representable -- the parameter is required -- so the property
   * it was protecting is stated here instead: a ciphertext bound to one
   * environment must not open under another, which is the whole point of the
   * binding.
   */
  it("does not let a dev ciphertext be replayed into prod", async () => {
    const key = randomBytes(32);
    const dev = await seal(key, utf8.encode("secret"), utf8.encode("environment:dev"));
    await expect(unseal(key, dev, utf8.encode("environment:prod"))).rejects.toThrow();
    expect(await unseal(key, dev, utf8.encode("environment:dev"))).toEqual(utf8.encode("secret"));
  });

  it("rejects a key that is not 32 bytes", async () => {
    await expect(seal(randomBytes(16), utf8.encode("x"), AAD)).rejects.toThrow(/32 bytes/);
    const box = await seal(randomBytes(32), utf8.encode("x"), AAD);
    await expect(unseal(randomBytes(16), box, AAD)).rejects.toThrow(/32 bytes/);
  });

  // Matched on the message, not a bare rejection: GCM accepts arbitrary IV
  // lengths, so an over-long nonce fails authentication anyway and a bare
  // toThrow() would pass without the guard ever being written.
  it("rejects a nonce that is not 12 bytes", async () => {
    const key = randomBytes(32);
    const box = await seal(key, utf8.encode("secret"), AAD);
    await expect(unseal(key, { ...box, nonce: randomBytes(16) }, AAD)).rejects.toThrow(/12 bytes/);
    await expect(unseal(key, { ...box, nonce: randomBytes(32) }, AAD)).rejects.toThrow(/12 bytes/);
  });

  /**
   * ASSOCIATED DATA IS REQUIRED, and this is the test that says so at runtime.
   *
   * The type system stops a TypeScript caller from omitting it, but this
   * package ships to JavaScript consumers too, and `undefined` arrives from a
   * typo, an optional chain, or a config lookup that returned nothing. Omitting
   * it used to produce a perfectly valid ciphertext bound to NOTHING -- the
   * exact outcome the empty-AAD guard below exists to prevent, reachable by
   * leaving out an argument rather than by passing a bad one.
   */
  it("rejects a missing associatedData rather than silently binding nothing", async () => {
    const key = randomBytes(32);
    const omitted = undefined as unknown as Uint8Array;
    await expect(seal(key, utf8.encode("x"), omitted)).rejects.toThrow(/associatedData/);
    const box = await seal(key, utf8.encode("x"), AAD);
    await expect(unseal(key, box, omitted)).rejects.toThrow(/associatedData/);
  });

  it("rejects empty associated data rather than silently binding nothing", async () => {
    const key = randomBytes(32);
    await expect(seal(key, utf8.encode("x"), new Uint8Array())).rejects.toThrow(
      /must not be empty/,
    );
    const box = await seal(key, utf8.encode("x"), AAD);
    await expect(unseal(key, box, new Uint8Array())).rejects.toThrow(/must not be empty/);
  });
});
