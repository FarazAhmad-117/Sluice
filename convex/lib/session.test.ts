import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha256";
import { toHex, utf8 } from "@sluice/crypto";
import {
  SESSION_LIFETIME_MS,
  hashSessionToken,
  issueSessionToken,
} from "./session";

/**
 * The two primitives the session layer is built on, tested apart from the
 * database so that a failure here names the primitive rather than the handler
 * that used it.
 */
describe("issueSessionToken", () => {
  it("is 32 bytes in canonical lowercase hex", () => {
    expect(issueSessionToken()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("does not repeat", () => {
    // 256 bits of entropy, so a collision in a thousand draws is not a flake
    // waiting to happen, it is a broken random source.
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(issueSessionToken());
    expect(seen.size).toBe(1000);
  });
});

describe("hashSessionToken", () => {
  it("is deterministic", () => {
    const token = issueSessionToken();
    expect(hashSessionToken(token)).toBe(hashSessionToken(token));
  });

  it("is 32 bytes in canonical lowercase hex", () => {
    expect(hashSessionToken(issueSessionToken())).toMatch(/^[0-9a-f]{64}$/);
  });

  it("never returns the token it was given", () => {
    const token = issueSessionToken();
    const hash = hashSessionToken(token);
    expect(hash).not.toBe(token);
    expect(hash).not.toContain(token);
  });

  it("separates tokens that differ by one character", () => {
    const a = "0".repeat(64);
    const b = "0".repeat(63) + "1";
    expect(hashSessionToken(a)).not.toBe(hashSessionToken(b));
  });

  it("is domain separated from a bare SHA-256 of the token", () => {
    // Without the domain string, a value hashed for some other purpose that
    // happened to equal a session token would produce a row key that matches
    // this table. It costs one string to make that impossible.
    const token = issueSessionToken();
    expect(hashSessionToken(token)).not.toBe(toHex(sha256(utf8.encode(token))));
  });

  it("accepts any string rather than parsing one", () => {
    // Deliberate: a presented token is never decoded, so there is no malformed
    // case with its own error. Anything that is not byte identical to an
    // issued token simply misses the index.
    expect(() => hashSessionToken("")).not.toThrow();
    expect(() => hashSessionToken("not hex at all")).not.toThrow();
    expect(hashSessionToken("")).not.toBe(hashSessionToken("x"));
  });
});

describe("SESSION_LIFETIME_MS", () => {
  it("is twelve hours", () => {
    expect(SESSION_LIFETIME_MS).toBe(12 * 60 * 60 * 1000);
  });
});
