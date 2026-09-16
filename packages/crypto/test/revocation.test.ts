import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes, toHex, utf8 } from "../src/bytes.js";
import {
  signRevocation,
  verifyRevocation,
  type RevocationNotice,
} from "../src/revocation.js";

/** A fresh org signing key. Any 32 bytes is a valid Ed25519 seed. */
function orgKeyPair(): { privateKey: Uint8Array; publicKeyHex: string } {
  const privateKey = randomBytes(32);
  return { privateKey, publicKeyHex: toHex(ed25519.getPublicKey(privateKey)) };
}

/** A well-formed token id: the hex form of the 16 bytes `mintToken` produces. */
function tokenIdHex(): string {
  return toHex(randomBytes(16));
}

function notice(overrides: Partial<RevocationNotice> = {}): RevocationNotice {
  return {
    tokenId: tokenIdHex(),
    epoch: 7,
    revokedAt: 1_700_000_000_000,
    reason: "leaked in a public repo",
    ...overrides,
  };
}

/**
 * The ORIGINAL, unvalidated encoding, reproduced here on purpose.
 *
 * The production module no longer allows a notice that abuses this, so the
 * collision can only be demonstrated by signing these bytes directly -- exactly
 * what a signer without the validation guard, or an attacker with the org key
 * and a patched client, would emit. Keeping it in the test is what proves the
 * guard in `src/revocation.ts` is the thing closing the hole, rather than the
 * hole having quietly moved somewhere else.
 */
function naiveEncode(fields: {
  tokenId: unknown;
  epoch: unknown;
  revokedAt: unknown;
  reason: unknown;
}): Uint8Array {
  return utf8.encode(
    // Byte-faithful to the original: `tokenId` and `reason` went into `join`
    // raw, `epoch` and `revokedAt` through `String()`. The difference is not
    // cosmetic -- `join` renders null and undefined as "" while `String()`
    // renders them as "null" and "undefined", so wrapping all five uniformly
    // would produce a signature the old code would never have made, and the
    // null-reason case would then pass without any validation running.
    [
      "sluice/revocation/v1",
      fields.tokenId,
      String(fields.epoch),
      String(fields.revokedAt),
      fields.reason,
    ].join("\n"),
  );
}

/**
 * Every input `signRevocation` must refuse and `verifyRevocation` must call
 * false. One list, driven through both paths, because the entire point of the
 * shared validator is that the two cannot drift.
 */
const INVALID_NOTICES: ReadonlyArray<{ label: string; value: unknown }> = [
  { label: "non-hex tokenId", value: notice({ tokenId: "z".repeat(32) }) },
  { label: "uppercase tokenId", value: notice({ tokenId: "A".repeat(32) }) },
  { label: "31 character tokenId", value: notice({ tokenId: "a".repeat(31) }) },
  { label: "33 character tokenId", value: notice({ tokenId: "a".repeat(33) }) },
  { label: "empty tokenId", value: notice({ tokenId: "" }) },
  { label: "tokenId with a newline", value: { ...notice(), tokenId: "aa\nbb" } },
  { label: "non-string tokenId", value: { ...notice(), tokenId: 12 } },
  { label: "negative epoch", value: notice({ epoch: -1 }) },
  { label: "fractional epoch", value: notice({ epoch: 1.5 }) },
  { label: "NaN epoch", value: notice({ epoch: Number.NaN }) },
  { label: "Infinity epoch", value: notice({ epoch: Number.POSITIVE_INFINITY }) },
  { label: "-Infinity epoch", value: notice({ epoch: Number.NEGATIVE_INFINITY }) },
  { label: "-0 epoch", value: notice({ epoch: -0 }) },
  { label: "unsafe integer epoch", value: notice({ epoch: Number.MAX_SAFE_INTEGER + 2 }) },
  { label: "string epoch", value: { ...notice(), epoch: "bb" } },
  { label: "negative revokedAt", value: notice({ revokedAt: -1 }) },
  { label: "fractional revokedAt", value: notice({ revokedAt: 1.5 }) },
  { label: "NaN revokedAt", value: notice({ revokedAt: Number.NaN }) },
  { label: "Infinity revokedAt", value: notice({ revokedAt: Number.POSITIVE_INFINITY }) },
  { label: "-0 revokedAt", value: notice({ revokedAt: -0 }) },
  { label: "string revokedAt", value: { ...notice(), revokedAt: "2" } },
  { label: "reason over 512 characters", value: notice({ reason: "x".repeat(513) }) },
  { label: "non-string reason", value: { ...notice(), reason: 5 } },
  { label: "null reason", value: { ...notice(), reason: null } },
];

describe("revocation happy path", () => {
  it("verifies a notice signed by the org key", () => {
    const org = orgKeyPair();
    const n = notice();
    expect(verifyRevocation(org.publicKeyHex, n, signRevocation(org.privateKey, n))).toBe(true);
  });

  it("produces a deterministic signature for the same notice", () => {
    const org = orgKeyPair();
    const n = notice();
    expect(toHex(signRevocation(org.privateKey, n))).toBe(toHex(signRevocation(org.privateKey, n)));
  });

  it("accepts epoch and revokedAt of zero", () => {
    const org = orgKeyPair();
    const n = notice({ epoch: 0, revokedAt: 0 });
    expect(verifyRevocation(org.publicKeyHex, n, signRevocation(org.privateKey, n))).toBe(true);
  });

  it("accepts an empty reason", () => {
    const org = orgKeyPair();
    const n = notice({ reason: "" });
    expect(verifyRevocation(org.publicKeyHex, n, signRevocation(org.privateKey, n))).toBe(true);
  });

  it("accepts a reason containing newlines, since it is the final field", () => {
    const org = orgKeyPair();
    const n = notice({ reason: "line one\nline two\n" });
    expect(verifyRevocation(org.publicKeyHex, n, signRevocation(org.privateKey, n))).toBe(true);
  });
});

describe("revocation signed byte format", () => {
  /**
   * Pins the EXACT bytes that get signed, independently of the implementation.
   *
   * The expected string is written out literally here rather than obtained from
   * the module, so this is not circular: the signature is made over bytes this
   * test alone decides, and `verifyRevocation` only returns true if the module
   * agrees character for character. Without this, the versioned domain
   * separator could be dropped or edited and every other test in this file
   * would still pass -- verified by mutation, it did.
   *
   * The prefix is what stops these bytes being confused with a handshake
   * message or any future structure signed under the same key. Any deliberate
   * change to the format gets a `/v2` prefix and a new expectation here.
   */
  it("signs exactly the versioned, newline-joined field list", () => {
    const org = orgKeyPair();
    const n: RevocationNotice = {
      tokenId: "0123456789abcdef0123456789abcdef",
      epoch: 42,
      revokedAt: 1_700_000_000_000,
      reason: "compromised",
    };
    const expected =
      "sluice/revocation/v1\n" +
      "0123456789abcdef0123456789abcdef\n" +
      "42\n" +
      "1700000000000\n" +
      "compromised";

    expect(toHex(signRevocation(org.privateKey, n))).toBe(
      toHex(ed25519.sign(utf8.encode(expected), org.privateKey)),
    );
    expect(
      verifyRevocation(org.publicKeyHex, n, ed25519.sign(utf8.encode(expected), org.privateKey)),
    ).toBe(true);
  });

  it("does not accept the same fields without the domain separator", () => {
    const org = orgKeyPair();
    const n: RevocationNotice = {
      tokenId: "0123456789abcdef0123456789abcdef",
      epoch: 42,
      revokedAt: 1_700_000_000_000,
      reason: "compromised",
    };
    const undomained = "0123456789abcdef0123456789abcdef\n42\n1700000000000\ncompromised";
    expect(
      verifyRevocation(org.publicKeyHex, n, ed25519.sign(utf8.encode(undomained), org.privateKey)),
    ).toBe(false);
  });
});

describe("revocation wrong signer", () => {
  it("rejects a notice signed by a different private key", () => {
    const org = orgKeyPair();
    const attacker = orgKeyPair();
    const n = notice();
    expect(verifyRevocation(org.publicKeyHex, n, signRevocation(attacker.privateKey, n))).toBe(
      false,
    );
  });

  it("rejects verification against a different public key", () => {
    const org = orgKeyPair();
    const other = orgKeyPair();
    const n = notice();
    expect(verifyRevocation(other.publicKeyHex, n, signRevocation(org.privateKey, n))).toBe(false);
  });
});

describe("revocation field tampering", () => {
  const org = orgKeyPair();
  const base = notice({ tokenId: "a".repeat(32), epoch: 7, revokedAt: 1_700_000_000_000 });
  const signature = signRevocation(org.privateKey, base);

  const tampered: ReadonlyArray<{ label: string; value: RevocationNotice }> = [
    { label: "tokenId swapped", value: { ...base, tokenId: "b".repeat(32) } },
    { label: "epoch rolled back", value: { ...base, epoch: 6 } },
    { label: "epoch rolled forward", value: { ...base, epoch: 8 } },
    { label: "epoch zeroed", value: { ...base, epoch: 0 } },
    { label: "revokedAt changed", value: { ...base, revokedAt: base.revokedAt + 1 } },
    { label: "reason changed", value: { ...base, reason: base.reason + "!" } },
  ];

  for (const { label, value } of tampered) {
    it(`rejects a notice with ${label}`, () => {
      // Sanity: the tamper must actually change something, otherwise the test
      // would "pass" against an implementation that verifies nothing at all.
      expect(value).not.toEqual(base);
      expect(verifyRevocation(org.publicKeyHex, value, signature)).toBe(false);
    });
  }

  it("still accepts the untampered notice, so the rejections mean something", () => {
    expect(verifyRevocation(org.publicKeyHex, base, signature)).toBe(true);
  });
});

describe("revocation canonicalization attack", () => {
  /**
   * A: { tokenId: "aa\nbb", epoch: 1,    revokedAt: 2, reason: "x"    }
   * B: { tokenId: "aa",     epoch: "bb", revokedAt: 1, reason: "2\nx" }
   *
   * Both newline-join to `sluice/revocation/v1\naa\nbb\n1\n2\nx`.
   */
  const A = { tokenId: "aa\nbb", epoch: 1, revokedAt: 2, reason: "x" };
  const B = { tokenId: "aa", epoch: "bb", revokedAt: 1, reason: "2\nx" };

  it("confirms the two notices really do collide under the naive encoding", () => {
    expect(toHex(naiveEncode(A))).toBe(toHex(naiveEncode(B)));
  });

  it("refuses to sign notice A, because tokenId contains a newline", () => {
    const org = orgKeyPair();
    expect(() => signRevocation(org.privateKey, A as unknown as RevocationNotice)).toThrow();
  });

  it("refuses to verify notice B against a signature over the colliding bytes", () => {
    const org = orgKeyPair();
    // Signed directly, bypassing signRevocation, because signRevocation now
    // refuses to produce this. This is the strongest form of the attack: the
    // attacker has a genuine org signature over the ambiguous bytes.
    const signature = ed25519.sign(naiveEncode(A), org.privateKey);
    expect(verifyRevocation(org.publicKeyHex, B as unknown as RevocationNotice, signature)).toBe(
      false,
    );
    expect(verifyRevocation(org.publicKeyHex, A as unknown as RevocationNotice, signature)).toBe(
      false,
    );
  });
});

describe("revocation input validation", () => {
  for (const { label, value } of INVALID_NOTICES) {
    it(`signRevocation throws on ${label}`, () => {
      const org = orgKeyPair();
      expect(() => signRevocation(org.privateKey, value as RevocationNotice)).toThrow();
    });

    it(`verifyRevocation returns false on ${label}`, () => {
      const org = orgKeyPair();
      // A GENUINE org signature over exactly the bytes the unvalidated encoder
      // would produce for this notice. Signing junk instead would make this
      // test pass with no validation in verifyRevocation at all, since a
      // mismatched signature already returns false -- it would look
      // load-bearing while testing nothing. This version fails unless
      // verifyRevocation rejects the notice before it reaches ed25519.verify.
      const signature = ed25519.sign(naiveEncode(value as RevocationNotice), org.privateKey);
      expect(verifyRevocation(org.publicKeyHex, value as RevocationNotice, signature)).toBe(false);
    });
  }

  it("accepts a reason of exactly 512 characters, so the cap is not off by one", () => {
    const org = orgKeyPair();
    const n = notice({ reason: "x".repeat(512) });
    expect(verifyRevocation(org.publicKeyHex, n, signRevocation(org.privateKey, n))).toBe(true);
  });

  it("rejects a reason of exactly 513 characters", () => {
    const org = orgKeyPair();
    expect(() => signRevocation(org.privateKey, notice({ reason: "x".repeat(513) }))).toThrow();
  });

  /**
   * The failure mode that matters most: validation inside verifyRevocation
   * silently killing a real revocation. It cannot happen as long as the two
   * paths accept exactly the same set, which this pins down from the accepting
   * side. The INVALID_NOTICES loop above pins the rejecting side.
   */
  it("verifies every notice signRevocation was willing to sign", () => {
    const org = orgKeyPair();
    const accepted: RevocationNotice[] = [
      notice(),
      notice({ epoch: 0, revokedAt: 0 }),
      notice({ epoch: Number.MAX_SAFE_INTEGER, revokedAt: Number.MAX_SAFE_INTEGER }),
      notice({ reason: "" }),
      notice({ reason: "x".repeat(512) }),
      notice({ reason: "\n\n [31m" }),
      notice({ tokenId: "0".repeat(32) }),
      notice({ tokenId: "f".repeat(32) }),
      notice({ tokenId: "0123456789abcdef0123456789abcdef" }),
    ];
    for (const n of accepted) {
      expect(verifyRevocation(org.publicKeyHex, n, signRevocation(org.privateKey, n))).toBe(true);
    }
  });
});

describe("revocation malformed crypto inputs", () => {
  it("returns false for a garbage 64 byte signature instead of throwing", () => {
    const org = orgKeyPair();
    expect(verifyRevocation(org.publicKeyHex, notice(), randomBytes(64))).toBe(false);
  });

  it("returns false for an 8 byte signature instead of throwing", () => {
    const org = orgKeyPair();
    expect(verifyRevocation(org.publicKeyHex, notice(), randomBytes(8))).toBe(false);
  });

  it("returns false for an empty signature instead of throwing", () => {
    const org = orgKeyPair();
    expect(verifyRevocation(org.publicKeyHex, notice(), new Uint8Array(0))).toBe(false);
  });

  it("returns false for a non-hex public key instead of throwing", () => {
    const org = orgKeyPair();
    const n = notice();
    expect(verifyRevocation("zz".repeat(32), n, signRevocation(org.privateKey, n))).toBe(false);
  });

  it("returns false for an odd-length public key string instead of throwing", () => {
    const org = orgKeyPair();
    const n = notice();
    expect(verifyRevocation("abc", n, signRevocation(org.privateKey, n))).toBe(false);
  });

  it("returns false for an empty public key instead of throwing", () => {
    const org = orgKeyPair();
    const n = notice();
    expect(verifyRevocation("", n, signRevocation(org.privateKey, n))).toBe(false);
  });

  /**
   * ONE IDENTITY, ONE SPELLING.
   *
   * `fromHex` accepts `[0-9a-fA-F]`, so before this guard an UPPERCASED org
   * public key verified exactly as well as the lowercase one `toHex` emits.
   * Two strings, one identity, both returning true. A caller that keys anything
   * on that string -- a replay cache, a rate-limit bucket, a per-org epoch
   * table -- gets two entries for one organisation and each one silently misses
   * what the other recorded.
   *
   * The fix is rejection, not coercion. Lowercasing the input before decoding
   * would change nothing observable, because `fromHex` already decodes both
   * spellings to the same bytes; the second spelling has to stop verifying for
   * the ambiguity to actually be gone. `toHex` emits lowercase, so no value
   * this package produces is affected.
   */
  it("returns false for an uppercase or mixed-case public key", () => {
    const org = orgKeyPair();
    const n = notice();
    const signature = signRevocation(org.privateKey, n);
    expect(verifyRevocation(org.publicKeyHex, n, signature)).toBe(true);
    expect(verifyRevocation(org.publicKeyHex.toUpperCase(), n, signature)).toBe(false);
    // Uppercase exactly one hex LETTER, found by search rather than by slicing
    // a fixed prefix: a fixed prefix is all digits about 2% of the time, which
    // makes `mixed` identical to the key and the assertion flake.
    const key = org.publicKeyHex;
    const at = key.search(/[a-f]/);
    expect(at).toBeGreaterThanOrEqual(0);
    const mixed = key.slice(0, at) + (key[at] as string).toUpperCase() + key.slice(at + 1);
    expect(mixed).not.toBe(key);
    expect(verifyRevocation(mixed, n, signature)).toBe(false);
  });

  it("returns false for a 31 byte public key instead of throwing", () => {
    const org = orgKeyPair();
    const n = notice();
    expect(verifyRevocation(toHex(randomBytes(31)), n, signRevocation(org.privateKey, n))).toBe(
      false,
    );
  });
});

describe("revocation key validation", () => {
  it("throws a clear error on an org private key that is not 32 bytes", () => {
    for (const length of [0, 16, 31, 33, 64]) {
      expect(() => signRevocation(randomBytes(length), notice())).toThrow(/32 bytes/);
    }
  });

  it("accepts a 32 byte org private key", () => {
    expect(() => signRevocation(randomBytes(32), notice())).not.toThrow();
  });
});
