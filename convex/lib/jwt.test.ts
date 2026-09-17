import { afterEach, describe, expect, it } from "vitest";
import {
  BUNDLE_TOKEN_LIFETIME_MS,
  signBundleToken,
  verifyBundleToken,
} from "./jwt";

const KEY_ONE =
  "1000000000000000000000000000000000000000000000000000000000000001";
const KEY_TWO =
  "2000000000000000000000000000000000000000000000000000000000000002";

const SUBJECT = "kd7abcdefghijklmnopqrstuvwx";
const NOW = 1_800_000_000_000;

/**
 * Written against `process.env` directly rather than through `vi.stubEnv`, for
 * the reason `verifier.test.ts` gives: the deployment reads
 * `process.env.JWT_SIGNING_KEY`, and a test that proves a stub works proves
 * nothing about the deployment.
 */
function withKey<T>(key: string | undefined, fn: () => T): T {
  const previous = process.env.JWT_SIGNING_KEY;
  if (key === undefined) delete process.env.JWT_SIGNING_KEY;
  else process.env.JWT_SIGNING_KEY = key;
  try {
    return fn();
  } finally {
    if (previous === undefined) delete process.env.JWT_SIGNING_KEY;
    else process.env.JWT_SIGNING_KEY = previous;
  }
}

afterEach(() => {
  delete process.env.JWT_SIGNING_KEY;
});

describe("the bundle token", () => {
  it("round trips the subject it was issued for", () => {
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      expect(verifyBundleToken({ token, now: NOW })).toEqual({
        subject: SUBJECT,
      });
    });
  });

  it("is three base64url segments with no padding", () => {
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      expect(token.split(".")).toHaveLength(3);
      expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    });
  });

  it("stops being accepted the instant it expires", () => {
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      // One millisecond before the deadline, still good.
      expect(
        verifyBundleToken({ token, now: NOW + BUNDLE_TOKEN_LIFETIME_MS - 1 }),
      ).not.toBeNull();
      // At the deadline, not good. `>=` rather than `>`, the same rule
      // `requireSession` applies, because a token valid "until" an instant is
      // not valid at it and the alternative leaves a window nobody revisits.
      expect(
        verifyBundleToken({ token, now: NOW + BUNDLE_TOKEN_LIFETIME_MS }),
      ).toBeNull();
    });
  });

  it("lives for five minutes and not longer", () => {
    expect(BUNDLE_TOKEN_LIFETIME_MS).toBe(5 * 60 * 1000);
  });

  it("does not verify under a different signing key", () => {
    const token = withKey(KEY_ONE, () =>
      signBundleToken({ subject: SUBJECT, now: NOW }),
    );
    expect(withKey(KEY_TWO, () => verifyBundleToken({ token, now: NOW }))).toBeNull();
  });

  it("refuses a token whose payload was edited", () => {
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      const other = signBundleToken({ subject: "kd7otherotherother", now: NOW });
      const [header, , signature] = token.split(".") as [string, string, string];
      const otherPayload = (other.split(".") as string[])[1] as string;
      expect(
        verifyBundleToken({
          token: `${header}.${otherPayload}.${signature}`,
          now: NOW,
        }),
      ).toBeNull();
    });
  });

  it("refuses the alg none downgrade", () => {
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      const payload = (token.split(".") as string[])[1] as string;
      const header = base64Url(JSON.stringify({ alg: "none", typ: "JWT" }));
      expect(verifyBundleToken({ token: `${header}.${payload}.`, now: NOW })).toBeNull();
      // And with the original signature still attached, which is the shape a
      // naive verifier that reads `alg` from the token would accept.
      const signature = (token.split(".") as string[])[2] as string;
      expect(
        verifyBundleToken({ token: `${header}.${payload}.${signature}`, now: NOW }),
      ).toBeNull();
    });
  });

  it("refuses a header that names any other algorithm", () => {
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      const [, payload, signature] = token.split(".") as [string, string, string];
      for (const alg of ["HS384", "HS512", "RS256", "hs256"]) {
        const header = base64Url(JSON.stringify({ alg, typ: "JWT" }));
        expect(
          verifyBundleToken({ token: `${header}.${payload}.${signature}`, now: NOW }),
        ).toBeNull();
      }
    });
  });

  it("refuses a token that is not three segments", () => {
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      expect(verifyBundleToken({ token: "", now: NOW })).toBeNull();
      expect(verifyBundleToken({ token: `${token}.extra`, now: NOW })).toBeNull();
      expect(
        verifyBundleToken({ token: token.split(".").slice(0, 2).join("."), now: NOW }),
      ).toBeNull();
    });
  });

  it("refuses a re-encoded token that is not byte identical", () => {
    // Base64 has spellings that decode to the same bytes. Accepting them would
    // give one token several strings, which a replay cache or a rate limit
    // bucket elsewhere would count as several identities.
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      const [header, payload, signature] = token.split(".") as [
        string,
        string,
        string,
      ];
      expect(
        verifyBundleToken({ token: `${header}==.${payload}.${signature}`, now: NOW }),
      ).toBeNull();
      expect(
        verifyBundleToken({ token: `${header}.${payload}.${signature}=`, now: NOW }),
      ).toBeNull();
    });
  });

  it("is loud rather than lenient when the key is missing or malformed", () => {
    expect(() => withKey(undefined, () => signBundleToken({ subject: SUBJECT, now: NOW }))).toThrow();
    expect(() => withKey("", () => signBundleToken({ subject: SUBJECT, now: NOW }))).toThrow();
    expect(() => withKey("not-hex", () => signBundleToken({ subject: SUBJECT, now: NOW }))).toThrow();
    // Uppercase hex is rejected rather than folded, the rule every other
    // identifier in this codebase obeys. Note this constant has letters in it:
    // uppercasing `KEY_ONE`, which is all digits, changes nothing and would
    // have made this assertion pass without testing anything.
    expect(() => withKey("AA".repeat(32), () => signBundleToken({ subject: SUBJECT, now: NOW }))).toThrow();
    // Verification too. A deployment that lost its key must fail, not quietly
    // start refusing every bundle as though every token were forged.
    const token = withKey(KEY_ONE, () => signBundleToken({ subject: SUBJECT, now: NOW }));
    expect(() => withKey(undefined, () => verifyBundleToken({ token, now: NOW }))).toThrow();
  });

  it("never carries the plaintext token id", () => {
    // The whole reason `serviceTokens` stores only a hash. A plaintext id in a
    // bearer token is a plaintext id in every log that prints one.
    withKey(KEY_ONE, () => {
      const token = signBundleToken({ subject: SUBJECT, now: NOW });
      const payload = (token.split(".") as string[])[1] as string;
      const claims = JSON.parse(
        new TextDecoder().decode(
          Uint8Array.from(
            atob(payload.replace(/-/g, "+").replace(/_/g, "/")),
            (c) => c.charCodeAt(0),
          ),
        ),
      ) as Record<string, unknown>;
      expect(Object.keys(claims).sort()).toEqual(["aud", "exp", "iat", "iss", "sub"]);
      expect(claims.sub).toBe(SUBJECT);
    });
  });
});

function base64Url(text: string): string {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
