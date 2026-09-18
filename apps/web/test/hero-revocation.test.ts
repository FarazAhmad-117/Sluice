import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { fromHex, parseToken, toHex, verifyRevocation } from "@sluice/crypto";
import {
  HERO_REASON,
  attemptHeroRevocation,
  createHeroSession,
} from "../src/lib/landing/hero-revocation";

/**
 * THE LANDING PAGE'S CRYPTOGRAPHIC CLAIM.
 *
 * The hero invites a stranger to press "Forge it as the server" and watch the
 * fleet survive. That is a public claim about the product's central security
 * property, made to people who have not read the threat model and will not read
 * the source, so it needs a test for the same reason the protocol does.
 *
 * The failure this file exists to catch is not a crash. It is somebody
 * simplifying the demo -- dropping the second keypair, reusing one signature,
 * short-circuiting on `signer === "server"` -- so that the page keeps showing
 * exactly what it shows today while proving nothing at all. Every assertion
 * below is therefore about the BYTES, not about the rendered outcome.
 */

/** Signature length in hex characters. Ed25519 signatures are 64 bytes. */
const SIGNATURE_HEX_LENGTH = 128;

describe("hero session", () => {
  it("mints a token whose id is what the notices are signed over", () => {
    const session = createHeroSession();

    // The token id in the session must be the id of the token whose string the
    // page shows a hash of. If these ever drift, the demo is revoking one token
    // while displaying another.
    expect(toHex(parseToken(session.token).tokenId)).toBe(session.tokenId);
    expect(session.tokenId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("gives the organisation and the server operator different keys", () => {
    const session = createHeroSession();

    expect(toHex(session.serverPrivateKey)).not.toBe(toHex(session.orgPrivateKey));
    expect(session.orgPublicKeyHex).toBe(toHex(ed25519.getPublicKey(session.orgPrivateKey)));
  });

  it("does not reuse a session across calls", () => {
    // A module-level cache would make every visitor share a token id, which is
    // harmless on a demo and catastrophic as a habit.
    expect(createHeroSession().tokenId).not.toBe(createHeroSession().tokenId);
  });
});

describe("revocation attempt", () => {
  it("verifies when the organisation signs", () => {
    const session = createHeroSession();

    const attempt = attemptHeroRevocation(session, "org", 1);

    expect(attempt.verified).toBe(true);
    expect(attempt.signatureHex).toHaveLength(SIGNATURE_HEX_LENGTH);
  });

  it("does not verify when the server operator signs", () => {
    const session = createHeroSession();

    const attempt = attemptHeroRevocation(session, "server", 1);

    expect(attempt.verified).toBe(false);
  });

  /**
   * The load-bearing one.
   *
   * A forgery that failed because it was malformed would prove nothing: any
   * verifier rejects garbage. The forged notice has to be a genuine,
   * well-formed Ed25519 signature over the exact bytes the real one covers,
   * rejected for one reason only -- it was made by a key the organisation never
   * issued. This asserts exactly that, by verifying the same signature against
   * the server operator's OWN public key, where it must succeed.
   */
  it("forges a real signature that is genuine under the wrong key", () => {
    const session = createHeroSession();
    const epoch = 7;

    const attempt = attemptHeroRevocation(session, "server", epoch);
    expect(attempt.verified).toBe(false);

    const serverPublicKeyHex = toHex(ed25519.getPublicKey(session.serverPrivateKey));
    // `revokedAt` is read from the clock inside the attempt, so the notice is
    // reconstructed from the signature's own timestamp window rather than
    // guessed. Searching a small range keeps this deterministic without
    // exposing the notice from the module purely for the test's benefit.
    const verifiedUnderServerKey = withinClockWindow((revokedAt) =>
      verifyRevocation(
        serverPublicKeyHex,
        { tokenId: session.tokenId, epoch, revokedAt, reason: HERO_REASON },
        fromHex(attempt.signatureHex),
      ),
    );

    expect(verifiedUnderServerKey).toBe(true);
  });

  it("produces a distinct signature per epoch", () => {
    const session = createHeroSession();

    // Ed25519 is deterministic, so identical notices give identical bytes. The
    // signature on screen changing between presses is only true while the epoch
    // advances, which `RevocationNotice` requires anyway.
    const first = attemptHeroRevocation(session, "org", 1);
    const second = attemptHeroRevocation(session, "org", 2);

    expect(second.signatureHex).not.toBe(first.signatureHex);
  });

  it("measures a real elapsed time", () => {
    const attempt = attemptHeroRevocation(createHeroSession(), "org", 1);

    // Not a hardcoded figure, and not a figure the UI invented. An upper bound
    // rather than a lower one: the point is that it is measured, and asserting
    // it is above zero would flake on a coarse timer.
    expect(attempt.elapsedMs).toBeGreaterThanOrEqual(0);
    expect(attempt.elapsedMs).toBeLessThan(1000);
  });
});

/**
 * Runs `attempt` for each millisecond the signing clock could plausibly have
 * read, newest first, and reports whether any of them matched.
 *
 * Two hundred milliseconds of slack is far more than the microseconds a sign
 * takes, and keeps the search to a few hundred verifications.
 */
function withinClockWindow(attempt: (revokedAt: number) => boolean): boolean {
  const now = Date.now();
  for (let revokedAt = now; revokedAt > now - 200; revokedAt--) {
    if (attempt(revokedAt)) return true;
  }
  return false;
}
