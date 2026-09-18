import { ed25519 } from "@noble/curves/ed25519";
import { mintToken, signRevocation, toHex, verifyRevocation } from "@sluice/crypto";
import type { RevocationNotice } from "@sluice/crypto";

/**
 * THE CRYPTOGRAPHY BEHIND THE HERO DEMO.
 *
 * This is a `.ts` module and not a handful of closures inside `RevokeDemo.tsx`
 * for one reason: the landing page makes a cryptographic claim, and a claim the
 * page makes in public should be pinned by a test rather than by whether the
 * component happened to render the branch someone expected. `test/
 * hero-revocation.test.ts` asserts both outcomes against these functions.
 *
 * The demo's whole argument is that the two signers below are not two code
 * paths. They are the same call, `signRevocation`, over byte-identical notices,
 * differing only in which private key goes in. Everything after that -- the
 * `false`, the fleet surviving, the red border -- is Ed25519 declining to
 * verify, not a component deciding what to show. Keep it that way. The moment
 * anything here branches on `signer` after the key is chosen, the page is
 * asserting its conclusion instead of demonstrating it.
 */

/** Who signed an attempt. The forger is the operator of Sluice, by name. */
export type HeroSigner = "org" | "server";

export interface HeroSession {
  /** The organisation's revocation key. In production this lives in a browser. */
  orgPrivateKey: Uint8Array;
  orgPublicKeyHex: string;
  /**
   * Stands in for whoever runs the server: a perfectly valid Ed25519 key that
   * the organisation simply never issued. This is the threat model's whole
   * point, so it is a real key and not a corrupted copy of the real one.
   */
  serverPrivateKey: Uint8Array;
  /** Lowercase hex of the minted token id, as `RevocationNotice` requires. */
  tokenId: string;
  /** The full `slc_...` string. Only ever hashed for display, never rendered. */
  token: string;
}

export interface HeroAttempt {
  signer: HeroSigner;
  /** Full lowercase hex of the real signature. The caller truncates for display. */
  signatureHex: string;
  /** The return value of `verifyRevocation`. Never a literal. */
  verified: boolean;
  /**
   * Wall clock across sign and verify, in milliseconds.
   *
   * This measures the cryptography and nothing else. There is no network here
   * and no delivery path built yet, so any figure presented as end-to-end
   * latency would be invented. The caller must label it for what it is.
   */
  elapsedMs: number;
}

/** Short enough for the panel, long enough to read as a real audit string. */
export const HERO_REASON = "Laptop stolen at ORD. Rotating every token on this org.";

/**
 * Two keypairs and a token, none of which a server ever sees.
 *
 * Pure and synchronous, so a caller can run it straight out of an event
 * handler. Cost is three scalar multiplications and two `getRandomValues`
 * calls, comfortably under a millisecond on anything that can run the page.
 *
 * Callers must not run this during render or in a mount effect. It reads
 * `crypto.getRandomValues`, so on the server it either throws or -- worse --
 * succeeds and produces a token id the client then disagrees with.
 */
export function createHeroSession(): HeroSession {
  const orgPrivateKey = ed25519.utils.randomPrivateKey();
  const serverPrivateKey = ed25519.utils.randomPrivateKey();
  const minted = mintToken({ environment: "prod" });

  return {
    orgPrivateKey,
    orgPublicKeyHex: toHex(ed25519.getPublicKey(orgPrivateKey)),
    serverPrivateKey,
    tokenId: minted.upload.tokenId,
    token: minted.token,
  };
}

/**
 * Signs a revocation notice as `signer`, then verifies it as the SDK would.
 *
 * `epoch` is supplied by the caller rather than tracked here so this stays
 * pure: `RevocationNotice` requires a monotonic per-token counter, and a module
 * holding that counter in a module-level variable would leak state between two
 * demos on one page and between two tests in one file.
 *
 * Note which public key the verification uses. It is always the ORGANISATION's,
 * for both signers, because that is what an SDK has: the org key it was
 * configured with. A forged notice fails not because this function knows it is
 * forged, but because the SDK has no reason to have ever heard of the key that
 * signed it.
 */
export function attemptHeroRevocation(
  session: HeroSession,
  signer: HeroSigner,
  epoch: number,
): HeroAttempt {
  const notice: RevocationNotice = {
    tokenId: session.tokenId,
    epoch,
    revokedAt: Date.now(),
    reason: HERO_REASON,
  };

  const key = signer === "org" ? session.orgPrivateKey : session.serverPrivateKey;

  const started = performance.now();
  const signature = signRevocation(key, notice);
  const verified = verifyRevocation(session.orgPublicKeyHex, notice, signature);
  const elapsedMs = performance.now() - started;

  return { signer, signatureHex: toHex(signature), verified, elapsedMs };
}
