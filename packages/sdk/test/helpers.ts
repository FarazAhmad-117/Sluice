import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes, signRevocation, toHex, type RevocationNotice } from "@sluice/crypto";
import { SluiceCore } from "../src/core";
import type { SecretBundle, SluiceCoreOptions, SluiceDecision, SluiceEvent } from "../src/types";

export interface Org {
  readonly privateKey: Uint8Array;
  readonly publicKeyHex: string;
}

export function orgKeyPair(): Org {
  const privateKey = randomBytes(32);
  return { privateKey, publicKeyHex: toHex(ed25519.getPublicKey(privateKey)) };
}

export function tokenIdHex(): string {
  return toHex(randomBytes(16));
}

export function notice(overrides: Partial<RevocationNotice> = {}): RevocationNotice {
  return {
    tokenId: "0".repeat(32),
    epoch: 1,
    revokedAt: 1_700_000_000_000,
    reason: "leaked in a public repo",
    ...overrides,
  };
}

export function bundle(
  secrets: Record<string, string> = { DATABASE_URL: "postgres://a" },
  epoch = 1,
): SecretBundle {
  return { epoch, secrets };
}

/** A core wired to a real org key, with a fixed token id. */
export function makeCore(
  org: Org,
  tokenId: string,
  overrides: Partial<SluiceCoreOptions> = {},
): SluiceCore {
  return new SluiceCore({
    orgRevocationPublicKey: org.publicKeyHex,
    tokenId,
    ...overrides,
  });
}

/** A `revocation` event carrying a genuine signature from `org`. */
export function signedRevocation(
  org: Org,
  n: RevocationNotice,
  now: number,
): Extract<SluiceEvent, { type: "revocation" }> {
  return { type: "revocation", now, notice: n, signature: signRevocation(org.privateKey, n) };
}

export function types(decisions: readonly SluiceDecision[]): string[] {
  return decisions.map((d) => d.type);
}

export function pick<T extends SluiceDecision["type"]>(
  decisions: readonly SluiceDecision[],
  type: T,
): Extract<SluiceDecision, { type: T }>[] {
  return decisions.filter((d): d is Extract<SluiceDecision, { type: T }> => d.type === type);
}
