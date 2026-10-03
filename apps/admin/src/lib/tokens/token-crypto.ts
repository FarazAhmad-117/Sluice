import {
  fromHex,
  mintToken,
  pdkAssociatedData,
  seal,
  signRevocation,
  toHex,
  tokenIdHash,
  tokenMetaAssociatedData,
  unseal,
  utf8,
} from "@sluice/crypto";
import type { EnvironmentKey } from "@/lib/secrets/pdk";

/**
 * A SERVICE TOKEN'S CRYPTOGRAPHY, IN THE BROWSER: MINT, WRAP, SEAL, OPEN, SIGN.
 *
 * Issuing a token does three things the server can never do for us, because
 * it never holds the environment's project data key:
 *
 * - wraps that key to the token's unwrap key, under the associated data the
 *   bundle and the CLI rebuild (`pdkAssociatedData`, grantee type "token");
 * - seals the person's name for it and its plaintext id under the
 *   environment's key (`tokenMetaAssociatedData`), so any member can list it
 *   by name and revoke it later;
 * - hands back the token string once, wrapped so it is hard to log.
 *
 * Revoking signs a notice with the org's revocation key, which only a
 * member's browser can unwrap. The server checks the signature and stores it;
 * every running process checks it again before it stops.
 */

export type TokenTarget = "computer" | "server" | "ci" | "docker";

/** UTF-8 bytes, matching `MAX_TOKEN_NAME_BYTES` in `convex/tokens.ts`. */
export const TOKEN_NAME_MAX_BYTES = 64;

const DEFAULT_REASON = "Revoked from the dashboard.";

/** What is wrong with a name, in a sentence to show, or null when it is fine. */
export function tokenNameProblem(name: string): string | null {
  const trimmed = name.trim();
  if (trimmed === "") return "Give it a name.";
  if (utf8.encode(trimmed).length > TOKEN_NAME_MAX_BYTES) {
    return `Names can be up to ${TOKEN_NAME_MAX_BYTES} characters.`;
  }
  return null;
}

/**
 * The token string, held so that logging it takes effort. `reveal()` is the
 * only way out; JSON and string conversion show a placeholder. As with
 * `MintedToken`, the guards live on the prototype, so pass this object, never
 * a spread copy of it.
 */
export class IssuedToken {
  readonly #value: string;
  constructor(value: string) {
    this.#value = value;
  }
  reveal(): string {
    return this.#value;
  }
  toJSON(): string {
    return "[service token]";
  }
  toString(): string {
    return "[service token]";
  }
}

/** Exactly what `tokens.createServiceToken` takes, apart from the session and environment. */
export interface CreateTokenArgs {
  readonly tokenId: string;
  readonly publicKey: string;
  readonly wrappedPDK: string;
  readonly pdkNonce: string;
  readonly pdkVersion: number;
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly tokenIdCiphertext: string;
  readonly tokenIdNonce: string;
  readonly target: TokenTarget;
}

export interface Issued {
  readonly token: IssuedToken;
  readonly args: CreateTokenArgs;
  /** The row's identity once stored, for matching it in the listing. */
  readonly tokenIdHash: string;
}

export async function issueToken(input: {
  readonly key: EnvironmentKey;
  readonly environmentName: string;
  readonly name: string;
  readonly target: TokenTarget;
}): Promise<Issued> {
  const problem = tokenNameProblem(input.name);
  if (problem !== null) throw new Error(problem);
  const { key } = input;

  const minted = mintToken({ environment: input.environmentName });
  const hash = tokenIdHash({ tokenId: minted.tokenId });
  const meta = (field: "name" | "tokenId") =>
    tokenMetaAssociatedData({ environmentUid: key.environmentUid, pdkVersion: key.pdkVersion, tokenIdHash: hash, field });

  const [grant, name, id] = await Promise.all([
    seal(
      minted.unwrapKey,
      key.pdk,
      pdkAssociatedData({
        environmentUid: key.environmentUid,
        pdkVersion: key.pdkVersion,
        granteeType: "token",
        granteeId: hash,
      }),
    ),
    seal(key.pdk, utf8.encode(input.name.trim()), meta("name")),
    seal(key.pdk, minted.tokenId, meta("tokenId")),
  ]);
  // Two seals under one key: their nonces must differ. A collision is
  // astronomically unlikely and catastrophic for AES-GCM, so it is checked.
  if (toHex(name.nonce) === toHex(id.nonce)) {
    throw new Error("A nonce may not be reused under one project data key.");
  }

  return {
    token: new IssuedToken(minted.token),
    tokenIdHash: hash,
    args: {
      tokenId: minted.upload.tokenId,
      publicKey: minted.upload.publicKey,
      wrappedPDK: toHex(grant.ciphertext),
      pdkNonce: toHex(grant.nonce),
      pdkVersion: key.pdkVersion,
      nameCiphertext: toHex(name.ciphertext),
      nameNonce: toHex(name.nonce),
      tokenIdCiphertext: toHex(id.ciphertext),
      tokenIdNonce: toHex(id.nonce),
      target: input.target,
    },
  };
}

/** The sealed half of a `tokens.listProjectTokens` row. */
export interface SealedTokenMeta {
  readonly nameCiphertext: string;
  readonly nameNonce: string;
  readonly tokenIdCiphertext: string;
  readonly tokenIdNonce: string;
  readonly metaPdkVersion: number;
  readonly tokenIdHash: string;
}

export class TokenMetaOpenError extends Error {
  constructor() {
    // Silent about which input was wrong, as every unseal failure here is.
    super("This token's details could not be opened.");
    this.name = "TokenMetaOpenError";
  }
}

/**
 * Opens a token's name and id. The id is checked against the row's hash as
 * well as by the associated data, so a browser never signs a revocation for
 * an id that is not this row's.
 */
export async function openTokenMeta(
  key: EnvironmentKey,
  sealed: SealedTokenMeta,
): Promise<{ readonly name: string; readonly tokenIdHex: string }> {
  const meta = (field: "name" | "tokenId") =>
    tokenMetaAssociatedData({
      environmentUid: key.environmentUid,
      pdkVersion: sealed.metaPdkVersion,
      tokenIdHash: sealed.tokenIdHash,
      field,
    });
  try {
    const [name, id] = await Promise.all([
      unseal(key.pdk, { ciphertext: fromHex(sealed.nameCiphertext), nonce: fromHex(sealed.nameNonce) }, meta("name")),
      unseal(key.pdk, { ciphertext: fromHex(sealed.tokenIdCiphertext), nonce: fromHex(sealed.tokenIdNonce) }, meta("tokenId")),
    ]);
    if (tokenIdHash({ tokenId: id }) !== sealed.tokenIdHash) throw new TokenMetaOpenError();
    return { name: new TextDecoder("utf-8", { fatal: true }).decode(name), tokenIdHex: toHex(id) };
  } catch {
    throw new TokenMetaOpenError();
  }
}

/** Exactly what `tokens.revokeServiceToken` takes, apart from the session. */
export interface RevokeTokenArgs {
  readonly tokenId: string;
  readonly epoch: number;
  readonly revokedAt: number;
  readonly reason: string;
  readonly signature: string;
}

/**
 * Signs a revocation notice. The epoch is 1: a token is revoked once, and the
 * server refuses any notice at or below one it already holds. The reason is
 * broadcast to every process using the token and lands in their logs, so the
 * dashboard warns the person before they type one.
 */
export function signTokenRevocation(input: {
  readonly revocationKey: Uint8Array;
  readonly tokenIdHex: string;
  readonly reason: string;
  readonly now: number;
}): RevokeTokenArgs {
  const reason = input.reason.trim() === "" ? DEFAULT_REASON : input.reason.trim();
  const notice = { tokenId: input.tokenIdHex, epoch: 1, revokedAt: input.now, reason };
  return { ...notice, signature: toHex(signRevocation(input.revocationKey, notice)) };
}
