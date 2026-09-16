# Sluice Foundation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stand up the Sluice monorepo, ship an auditable standalone crypto core, and deploy the public landing page to Vercel.

**Architecture:** A pnpm workspace monorepo. `packages/crypto` is a zero-Convex, zero-framework TypeScript library holding every cryptographic primitive, published and testable on its own so it can be audited without reading the app. `apps/web` is a Next.js app serving the landing page, dashboard and docs. `convex/` holds the backend. This plan covers the foundation through a live landing page. Backend, dashboard and delivery follow in later plans.

**Tech Stack:** pnpm workspaces, TypeScript, Vitest, @noble/hashes, @noble/curves, Next.js 15 App Router, Tailwind v4, shadcn/ui, Geist + Geist Mono, Vercel.

**Design authority:** `docs/plans/2026-09-16-sluice-design.md`. Read it before writing any UI.

---

## Ground rules for every task

- TDD. The failing test comes first, always. For crypto this is not optional: an untested key derivation that looks right is the most dangerous code in the repo.
- Commit after every task. Small commits make a security review tractable.
- `packages/crypto` takes no dependency on Convex, Next.js, React, or Node built-ins. It must run unchanged in a browser, in Node, and in Bun.
- Every visible string follows the copy rules in the design doc. Zero em-dashes.

---

# Milestone 1: Repo foundation

### Task 1: Workspace scaffold

**Files:**
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `tsconfig.base.json`
- Create: `.nvmrc`

**Step 1: Verify pnpm and Node**

Run: `node --version && pnpm --version`
Expected: Node 20 or newer, pnpm 9 or newer. If pnpm is missing, run `npm i -g pnpm`.

**Step 2: Write the root manifest**

`package.json`:

```json
{
  "name": "sluice",
  "private": true,
  "packageManager": "pnpm@10.30.3",
  "scripts": {
    "test": "pnpm -r test",
    "build": "pnpm -r build",
    "typecheck": "pnpm -r typecheck"
  }
}
```

`pnpm-workspace.yaml`:

```yaml
packages:
  - "packages/*"
  - "apps/*"
```

`.nvmrc`:

```
22
```

**Step 3: Write the shared TypeScript config**

`tsconfig.base.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "declaration": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

`noUncheckedIndexedAccess` matters here. Crypto code indexes into byte arrays constantly and this catches a whole class of mistake.

**Step 4: Verify**

Run: `pnpm install`
Expected: completes with no workspace packages yet, no errors.

**Step 5: Commit**

```bash
git add package.json pnpm-workspace.yaml tsconfig.base.json .nvmrc
git commit -m "chore: scaffold pnpm workspace"
```

---

### Task 2: Crypto package skeleton and test harness

**Files:**
- Create: `packages/crypto/package.json`
- Create: `packages/crypto/tsconfig.json`
- Create: `packages/crypto/vitest.config.ts`
- Create: `packages/crypto/src/index.ts`
- Create: `packages/crypto/test/smoke.test.ts`

**Step 1: Write the package manifest**

`packages/crypto/package.json`:

```json
{
  "name": "@sluice/crypto",
  "version": "0.0.0",
  "type": "module",
  "main": "./src/index.ts",
  "exports": { ".": "./src/index.ts" },
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@noble/hashes": "^1.5.0",
    "@noble/curves": "^1.6.0"
  },
  "devDependencies": {
    "typescript": "^5.9.0",
    "vitest": "^2.1.0"
  }
}
```

The noble libraries are chosen deliberately: they are audited, dependency-free, and small enough that a reviewer can read them. Do not add a crypto dependency to this package without saying why in the commit message.

`packages/crypto/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "include": ["src", "test"]
}
```

`packages/crypto/vitest.config.ts`:

```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
```

**Step 2: Write the failing smoke test**

`packages/crypto/test/smoke.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { VERSION } from "../src/index.js";

describe("package", () => {
  it("exports a version tag", () => {
    expect(VERSION).toBe("sluice-crypto/v1");
  });
});
```

**Step 3: Run it to confirm it fails**

Run: `pnpm --filter @sluice/crypto test`
Expected: FAIL, cannot resolve `VERSION` from `../src/index.js`.

**Step 4: Write the minimal implementation**

`packages/crypto/src/index.ts`:

```ts
export const VERSION = "sluice-crypto/v1";
```

**Step 5: Verify it passes**

Run: `pnpm --filter @sluice/crypto test`
Expected: PASS, 1 test.

**Step 6: Commit**

```bash
git add packages/crypto
git commit -m "feat(crypto): scaffold auditable crypto package"
```

---

### Task 3: Byte helpers with known test vectors

Every later task depends on these. Get them right and tested before touching real crypto.

**Files:**
- Create: `packages/crypto/src/bytes.ts`
- Create: `packages/crypto/test/bytes.test.ts`

**Step 1: Write the failing tests**

`packages/crypto/test/bytes.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { concat, constantTimeEqual, fromHex, toHex, randomBytes } from "../src/bytes.js";

describe("hex", () => {
  it("round-trips a known vector", () => {
    expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe("deadbeef");
    expect(fromHex("deadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("rejects odd-length hex", () => {
    expect(() => fromHex("abc")).toThrow();
  });

  it("rejects non-hex characters", () => {
    expect(() => fromHex("zz")).toThrow();
  });
});

describe("concat", () => {
  it("joins in order", () => {
    const out = concat(new Uint8Array([1, 2]), new Uint8Array([3]));
    expect(out).toEqual(new Uint8Array([1, 2, 3]));
  });
});

describe("constantTimeEqual", () => {
  it("is true for identical arrays", () => {
    expect(constantTimeEqual(fromHex("00ff"), fromHex("00ff"))).toBe(true);
  });

  it("is false for different content", () => {
    expect(constantTimeEqual(fromHex("00ff"), fromHex("00fe"))).toBe(false);
  });

  it("is false for different lengths", () => {
    expect(constantTimeEqual(fromHex("00ff"), fromHex("00"))).toBe(false);
  });
});

describe("randomBytes", () => {
  it("returns the requested length", () => {
    expect(randomBytes(32)).toHaveLength(32);
  });

  it("does not repeat across calls", () => {
    expect(toHex(randomBytes(32))).not.toBe(toHex(randomBytes(32)));
  });
});
```

**Step 2: Run to confirm failure**

Run: `pnpm --filter @sluice/crypto test`
Expected: FAIL, module `../src/bytes.js` not found.

**Step 3: Implement**

`packages/crypto/src/bytes.ts`:

```ts
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string must have even length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = hex.slice(i * 2, i * 2 + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) throw new Error("invalid hex string");
    out[i] = Number.parseInt(pair, 16);
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Length-independent comparison. Never use === on secret material. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export const utf8 = {
  encode: (s: string) => new TextEncoder().encode(s),
  decode: (b: Uint8Array) => new TextDecoder().decode(b),
};
```

**Step 4: Verify**

Run: `pnpm --filter @sluice/crypto test`
Expected: PASS, all bytes tests green.

**Step 5: Commit**

```bash
git add packages/crypto
git commit -m "feat(crypto): add byte helpers with constant-time comparison"
```

---

### Task 4: AEAD seal and unseal

**Files:**
- Create: `packages/crypto/src/aead.ts`
- Create: `packages/crypto/test/aead.test.ts`

**Step 1: Write the failing tests**

`packages/crypto/test/aead.test.ts`:

```ts
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

  it("produces a fresh nonce on every call", async () => {
    const key = randomBytes(32);
    const message = utf8.encode("same input");
    const a = await seal(key, message);
    const b = await seal(key, message);
    expect(a.nonce).not.toEqual(b.nonce);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
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

  it("binds associated data", async () => {
    const key = randomBytes(32);
    const aad = utf8.encode("environment:prod");
    const box = await seal(key, utf8.encode("secret"), aad);
    await expect(unseal(key, box, utf8.encode("environment:dev"))).rejects.toThrow();
    expect(await unseal(key, box, aad)).toEqual(utf8.encode("secret"));
  });

  it("rejects a key that is not 32 bytes", async () => {
    await expect(seal(randomBytes(16), utf8.encode("x"))).rejects.toThrow();
  });
});
```

The associated-data test is the one that matters most. Binding a ciphertext to its environment id means a `dev` blob cannot be replayed into `prod` even by someone with write access to the database.

**Step 2: Run to confirm failure**

Run: `pnpm --filter @sluice/crypto test`
Expected: FAIL, module `../src/aead.js` not found.

**Step 3: Implement**

`packages/crypto/src/aead.ts`:

```ts
import { randomBytes } from "./bytes.js";

export interface SealedBox {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

const KEY_BYTES = 32;
const NONCE_BYTES = 12;

async function importKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== KEY_BYTES) {
    throw new Error(`key must be ${KEY_BYTES} bytes, got ${key.length}`);
  }
  return crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): Promise<SealedBox> {
  const cryptoKey = await importKey(key);
  const nonce = randomBytes(NONCE_BYTES);
  const params: AesGcmParams = { name: "AES-GCM", iv: nonce, tagLength: 128 };
  if (associatedData) params.additionalData = associatedData;
  const ciphertext = await crypto.subtle.encrypt(params, cryptoKey, plaintext);
  return { ciphertext: new Uint8Array(ciphertext), nonce };
}

export async function unseal(
  key: Uint8Array,
  box: SealedBox,
  associatedData?: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await importKey(key);
  const params: AesGcmParams = { name: "AES-GCM", iv: box.nonce, tagLength: 128 };
  if (associatedData) params.additionalData = associatedData;
  const plaintext = await crypto.subtle.decrypt(params, cryptoKey, box.ciphertext);
  return new Uint8Array(plaintext);
}
```

Note: WebCrypto appends the GCM tag to the ciphertext rather than returning it separately. The schema sketch in `Implementation_Plan.md` section 5 lists `tag` as its own column. Drop that column. Storing `{ciphertext, nonce}` is correct for this implementation and one fewer field to get wrong.

**Amendments applied during review. The shipped code includes all of these.**

The implementation above is the starting point, not the final state. Review found three gaps and one build trap, all reproduced empirically before fixing:

1. **`unseal` must enforce the nonce length.** GCM permits arbitrary IV lengths, so a box carrying a 16 or 32 byte nonce decrypts happily. A `SealedBox` is reconstituted from an untrusted database row, so the module enforces its own advertised invariant rather than trusting what is stored. Guard on `box.nonce.length !== NONCE_BYTES`.

2. **A zero-length `associatedData` must be rejected in both functions.** An empty AAD is cryptographically identical to no AAD, so a caller computing AAD from an environment id that turns out to be an empty string would get an unbound ciphertext and no error. Since AAD binding is the whole reason the parameter exists, this fails loudly. Implemented as one shared helper called from both paths so they cannot drift.

3. **`Uint8Array` does not satisfy `BufferSource` on TypeScript 5.7 or newer.** 5.7 made `Uint8Array` generic over its backing buffer, and DOM's `BufferSource` excludes `SharedArrayBuffer`. Every `crypto.subtle` argument position needs a narrowing helper returning `Uint8Array<ArrayBuffer>`. This affects every later task touching WebCrypto.

4. **Pin TypeScript to `^5.9.0`, not `^5.6.0`.** The `Uint8Array<ArrayBuffer>` generic does not exist before 5.7, so the earlier pin let a fresh install resolve a compiler that cannot build the package. Run `pnpm install --lockfile-only` after changing it, or `--frozen-lockfile` in CI fails on the drifted specifier.

Also decided here: **`SealedBox` carries no version field.** It is a crypto primitive, not a storage format. The storage layer binds the algorithm version into the AAD alongside the environment id, which makes the version authenticated rather than a mutable column an attacker could edit independently of the ciphertext.

**Step 4: Verify**

Run: `pnpm --filter @sluice/crypto test`
Expected: PASS.

**Step 5: Commit**

```bash
git add packages/crypto
git commit -m "feat(crypto): add AES-256-GCM seal and unseal with AAD binding"
```

---

### Task 5: Service token minting and the HKDF split

This is section 3.4 of `Implementation_Plan.md` and the heart of the zero-knowledge claim. The server must receive a public key and a blob it cannot open.

**Files:**
- Create: `packages/crypto/src/token.ts`
- Create: `packages/crypto/test/token.test.ts`

**Step 1: Write the failing tests**

`packages/crypto/test/token.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import {
  mintToken,
  parseToken,
  deriveTokenKeys,
  signHandshake,
  verifyHandshake,
} from "../src/token.js";

describe("mintToken", () => {
  it("produces a parseable token string", () => {
    const minted = mintToken({ environment: "prod" });
    const parsed = parseToken(minted.token);
    expect(toHex(parsed.tokenId)).toBe(toHex(minted.tokenId));
    expect(toHex(parsed.tokenSecret)).toBe(toHex(minted.tokenSecret));
  });

  it("prefixes the token with the environment", () => {
    expect(mintToken({ environment: "prod" }).token.startsWith("slc_prod_")).toBe(true);
  });

  it("keeps the unwrap key and secret out of the upload payload", () => {
    const minted = mintToken({ environment: "prod" });
    const uploadJson = JSON.stringify(minted.upload);
    expect(uploadJson).not.toContain(toHex(minted.unwrapKey));
    expect(uploadJson).not.toContain(toHex(minted.tokenSecret));
  });

  it("derives the same keys from the same secret", () => {
    const minted = mintToken({ environment: "prod" });
    const rederived = deriveTokenKeys(minted.tokenId, minted.tokenSecret);
    expect(toHex(rederived.unwrapKey)).toBe(toHex(minted.unwrapKey));
  });

  it("derives different auth and unwrap keys from one secret", () => {
    const minted = mintToken({ environment: "prod" });
    expect(toHex(minted.unwrapKey)).not.toBe(toHex(minted.authSeed));
  });

  it("produces distinct keys for distinct tokens", () => {
    const a = mintToken({ environment: "prod" });
    const b = mintToken({ environment: "prod" });
    expect(toHex(a.unwrapKey)).not.toBe(toHex(b.unwrapKey));
  });

  it("rejects a malformed token string", () => {
    expect(() => parseToken("slc_prod_nope")).toThrow();
  });
});

describe("handshake", () => {
  it("verifies a signature made with the matching secret", () => {
    const minted = mintToken({ environment: "prod" });
    const timestamp = 1_757_000_000;
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, timestamp);
    expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, timestamp, signature)).toBe(true);
  });

  it("rejects a signature over a different timestamp", () => {
    const minted = mintToken({ environment: "prod" });
    const signature = signHandshake(minted.tokenId, minted.tokenSecret, 1_757_000_000);
    expect(verifyHandshake(minted.upload.publicKey, minted.tokenId, 1_757_000_001, signature)).toBe(false);
  });

  it("rejects a signature from a different token", () => {
    const a = mintToken({ environment: "prod" });
    const b = mintToken({ environment: "prod" });
    const timestamp = 1_757_000_000;
    const signature = signHandshake(b.tokenId, b.tokenSecret, timestamp);
    expect(verifyHandshake(a.upload.publicKey, a.tokenId, timestamp, signature)).toBe(false);
  });
});
```

**Step 2: Run to confirm failure**

Run: `pnpm --filter @sluice/crypto test`
Expected: FAIL, module `../src/token.js` not found.

**Step 3: Implement**

`packages/crypto/src/token.ts`:

```ts
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import { concat, fromHex, randomBytes, toHex, utf8 } from "./bytes.js";

const TOKEN_ID_BYTES = 16;
const TOKEN_SECRET_BYTES = 32;
const AUTH_INFO = "sluice/auth/v1";
const UNWRAP_INFO = "sluice/unwrap/v1";

export interface TokenKeys {
  authSeed: Uint8Array;
  unwrapKey: Uint8Array;
}

/**
 * Splits one token secret into two independent keys.
 * The auth seed becomes an Ed25519 signing key whose public half the server
 * stores. The unwrap key opens the PDK and is never transmitted.
 */
export function deriveTokenKeys(tokenId: Uint8Array, tokenSecret: Uint8Array): TokenKeys {
  return {
    authSeed: hkdf(sha256, tokenSecret, tokenId, utf8.encode(AUTH_INFO), 32),
    unwrapKey: hkdf(sha256, tokenSecret, tokenId, utf8.encode(UNWRAP_INFO), 32),
  };
}

export interface MintedToken {
  token: string;
  tokenId: Uint8Array;
  tokenSecret: Uint8Array;
  authSeed: Uint8Array;
  unwrapKey: Uint8Array;
  /** The only part that may be sent to the server. */
  upload: { tokenId: string; publicKey: string };
}

export function mintToken(opts: { environment: string }): MintedToken {
  const tokenId = randomBytes(TOKEN_ID_BYTES);
  const tokenSecret = randomBytes(TOKEN_SECRET_BYTES);
  const { authSeed, unwrapKey } = deriveTokenKeys(tokenId, tokenSecret);
  const publicKey = ed25519.getPublicKey(authSeed);

  return {
    token: `slc_${opts.environment}_${toHex(tokenId)}.${toHex(tokenSecret)}`,
    tokenId,
    tokenSecret,
    authSeed,
    unwrapKey,
    upload: { tokenId: toHex(tokenId), publicKey: toHex(publicKey) },
  };
}

export function parseToken(token: string): { tokenId: Uint8Array; tokenSecret: Uint8Array } {
  const match = /^slc_[a-z0-9-]+_([0-9a-f]{32})\.([0-9a-f]{64})$/.exec(token);
  if (!match) throw new Error("malformed token");
  return { tokenId: fromHex(match[1] as string), tokenSecret: fromHex(match[2] as string) };
}

function handshakeMessage(tokenId: Uint8Array, timestamp: number): Uint8Array {
  return concat(tokenId, utf8.encode(String(timestamp)));
}

export function signHandshake(
  tokenId: Uint8Array,
  tokenSecret: Uint8Array,
  timestamp: number,
): Uint8Array {
  const { authSeed } = deriveTokenKeys(tokenId, tokenSecret);
  return ed25519.sign(handshakeMessage(tokenId, timestamp), authSeed);
}

export function verifyHandshake(
  publicKeyHex: string,
  tokenId: Uint8Array,
  timestamp: number,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, handshakeMessage(tokenId, timestamp), fromHex(publicKeyHex));
  } catch {
    return false;
  }
}
```

**Step 4: Verify**

Run: `pnpm --filter @sluice/crypto test`
Expected: PASS.

**Step 5: Commit**

```bash
git add packages/crypto
git commit -m "feat(crypto): add token minting with HKDF auth and unwrap split"
```

---

### Task 6: Signed revocation notices

The kill switch only fires on a valid signature. This is what stops a compromised server from mass-killing customer fleets.

**Files:**
- Create: `packages/crypto/src/revocation.ts`
- Create: `packages/crypto/test/revocation.test.ts`

**Step 1: Write the failing tests**

`packages/crypto/test/revocation.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes, toHex } from "../src/bytes.js";
import { signRevocation, verifyRevocation } from "../src/revocation.js";

function orgKeypair() {
  const privateKey = randomBytes(32);
  return { privateKey, publicKey: toHex(ed25519.getPublicKey(privateKey)) };
}

const notice = {
  tokenId: "a".repeat(32),
  epoch: 3,
  revokedAt: 1_757_000_000,
  reason: "laptop stolen",
};

describe("revocation notices", () => {
  it("verifies a notice signed by the org key", () => {
    const org = orgKeypair();
    const signature = signRevocation(org.privateKey, notice);
    expect(verifyRevocation(org.publicKey, notice, signature)).toBe(true);
  });

  it("rejects a notice signed by a different key", () => {
    const attacker = orgKeypair();
    const signature = signRevocation(attacker.privateKey, notice);
    expect(verifyRevocation(orgKeypair().publicKey, notice, signature)).toBe(false);
  });

  it("rejects a notice whose token id was swapped", () => {
    const org = orgKeypair();
    const signature = signRevocation(org.privateKey, notice);
    expect(verifyRevocation(org.publicKey, { ...notice, tokenId: "b".repeat(32) }, signature)).toBe(false);
  });

  it("rejects a notice whose epoch was rolled back", () => {
    const org = orgKeypair();
    const signature = signRevocation(org.privateKey, notice);
    expect(verifyRevocation(org.publicKey, { ...notice, epoch: 2 }, signature)).toBe(false);
  });

  it("rejects a garbage signature without throwing", () => {
    const org = orgKeypair();
    expect(verifyRevocation(org.publicKey, notice, randomBytes(64))).toBe(false);
  });
});
```

**Step 2: Run to confirm failure**

Run: `pnpm --filter @sluice/crypto test`
Expected: FAIL, module `../src/revocation.js` not found.

**Step 3: Implement**

`packages/crypto/src/revocation.ts`:

```ts
import { ed25519 } from "@noble/curves/ed25519";
import { fromHex, utf8 } from "./bytes.js";

export interface RevocationNotice {
  tokenId: string;
  epoch: number;
  revokedAt: number;
  reason: string;
}

/**
 * Canonical encoding. Field order is fixed so a notice signed by one client
 * verifies identically everywhere. Never sign JSON.stringify output: key order
 * is not guaranteed across engines, and a verifier that disagrees about key
 * order with the signer will reject every valid notice.
 */
function encode(notice: RevocationNotice): Uint8Array {
  return utf8.encode(
    [
      "sluice/revocation/v1",
      notice.tokenId,
      String(notice.epoch),
      String(notice.revokedAt),
      notice.reason,
    ].join("\n"),
  );
}

export function signRevocation(orgPrivateKey: Uint8Array, notice: RevocationNotice): Uint8Array {
  return ed25519.sign(encode(notice), orgPrivateKey);
}

export function verifyRevocation(
  orgPublicKeyHex: string,
  notice: RevocationNotice,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, encode(notice), fromHex(orgPublicKeyHex));
  } catch {
    return false;
  }
}
```

**Step 4: Verify**

Run: `pnpm --filter @sluice/crypto test`
Expected: PASS.

**Step 5: Commit**

```bash
git add packages/crypto
git commit -m "feat(crypto): add signed revocation notices with canonical encoding"
```

---

### Task 7: Master unlock key derivation

**Files:**
- Create: `packages/crypto/src/muk.ts`
- Create: `packages/crypto/test/muk.test.ts`

**Step 1: Confirm the Argon2id export exists before writing against it**

Run: `pnpm --filter @sluice/crypto exec node -e "import('@noble/hashes/argon2').then(m => console.log(Object.keys(m)))"`

Expected: a list including `argon2id`. If the module path differs in the installed version, read `node_modules/@noble/hashes/package.json` exports and adjust the import below. Do not guess the path.

**Step 2: Write the failing tests**

`packages/crypto/test/muk.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { deriveMUK } from "../src/muk.js";

describe("deriveMUK", () => {
  it("is deterministic for the same password and user", async () => {
    const a = await deriveMUK("correct horse battery staple", "user_123");
    const b = await deriveMUK("correct horse battery staple", "user_123");
    expect(toHex(a)).toBe(toHex(b));
  });

  it("differs for a different user with the same password", async () => {
    const a = await deriveMUK("correct horse battery staple", "user_123");
    const b = await deriveMUK("correct horse battery staple", "user_456");
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("differs for a different password", async () => {
    const a = await deriveMUK("correct horse battery staple", "user_123");
    const b = await deriveMUK("correct horse battery stapler", "user_123");
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("returns 32 bytes", async () => {
    expect(await deriveMUK("pw", "user_123")).toHaveLength(32);
  });

  it("rejects an empty password", async () => {
    await expect(deriveMUK("", "user_123")).rejects.toThrow();
  });
});
```

**Step 3: Run to confirm failure**

Run: `pnpm --filter @sluice/crypto test`
Expected: FAIL, module `../src/muk.js` not found.

**Step 4: Implement**

`packages/crypto/src/muk.ts`:

```ts
import { argon2id } from "@noble/hashes/argon2";
import { utf8 } from "./bytes.js";

/** Tuned per section 3.1 of Implementation_Plan.md. Do not lower these. */
export const ARGON2_PARAMS = { m: 65536, t: 3, p: 4, dkLen: 32 } as const;

export async function deriveMUK(password: string, userId: string): Promise<Uint8Array> {
  if (password.length === 0) throw new Error("password must not be empty");
  return argon2id(utf8.encode(password), utf8.encode(userId), { ...ARGON2_PARAMS });
}
```

The MUK never leaves the client. No function in this package should ever serialise it.

**Step 5: Verify**

Run: `pnpm --filter @sluice/crypto test`
Expected: PASS. These tests are slower than the rest because Argon2id is deliberately expensive. If the suite times out, raise the Vitest timeout for this file rather than weakening the parameters.

**Step 6: Commit**

```bash
git add packages/crypto
git commit -m "feat(crypto): add Argon2id master unlock key derivation"
```

---

### Task 8: Public surface and the leak guard test

**Files:**
- Modify: `packages/crypto/src/index.ts`
- Create: `packages/crypto/test/surface.test.ts`

**Step 1: Write the failing test**

`packages/crypto/test/surface.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";

describe("public surface", () => {
  it("exports exactly the intended functions", () => {
    expect(Object.keys(api).sort()).toEqual(
      [
        "ARGON2_PARAMS",
        "VERSION",
        "concat",
        "constantTimeEqual",
        "deriveMUK",
        "deriveTokenKeys",
        "fromHex",
        "mintToken",
        "unseal",
        "parseToken",
        "randomBytes",
        "seal",
        "signHandshake",
        "signRevocation",
        "toHex",
        "utf8",
        "verifyHandshake",
        "verifyRevocation",
      ].sort(),
    );
  });
});
```

This test exists so that adding an export is a deliberate act that shows up in a diff. On a security package, an accidentally exported internal is how key material escapes.

**Step 2: Run to confirm failure**

Run: `pnpm --filter @sluice/crypto test`
Expected: FAIL, received array contains only `VERSION`.

**Step 3: Implement**

`packages/crypto/src/index.ts`:

```ts
export const VERSION = "sluice-crypto/v1";

export { concat, constantTimeEqual, fromHex, randomBytes, toHex, utf8 } from "./bytes.js";
export { seal, unseal, type SealedBox } from "./aead.js";
export { deriveMUK, ARGON2_PARAMS } from "./muk.js";
export {
  mintToken,
  parseToken,
  deriveTokenKeys,
  signHandshake,
  verifyHandshake,
  type MintedToken,
  type TokenKeys,
} from "./token.js";
export { signRevocation, verifyRevocation, type RevocationNotice } from "./revocation.js";
```

**Step 4: Verify the whole suite and types**

Run: `pnpm --filter @sluice/crypto test && pnpm --filter @sluice/crypto typecheck`
Expected: all tests PASS, no type errors.

**Step 5: Commit**

```bash
git add packages/crypto
git commit -m "feat(crypto): lock the public API surface"
```

---

# Milestone 2: Landing page

### Task 9: Next.js app scaffold

**Step 1: Scaffold**

Run:
```bash
pnpm dlx create-next-app@latest apps/web --ts --tailwind --app --src-dir --import-alias "@/*" --eslint
```
Expected: `apps/web` created. Decline any prompt offering extra examples.

**Step 2: Confirm it runs**

Run: `pnpm --filter web dev`
Expected: server on http://localhost:3000, default page renders. Stop the server.

**Step 3: Commit**

```bash
git add apps/web
git commit -m "chore(web): scaffold Next.js app"
```

---

### Task 10: Design tokens and fonts

**Files:**
- Modify: `apps/web/src/app/globals.css`
- Modify: `apps/web/src/app/layout.tsx`

**Step 1: Install the fonts**

Run: `pnpm --filter web add geist`

**Step 2: Write the token layer**

In `apps/web/src/app/globals.css`, below the Tailwind import, define every color from the design doc as a CSS custom property on `:root`, then redefine the surface and text tokens under `[data-theme="dark"]`. The landing page sets `data-theme="dark"` explicitly and does not follow the system preference. The dashboard will follow the system preference with a manual override.

Required token names, semantic rather than hue-based:

```
--brand, --brand-hover, --brand-subtle
--status-healthy, --status-warning, --status-danger
--surface-base, --surface-panel, --surface-card, --hairline
--text-primary, --text-muted
--radius-input (4px), --radius-card (8px), --radius-modal (12px)
```

Do not write raw hex values in components. Every color reference goes through a token, so that adding light mode later is a token change and not a component rewrite.

**Step 3: Wire the fonts in the root layout**

`apps/web/src/app/layout.tsx` imports `GeistSans` and `GeistMono` from the `geist` package, applies both font CSS variables to `<html>`, and sets `lang="en"`. Map Tailwind's `font-sans` and `font-mono` onto those variables in the Tailwind theme block.

**Step 4: Verify**

Run: `pnpm --filter web dev`
Expected: page renders on the dark base color with Geist applied. Confirm in devtools that `--surface-base` resolves to the value from the design doc.

**Step 5: Commit**

```bash
git add apps/web
git commit -m "feat(web): add design tokens and Geist type system"
```

---

### Task 11: The particle field

This is the brand's signature visual and the one genuinely custom piece of the landing page. It renders a sphere of points that scatters on demand, which is what revocation looks like.

**Files:**
- Create: `apps/web/src/components/particle-field.tsx`

**Requirements:**

- A client component. `"use client"` on the first line.
- Renders to a `<canvas>` sized by `ResizeObserver`. No window resize listeners.
- Points are generated once into a typed array and animated with `requestAnimationFrame`. No React state per frame.
- Accepts `state: "idle" | "scattered"` as a prop so the hero can drive it. Idle rotates slowly; scattered accelerates points outward, fades them, then reforms.
- Honors `prefers-reduced-motion`. Under reduced motion it paints a single static frame of the idle state and never animates.
- Cancels the animation frame and disconnects the observer on unmount.

**Verification:** load the page, toggle reduced motion in devtools, confirm the canvas stops animating and still renders. Navigate away and back, confirm no leaked animation frames in the performance panel.

**Commit:**

```bash
git add apps/web/src/components/particle-field.tsx
git commit -m "feat(web): add particle field with scatter state"
```

---

### Task 12: Landing sections

**Files:**
- Modify: `apps/web/src/app/page.tsx`
- Create: `apps/web/src/components/landing/*.tsx`

Build in this order, committing each section separately:

1. **Nav.** One line at desktop, height at or under 72px. Logo, Docs, Threat model, GitHub star count, primary CTA.
2. **Hero.** Asymmetric split. Headline at most 2 lines, subtext at most 20 words. Particle field on the right. One primary and one secondary CTA. No trust strip and no tagline inside the hero.
3. **Quickstart.** A real copyable install command set in Geist Mono, with a copy button that confirms success.
4. **Kill switch.** A real terminal recording, not a div mock. Record with asciinema and embed the player. If the recording does not exist yet, leave a clearly labelled placeholder slot and list it in the handoff rather than faking it with markup.
5. **Threat model teaser.** Two columns: what Sluice defends against, and what it does not. The second column is the credibility move. Do not soften it.
6. **Contributors.** All-Contributors data read at build time. Avatars link to profiles.
7. **Sponsors.** GitHub Sponsors and Open Collective, read at build time.
8. **Footer.** Docs, GitHub, security policy, licence.

**Checked before each commit:**

- At most 3 eyebrow labels across the whole page.
- No two sections share a layout family.
- Zero em-dashes in any visible string.
- Every CTA label fits one line at desktop, and no two CTAs share an intent.
- Every interactive element has a visible focus ring and a pointer cursor.
- The page renders with no horizontal scroll at 375px.

---

### Task 13: Deploy

**Step 1: Create the repo and push**

```bash
gh repo create sluice --public --source . --remote origin --push
```

**Step 2: Connect Vercel**

Import the repo in Vercel. Set the root directory to `apps/web`. Use the default Next.js build command. Add the custom domain once the first deploy is green.

**Step 3: Verify the live deploy**

Load the production URL and check: renders dark, fonts load without a flash, particle field animates, copy button works, no console errors, Lighthouse performance at or above 90 on desktop.

**Step 4: Fix anything the check surfaced, commit, and confirm the redeploy is green**

---

# What comes after this plan

Each of these needs its own plan, and each depends on decisions that are better made with the crypto core already in hand.

- **Convex backend.** Schema, the `repo/` discipline layer, auth with Argon2id over TLS, orgs, projects, environments.
- **Dashboard.** Three-pane shell, dense secrets table, live audit stream panel, dual theming.
- **Delivery and kill switch.** Handshake `httpAction`, bundle subscription query, Node SDK, the full availability matrix from section 4.3 of `Implementation_Plan.md`, and chaos tests that kill the socket mid-flight, replay old signatures, forge revocations, and revoke during a deploy.
- **Docs site.** Threat model, self-hosting guide, SDK reference.
- **Open source hygiene.** `SECURITY.md`, `CONTRIBUTING.md` with DCO, Apache-2.0 licence, npm provenance attestation.

## Decisions carried forward into the next plan

- **Secret names are encrypted.** The schema stores `nameCiphertext`, not a plaintext name, and the dashboard sorts and searches client-side. Changing this later means migrating every row.
- **No `tag` column.** WebCrypto appends the GCM tag to the ciphertext. Store `{ciphertext, nonce}` only.
- **Convex-native with a `repo/` layer.** Plain functions, no interface, no adapter. The point is an enumerable surface, not portability.
- **`MintedToken` is a class, not an interface.** It carries `toJSON` and a Node inspect hook on its prototype so that a stray `logger.info({ minted })` cannot dump a customer's unwrap key into a log aggregator. Consequences: it is a value as well as a type, and structural construction from an object literal no longer compiles. Build one with `mintToken()`.
- **Redaction does not survive reshaping, and this is the sharp edge.** Verified: `JSON.stringify(minted)` is redacted, but `JSON.stringify({ ...minted })` and `structuredClone` both emit the full token string, which contains the token id and secret in hex and is therefore everything needed to derive the unwrap key. Any serialisation, queueing or telemetry layer that spreads or clones objects generically will break this. Such a layer must take `minted.upload` explicitly.
- **`@types/node` is deliberately absent from `packages/crypto`.** It keeps `node:` imports from compiling at all, which enforces the browser, Node and Bun portability rule structurally rather than by convention. The cost is that tests exercise the inspect hook through `Symbol.for("nodejs.util.inspect.custom")` rather than by calling `util.inspect`. That symbol is the contract Node's formatter uses, so the coverage is equivalent.
