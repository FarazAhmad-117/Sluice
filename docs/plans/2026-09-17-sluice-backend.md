# Sluice Backend Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stand up the Convex backend: schema, a disciplined data-access layer, authentication that never sends a password, and the org, project, environment and secret hierarchy.

**Architecture:** Convex-native, with every database call routed through plain functions in `convex/repo/` so the surface stays enumerable. The server performs verification only and never decryption. Secret names and values are both ciphertext, bound by AEAD associated data to the environment they belong to, so a row cannot be replayed into a different environment even by someone with write access to the database.

**Tech Stack:** Convex, TypeScript, `@sluice/crypto` (the audited package from the foundation plan), Vitest with `convex-test`.

**Reads before starting:**
- `docs/plans/2026-09-16-sluice-foundation.md`, especially the carry-forward sections. They record decisions this plan depends on.
- `Implementation_Plan.md` sections 3 and 5.
- `packages/crypto/src/index.ts`, which is the entire public surface available to this work.

---

## Ground rules

- TDD. The failing test comes first and must be observed failing.
- Commit after every task.
- **Every database read and write goes through `convex/repo/`.** No query, mutation or action calls `ctx.db` directly. This is not an abstraction layer and it has no interface: it is a set of plain functions whose purpose is that the data surface can be enumerated by reading one directory. A reviewer asking "what can touch the secrets table" must get a complete answer from `grep`.
- The server never decrypts. If a task appears to require decrypting a customer value server-side, stop: the design is wrong, not the task.
- Zero em-dashes and zero en-dashes in any user-visible string.

---

## Convex constraints, verified in `Implementation_Plan.md` section 14

These shape the layout and are not negotiable.

- **`"use node"` files cannot contain any other Convex functions.** Node-runtime code lives in its own files, physically separated from queries and mutations.
- **Actions are not automatically retried**, because they may have side effects. Every action needs an idempotency key.
- **Memory limits differ by runtime: 64MB default, 512MB Node.** This matters more than it looks. Argon2id at the project's parameters allocates a single 64 MiB buffer, which is the entire default-runtime budget. **Nothing in this plan runs Argon2id server-side**, for the reason in Task 6, but if a future task tries to, it must be a `"use node"` action.
- **Actions time out at 10 minutes.**
- The default runtime's `crypto.subtle` coverage is incomplete: `deriveBits` for ECDH P-256 is unimplemented. Sluice is unaffected, because `@sluice/crypto` uses X25519 and Ed25519 through `@noble/curves`, which is pure JavaScript. Do not introduce a dependency on `subtle.deriveBits`.

---

# Milestone 1: Project, schema, and the repo layer

### Task 1: Initialise Convex

**Human step first.** The developer running this plan needs a Convex account at convex.dev. The CLI creates the project; there is no manual dashboard setup at this stage.

**Step 1: Install and initialise**

```bash
pnpm --filter web add convex
pnpm --filter web exec convex dev --once
```

The CLI prompts to create or select a project and writes `CONVEX_DEPLOYMENT` and `NEXT_PUBLIC_CONVEX_URL` into `apps/web/.env.local`.

**Step 2: Confirm `.env.local` is ignored**

Run: `git check-ignore -v apps/web/.env.local`
Expected: a match against the root `.gitignore` rule `.env.*`. If it does not match, stop and fix `.gitignore` before continuing. A deployment URL is not a secret, but the same file will later hold ones that are.

**Step 3: Commit**

Commit the dependency and any generated config, never `.env.local`.

---

### Task 2: Schema

**Files:**
- Create: `convex/schema.ts`

Write the schema from `Implementation_Plan.md` section 5, with the amendments the foundation plan recorded. The amendments are not optional and each has a reason:

```ts
// convex/schema.ts
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  users: defineTable({
    email: v.string(),
    // HMAC of the client-computed Argon2id verifier, under a server pepper.
    // Never the password, never the MUK. See Task 6.
    authVerifierHash: v.string(),
    publicKey: v.string(),        // X25519, hex
    verifyKey: v.string(),        // Ed25519, hex
    wrappedPrivateKey: v.string(),
    wrappedSigningKey: v.string(),
    recoveryBlob: v.optional(v.string()),
  }).index("by_email", ["email"]),

  orgs: defineTable({
    name: v.string(),
    slug: v.string(),
    revocationPublicKey: v.string(),
    wrappedRevocationKey: v.string(),
  }).index("by_slug", ["slug"]),

  orgMembers: defineTable({
    orgId: v.id("orgs"),
    userId: v.id("users"),
    role: v.union(v.literal("owner"), v.literal("admin"), v.literal("member")),
  }).index("by_org_user", ["orgId", "userId"])
    .index("by_user", ["userId"]),

  projects: defineTable({
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
  }).index("by_org", ["orgId"]),

  environments: defineTable({
    projectId: v.id("projects"),
    name: v.string(),
    pdkVersion: v.number(),
    epoch: v.number(),
  }).index("by_project", ["projectId"]),

  pdkGrants: defineTable({
    environmentId: v.id("environments"),
    granteeType: v.union(v.literal("user"), v.literal("token")),
    granteeId: v.string(),
    wrappedPDK: v.string(),
    nonce: v.string(),
  }).index("by_environment", ["environmentId"])
    .index("by_grantee", ["granteeType", "granteeId"]),

  secrets: defineTable({
    environmentId: v.id("environments"),
    // Both name and value are ciphertext. The name is encrypted because a
    // plaintext column full of STRIPE_LIVE_SECRET_KEY tells an attacker with
    // database access exactly which ciphertext to prioritise, and tells the
    // operator something they publicly claim not to know.
    nameCiphertext: v.string(),
    nameNonce: v.string(),
    valueCiphertext: v.string(),
    valueNonce: v.string(),
    pdkVersion: v.number(),
    version: v.number(),
    deletedAt: v.optional(v.number()),
  }).index("by_environment", ["environmentId"]),

  serviceTokens: defineTable({
    environmentId: v.id("environments"),
    // The id is stored hashed so a database reader cannot enumerate valid
    // identifiers. Lookups hash the incoming id and match on this.
    tokenIdHash: v.string(),
    publicKey: v.string(),
    wrappedPDK: v.string(),
    nonce: v.string(),
    epoch: v.number(),
    status: v.union(v.literal("active"), v.literal("revoked")),
    lastSeenAt: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
  }).index("by_token_id_hash", ["tokenIdHash"])
    .index("by_environment", ["environmentId"]),

  revocations: defineTable({
    tokenId: v.string(),
    epoch: v.number(),
    signature: v.string(),
    signedBy: v.id("users"),
    revokedAt: v.number(),
    reason: v.string(),
  }).index("by_token_id", ["tokenId"]),

  // Replay protection for the handshake. Ed25519 signatures are deterministic,
  // so the same token id and timestamp always produce the same signature.
  // Verification proves authenticity, not freshness. See Task 10.
  handshakeNonces: defineTable({
    signatureHash: v.string(),
    expiresAt: v.number(),
  }).index("by_signature_hash", ["signatureHash"])
    .index("by_expiry", ["expiresAt"]),

  auditLog: defineTable({
    orgId: v.id("orgs"),
    actorType: v.union(v.literal("user"), v.literal("token"), v.literal("system")),
    actorId: v.string(),
    action: v.string(),
    targetId: v.optional(v.string()),
    ip: v.optional(v.string()),
    ts: v.number(),
    metadata: v.optional(v.string()),
  }).index("by_org_ts", ["orgId", "ts"]),
});
```

**Deliberate departures from the sketch in `Implementation_Plan.md`, each recorded in the foundation plan:**

- **No `tag` column on `secrets`.** WebCrypto appends the GCM tag to the ciphertext. A separate column would always be empty and is one more field to get inconsistent.
- **Secret names are ciphertext.** Sorting and search move to the client, which already holds the PDK.
- **`handshakeNonces` is new.** Without it the handshake is replayable, because Ed25519 is deterministic.
- **`revocations.tokenId` is the plaintext id**, not the hash, because the SDK matches on it and the notice is signed over it. The signed encoding pins it to 32 lowercase hex characters, so canonicalisation is already enforced by `@sluice/crypto`.

**Verify:** `pnpm --filter web exec convex dev --once` pushes the schema without error.

**Commit:** `feat(convex): add schema with encrypted secret names`

---

### Task 3: The repo layer and its enumeration test

**Files:**
- Create: `convex/repo/users.ts`, `orgs.ts`, `projects.ts`, `environments.ts`, `secrets.ts`, `tokens.ts`, `audit.ts`
- Create: `convex/repo/README.md`
- Create: `convex/repo/repo.test.ts`

Each file exports plain async functions taking a Convex context as their first argument. No classes, no interface, no adapter.

**Write the enumeration test first.** It reads every file under `convex/` that is not in `repo/` and asserts none of them contains `ctx.db`. This is the mechanism that makes the discipline real rather than aspirational, and it is the reason this layer exists at all.

```ts
// convex/repo/repo.test.ts
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry !== "_generated" && entry !== "repo") walk(full, out);
    } else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

describe("repo discipline", () => {
  it("is the only place that touches ctx.db", () => {
    const offenders = walk("convex").filter((f) =>
      readFileSync(f, "utf8").includes("ctx.db"),
    );
    expect(offenders).toEqual([]);
  });
});
```

Note this test needs Node built-ins, so it lives in the app's test scope, not in `packages/crypto`, which deliberately has no `@types/node`.

`convex/repo/README.md` states in three sentences why the layer exists: the point is an enumerable data surface for review and audit, not portability, and nobody should turn it into an interface.

**Commit:** `feat(convex): add the repo layer and pin its discipline with a test`

---

# Milestone 2: Authentication

### Task 4: Test harness

**Files:**
- Create: `convex/convex.test.ts` or equivalent harness setup

Install and wire `convex-test` so mutations and queries run against an in-memory database. Prove the harness works with one trivial round trip before building anything on it.

**Commit:** `test(convex): add the convex-test harness`

---

### Task 5: Signup

**Files:**
- Create: `convex/auth.ts`
- Create: `convex/auth.test.ts`

The client does all the expensive work. It derives the MUK with Argon2id, wraps its keypairs, derives a **separate** auth verifier, and uploads only public material plus opaque blobs.

`signup` accepts: `email`, `authVerifier` (hex), `publicKey`, `verifyKey`, `wrappedPrivateKey`, `wrappedSigningKey`, `recoveryBlob`.

**Tests, at minimum:**
- A new email creates a user and returns its id.
- A duplicate email is rejected.
- The stored record contains no plaintext password and no value equal to the submitted `authVerifier`.
- An email that differs only by case is treated as the same account.
- `authVerifier` must be 64 lowercase hex characters, matching the canonical-hex rule `@sluice/crypto` enforces on every other identifier.

**Commit:** `feat(convex): add signup that never receives a password`

---

### Task 6: Verifier hashing, and why Argon2id is not on the server

**Files:**
- Create: `convex/node/verifier.ts` (only if the chosen primitive needs Node; prefer not)
- Modify: `convex/auth.ts`

The stored value is `HMAC-SHA256(authVerifier, pepper)`, where the pepper is a Convex environment variable.

**This is a deliberate design choice and the plan must justify it in a comment**, because a reviewer will reasonably ask why a password-adjacent value is protected by a fast hash:

The client already paid the Argon2id cost. The `authVerifier` it uploads is a 256-bit value with full entropy, not a password, so there is nothing to brute-force: an attacker holding a database dump cannot guess a 256-bit input regardless of how fast the hash is. The pepper exists to defeat the dump-only attacker, since it lives in deployment configuration rather than in the table. Running Argon2id again server-side would add no security, would allocate 64 MiB against a 64MB default-runtime budget, and would therefore force every login through a `"use node"` action for nothing.

**Human step:** generate a pepper and set it in the Convex dashboard under Settings, Environment Variables, as `AUTH_PEPPER`. Generate it with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Document in the repo that this key, and the JWT signing key in Task 10, are the only secrets stored on Convex, and that neither can decrypt customer data.

**Tests:** the same verifier yields the same hash; a different verifier yields a different hash; the hash differs when the pepper differs; the stored hash is not the submitted verifier.

**Commit:** `feat(convex): hash the auth verifier under a server pepper`

---

### Task 7: Login and sessions

**Files:**
- Modify: `convex/auth.ts`

`login` takes `email` and `authVerifier`, compares with a constant-time comparison, and on success returns the wrapped key blobs so the client can unwrap them locally with its MUK.

**Tests:**
- A correct verifier returns the blobs.
- A wrong verifier fails.
- **A wrong verifier and an unknown email fail identically**, with the same error and no observable timing difference in the branch structure. An error that distinguishes them is an account enumeration oracle.
- The comparison uses `constantTimeEqual` from `@sluice/crypto`, not `===`.

**Commit:** `feat(convex): add login that returns only wrapped material`

---

# Milestone 3: The hierarchy

### Task 8: Orgs, projects, environments

**Files:**
- Create: `convex/orgs.ts`, `convex/projects.ts`, `convex/environments.ts`, and their tests

Creating an org also creates the owner membership and stores the org revocation public key plus the admin-wrapped private key. Creating an environment initialises `pdkVersion` at 1 and `epoch` at 0.

**Every mutation checks membership through the repo layer before writing.** Write the authorisation test before the happy-path test: a user who is not a member must not be able to read or write, and the test should assert that first.

**Commit one file at a time.**

---

### Task 9: Secrets

**Files:**
- Create: `convex/secrets.ts`, `convex/secrets.test.ts`

The server stores and returns ciphertext. It never sees a name or a value.

**The associated data rule, which is the important part of this task.** Every secret ciphertext is bound by AEAD associated data to a string combining the environment id and the algorithm version:

```
aad = utf8("sluice/secret/v1|" + environmentId)
```

This is the carry-forward decision from the foundation plan: the algorithm version is authenticated by living inside the AAD rather than sitting in a mutable column an attacker could edit independently of the ciphertext.

**Tests:**
- A secret round-trips through create and read as ciphertext, unchanged.
- No mutation or query in this file accepts a plaintext name or value. Assert this by inspecting the validators, not by convention.
- A secret belonging to one environment cannot be read through another environment's id.
- Soft delete sets `deletedAt` and the default listing excludes it.
- Versioning increments on update and the previous version remains readable.

**Commit:** `feat(convex): add secret storage that only ever holds ciphertext`

---

# Milestone 4: Delivery

### Task 10: The handshake `httpAction`

**Files:**
- Create: `convex/http.ts`
- Create: `convex/http.test.ts`

The SDK sends `tokenId`, `unixSeconds` and an Ed25519 signature. The server hashes the token id, looks up the stored public key, and verifies with `verifyHandshake` from `@sluice/crypto`.

**Four checks, in this order, and the order matters:**

1. The timestamp is a non-negative safe integer within 60 seconds of now. Reject outside the window before doing any cryptography, so an attacker cannot make the server work.
2. The signature verifies against the stored public key.
3. The signature hash is not present in `handshakeNonces`. **This is the replay defence and it is required**, because Ed25519 signatures are deterministic: the same token id and timestamp always produce identical bytes. Verification proves authenticity, never freshness.
4. The token status is `active` and `expiresAt`, if set, has not passed.

On success, insert the signature hash with a 120-second expiry, issue a short-lived JWT, and append an audit event.

**Human step:** generate a JWT signing key and set it in the Convex dashboard as `JWT_SIGNING_KEY`.

**Chaos tests belong here, not later:**
- A replayed request with the identical signature is rejected on the second attempt.
- A timestamp 61 seconds old is rejected.
- A timestamp 61 seconds in the future is rejected.
- A signature valid for one token does not authenticate another.
- A revoked token fails even with a perfectly valid signature.
- An unknown token id fails in the same way as a bad signature, revealing nothing about which token ids exist.

**Commit:** `feat(convex): add the token handshake with replay protection`

---

### Task 11: The bundle subscription

**Files:**
- Create: `convex/bundle.ts`, `convex/bundle.test.ts`

A query returning `{ wrappedPDK, secrets[], epoch, revocationNotice? }` for the authenticated token's environment. This is the reactive subscription that makes instant revocation work: Convex pushes an update to every live subscriber the moment a revocation row lands.

**Tests:**
- A token receives only its own environment's secrets.
- Inserting a revocation row causes the notice to appear in the bundle.
- An epoch bump changes the wrapped PDK the token receives.
- Everything in the bundle is ciphertext or public key material. Assert no field could be plaintext.

**Commit:** `feat(convex): add the reactive bundle subscription`

---

## Decisions carried into this plan, do not relitigate

- **Convex-native.** The `repo/` layer is discipline, not portability. Do not turn it into an interface.
- **Secret names are encrypted.** Client-side sort and search.
- **No `tag` column.** WebCrypto appends the GCM tag to the ciphertext.
- **Algorithm version lives in the AAD**, not in a column.
- **The org revocation public key must be pinned in customer configuration**, never fetched from this server. That is an SDK requirement, recorded in the foundation plan, and nothing in this plan may make it easy to violate.
- **Epochs must be globally monotonic per token id and must never reset.** The SDK's replay defence depends on it. Any code here that resets an epoch is a bug.

## Known gaps this plan does not close

- **Argon2id in the browser still takes about eight seconds** in pure JavaScript. The WASM and Web Worker task from the foundation plan must land before signup or login is usable by a real person. This plan builds the server side, which does not care, but the product is not shippable without it.
- **No account recovery.** The recovery kit and the Shamir break-glass from `Implementation_Plan.md` section 3.5 are not in this plan. Until they exist, a forgotten password is permanent data loss, and the signup UI must say so.
- **No rate limiting or brute-force lockout.** Task 10 is the obvious target and needs it before anything is public.
