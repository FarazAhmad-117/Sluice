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

## Amendments from the schema review, applied 2026-09-17

The schema as originally written in this plan had four defects, all found by reviewing it against the tasks that would consume it. The shipped schema differs, and these constraints now bind the later tasks.

- **`revocations` carries `tokenIdHash` as well as the plaintext `tokenId`.** Without it the bundle query in Task 11 had no way to find a notice, because `serviceTokens` stores only the hash. Do not "clean up" the duplication: the plaintext id is there because the notice is signed over it, the hash is there so the query never needs the plaintext.
- **`secrets` carries `lineageId` and `supersededAt`.** Task 9 could otherwise have history or a usable listing, not both. **Task 9 must decide where lineage ids come from and assert their uniqueness**, because `lineageId` is a string and nothing stops two secrets sharing one, which would silently merge their histories. Minting from `randomBytes` is the obvious answer but it is a decision to write down.
- **`revocationGrants` replaces `orgs.wrappedRevocationKey`.** A single wrap made the product's wedge depend on one person never leaving, never forgetting their password, and never being the one whose laptop was stolen, which is the exact scenario revocation exists for. **Task 8 must create the org and its first revocation grant in the same mutation**, or an org exists that nobody can ever revoke for.
- **Narrow indexes were replaced by composite ones, not added alongside.** Each old index is a strict prefix of its replacement, so Convex answers the old query from the new index. Restoring a narrow index only adds write amplification.

### Constraints the later tasks inherit

- **Task 5 must normalise email before storage.** `by_email` is an exact-match index, so a case-insensitive account identity that is not normalised on write passes its test only by accident. Assert also that `getUserByEmail` throws on duplicates rather than silently picking one: that is the right failure mode for an auth table, but it should be a decision with a test, not an accident of `.unique()`.
- **Task 10's replay check must be a single mutation.** Check-then-insert as two calls is a time-of-check-to-time-of-use race in which two concurrent replays of the identical signature both observe "absent" and both succeed, which is precisely the attack `handshakeNonces` exists to stop. Insert and fail on conflict.
- **Tasks 10 and 11 must share one token-id hashing helper.** Two call sites computing the hash independently can diverge, and if they do, revocation silently stops reaching the bundle while every test that seeds one side by hand still passes. At least one test must revoke through the real path and read through the real bundle.
- **`auditLog.metadata` gets a discriminated validator per action type**, not a free-form string. It is the most likely place a decrypted name or a request body lands by accident, and because nothing reads it, nobody would notice.
- **`revocations.reason` must never carry secret-derived text.** It is signed and broadcast to every SDK instance, so an operator pasting incident context into it is a realistic path from incident to secret-in-every-customer-log. The foundation plan already requires the SDK to sanitise it for rendering; this is the separate rule that it must not contain sensitive text in the first place.
- **Task 4 fixtures go through repo functions.** The enumeration test scans test files too, so the usual `t.run(async (ctx) => ctx.db.insert(...))` seeding idiom is unavailable. This is deliberate: fixtures exercising the real insert path is a feature, and the data surface stays genuinely complete. Do not add an exclusion.

### New task: reap expired handshake nonces

`handshakeNonces` gains a row per successful handshake and nothing deletes them. `deleteExpiredHandshakeNonces` exists in the repo layer and takes a mandatory `limit`, returning a count.

Write a Convex cron that calls it and pages using the returned count. **Do not call it with an unbounded limit.** A reaper that tries to delete every expired row in one transaction will eventually exceed Convex's per-transaction limits, and from that point it never succeeds again: the table grows forever while the cleanup appears to run.

## Immediate follow-ups after the session work lands

Ordered by how fast they get more expensive.

1. **Delete or re-export `convex/lib/aad.ts`.** `@sluice/crypto` now owns the secret AAD rule, so there are currently **two** definitions of `"sluice/secret/v1|"` and both look authoritative. That is strictly worse than the single-sided definition it replaced. The crypto version also fixes two real holes the Convex one still has, verified rather than reasoned about:
   - `TextEncoder` substitutes U+FFFD for unpaired surrogates instead of throwing, so the environment ids `"\uD800"`, `"\uDC00"` and `"�"` are three distinct index keys that encode to identical bytes. Each can open the others' ciphertext. That is exactly the cross-environment binding failure the AAD exists to prevent.
   - A non-string id is not caught. A numeric `42` produces the well-formed AAD `"sluice/secret/v1|42"`, and `undefined` throws an unhelpful `TypeError` about reading a property rather than a useful error. An id off a database row or a URL segment is exactly where a number or a missing value comes from.

   The signature changed to an object argument. There are **zero callers today**, so the migration is free now and will not be once the web client seals its first secret.

2. **Ban the literal outside the crypto package.** Nothing mechanically stops the SDK or the dashboard from re-deriving the AAD by hand. A lint rule forbidding `sluice/secret/v1` anywhere except `packages/crypto` is the only enforcement available, and it belongs in the ESLint config.

3. **Use `tokenIdHash` from `@sluice/crypto` at both write sites.** `serviceTokens` is written at token creation and `revocations` at revocation. Neither exists yet, so the construction is still free to choose. The moment the first row is written it is frozen, and a mismatch is unfixable without re-deriving from plaintext token ids the server does not have. **Required test: insert a service token and a revocation through the real code path and assert the join returns the notice.** Every fixture that seeds both hash values by hand passes regardless, which is the whole trap.

4. **Decide how `handshakeNonces.signatureHash` is computed.** It is a column with an index and a repo function that takes it pre-computed, and **nothing anywhere produces it**. Identical shape to the token id hash. It is server-only so drift is less likely, but it is the replay cache for the handshake and "the server hashes it consistently" is currently an assumption with no code behind it.

## Requirements on the SDK transport task, from building the decision core

`packages/sdk` now holds a pure decision core: events in, decisions out, no network, no clock of its own. 93 tests, and the property that matters is enumerated rather than sampled. 599,184 benign sequences across 4,108,704 events produce no shutdown, and 1,110 hostile sequences with real Ed25519 verification produce no shutdown and never move the epoch floor.

The transport is a thin shell around it, and the shell is where the kill switch can still be broken. These are required, not advisory.

- **The core cannot enforce its own deadline.** It is event-driven, so a shell that stops sending ticks leaves a revoked process alive forever. The shell owns an independent timer and must tick at least every `MAX_CLOCK_STEP_MS`.
- **The shell must not wait for `onRevoke` before ticking.** A shell that does hands a customer handler the power to cancel a revocation by hanging, which is the drain bound defeated by a `finally` block that never returns.
- **The shell must not give customer code anything that can cancel its own timer.** Passing the handler an `AbortController` or a cancellation token feels like good hygiene and quietly hands back exactly the power the drain bound exists to take away. This is the one a shell author is most likely to get wrong, because it looks like a courtesy.
- **The shell persists and restores the epoch floor.** `initialEpochFloor` is a required option with an explicit `NO_PERSISTED_FLOOR` sentinel, so a shell that answers the sentinel on every start has chosen to reopen a replay window at every restart rather than stumbled into one.

**The required test for this task: exit happens with a hanging `onRevoke`, zero socket traffic, and no shell-created timer reachable by customer code.** All three, in one test. The hang and the silence are the obvious halves; the third is the one that ships broken.

**On writing that task's tests:** pick the hostile alphabet before writing the shell, not after. The decision core's own enumeration was complete over the space it was given and blind to the threat, because the alphabet encoded an assumption about the attack rather than testing it. A 1,110-sequence enumeration missed an off-by-one that re-admitted a replay of the most recent genuine notice, which is the one an attacker is likeliest to hold. The safeguard was never the sequence count; it was choosing the right symbol.

## BLOCKING GAP: there is no session layer

Found while building Tasks 8 and 9, and it is a defect in this plan rather than in that work.

`callerId` is a mutation argument. Any client that can reach the deployment can pass any user id and be treated as that user. Every authorisation test in `orgs.test.ts`, `projects.test.ts`, `environments.test.ts` and `secrets.test.ts` proves the authorisation *logic* is correct and proves nothing about the *boundary*: they show a non-member is refused, not that an attacker cannot simply claim to be a member.

Task 7 returns wrapped key material and nothing a later request can present as proof of identity. Task 10 introduces bearer credentials for service tokens only, never for people. So no task in this plan creates a dashboard session, which means the hierarchy is currently unauthenticated in practice.

**This must be built before the deployment is exposed to anything, and before any dashboard work starts.** A dashboard written against `callerId` as an argument would need every call site changed afterwards.

The cost of the gap is contained deliberately: the identity is resolved in exactly one place, `callerArg` and `resolveCaller` in `convex/lib/authz.ts`. Moving to `ctx.auth` is one edit there rather than fifteen across the handlers.

### The session task, to be written properly before execution

- Decide the mechanism. Convex has first-class auth integration, and a custom session table is the alternative. Custom sessions mean owning rotation, expiry and revocation, which is real work on a security product.
- Whatever it is, it must produce a server-verified identity reachable through `ctx.auth`, not a claim the client supplies.
- `callerArg` is deleted in the same change, so the old path cannot survive anywhere.
- The authorisation tests get a companion that asserts an unauthenticated call is refused, which is the test none of them can express today.

## Also outstanding, found in the same review

- **There is no mutation that adds a member to an org, so there is no way to issue a second revocation grant.** The schema moved to a grants table precisely so more than one person can sign a revocation notice. Structurally that is fixed; operationally the wedge is still bus-factor one until invitations ship. Whoever builds invitations must ship grant issuance in the same change, or the schema change bought nothing.
- **Reads are not audited and on Convex they cannot be.** Queries cannot write, so `listSecrets` and `getSecret` leave no trace. An insider with a valid session can drain every ciphertext in an org and the audit log shows nothing. Fixing it means making the read path a mutation or an action, with a real caching cost. Decide it deliberately rather than discover it.
- **`orgMembers.role` is stored and never enforced.** A `member` can currently create projects, create environments and delete secrets exactly like an owner. A field that implies a permission model which does not exist is worse than no field. The check belongs in `convex/lib/authz.ts`.
- **The AAD rule belongs in `@sluice/crypto`, not in `convex/lib/aad.ts`.** The SDK cannot import from `convex/`, so it will hand-copy the literal `"sluice/secret/v1|"`, and one character of drift produces ciphertext nobody can read with no error until someone tries. This is the same failure class the token-id hashing amendment already calls out. Both sides already depend on the crypto package. Move it there.

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
