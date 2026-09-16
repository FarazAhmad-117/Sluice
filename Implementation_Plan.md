# Sluice — Implementation Plan

*Zero-knowledge environment variable delivery, built on Convex.*
*"Sluice" is a working name. Verify trademark (USPTO/EUIPO), npm, and domain before committing.*

---

## 1. What this is

A platform where teams store environment variables in a dashboard, organise them by app and environment, and have them delivered directly into running processes by a stack-specific SDK. The server never sees a plaintext secret. Admins can revoke a service token and every running process holding it dies within milliseconds.

The differentiator is not storage. Doppler, Infisical, EnvKey, 1Password and HashiCorp Vault all store secrets. The differentiator is **instant, cryptographically authenticated revocation of live processes**, which Convex's reactive subscriptions make natural and which every polling-based competitor does badly.

Lead with that. Not with "we store your secrets securely."

---

## 2. Threat model (write this down and publish it)

A zero-knowledge claim is meaningless without stating who you defend against. Be explicit in your docs, because security people will ask and vague answers destroy credibility.

### Defended against

| Adversary | Mitigation |
|---|---|
| Database dump / backup theft | Ciphertext only; no key material in DB |
| Malicious or compelled operator (you) | No decryption key ever reaches the server |
| Convex platform compromise | Same as above |
| Network attacker (TLS stripped) | Payloads are already encrypted end-to-end |
| Stolen service token | Instantly revocable; scoped to one env |
| Malicious server pushing fake revocations | Revocation notices are signed by customer-held keys |
| Insider at a customer org | RBAC + audit log + per-environment key separation |

### NOT defended against (say so out loud)

- **Compromised client device.** If an admin's laptop is owned, their keys are owned.
- **Malicious JavaScript served to the web dashboard.** This is the unsolved problem of browser-based E2EE. A compromised server can serve a dashboard build that exfiltrates the master unlock key. Mitigations below in §10.
- **A workload that already has the secret.** Once a process decrypts a value, that process can leak it. You control delivery, not use.
- **Your customer choosing weak passwords.** Enforce a minimum and offer SSO-backed key wrapping later.

---

## 3. Cryptographic architecture

### 3.1 Human key hierarchy

```
Password
  └─ Argon2id(password, salt=userId, m=64MiB, t=3, p=4)
       └─ MUK  (Master Unlock Key, 256-bit, NEVER transmitted)
            └─ wraps: userPrivateKey   (X25519, AES-256-GCM)
            └─ wraps: userSigningKey   (Ed25519, AES-256-GCM)

Server stores: userPublicKey, userVerifyKey, wrapped blobs, authVerifier
```

The `authVerifier` is a **separate** derivation, not the MUK. Use OPAQUE or SRP-6a so the password never crosses the wire at all. If that's too much for v1, use `Argon2id(password, salt=userId, info="auth")` sent over TLS and hashed again server-side with a per-deployment pepper. Ship OPAQUE by v2.

### 3.2 Project keys

```
PDK (Project Data Key) — random 256-bit AES-GCM key, one per (project, environment)
  └─ wrapped to each member: sealed_box(PDK, memberPublicKey)   [X25519 + XChaCha20-Poly1305]
  └─ wrapped to each service token: AES-256-GCM(PDK, tokenUnwrapKey)
```

Per-environment PDKs, not per-project. This is what makes "a developer can read `dev` but not `prod`" a *cryptographic* guarantee rather than a server-side permission check that you could bypass.

Adding a member is done client-side by an existing member: fetch the new member's public key, verify its fingerprint, re-wrap the PDK, upload. The server just moves blobs.

### 3.3 Secret storage

Every value: `AES-256-GCM(value, PDK)` with a fresh 96-bit nonce. Store `{ciphertext, nonce, tag, pdkVersion, createdAt}`. Never reuse a nonce under the same key — use a CSPRNG per write and track a counter as a safety net.

Encrypt the **key names** too, or at least offer it as a toggle. `STRIPE_LIVE_SECRET_KEY` as a plaintext column tells an attacker with DB access exactly which ciphertext to prioritise, and tells you things you claimed not to know.

### 3.4 Machine identity — the hard part

This is where most "zero-knowledge" secrets managers quietly stop being zero-knowledge. The naive design sends the whole token to the server, which means the server could derive the unwrap key on every request. Don't do that.

**Token minting (browser, at creation time):**

```
tokenSecret = 32 random bytes                      // client only, shown ONCE
tokenId     = 16 random bytes

authSeed  = HKDF-SHA256(tokenSecret, salt=tokenId, info="sluice/auth/v1",   len=32)
unwrapKey = HKDF-SHA256(tokenSecret, salt=tokenId, info="sluice/unwrap/v1", len=32)

signingKeypair = Ed25519_from_seed(authSeed)

Upload to server:
  tokenId
  signingKeypair.publicKey            // public only
  wrappedPDK = AES-256-GCM(PDK, unwrapKey)
  scope = { projectId, environmentId, expiresAt }
  orgRevocationPublicKey

Token string shown to user:
  slc_prod_<base58(tokenId)>.<base58(tokenSecret)>
```

The server receives a public key and a blob it cannot open. `unwrapKey` is never transmitted and is not derivable from anything the server holds.

**Runtime handshake:**

1. SDK sends `tokenId` + `unixSeconds` + `Ed25519_sign(tokenId || unixSeconds)` to an `httpAction`.
2. Server verifies against the stored public key, rejects timestamps outside ±60s, and stores the signature hash briefly for replay protection.
3. Server issues a short-lived JWT (5 min) and logs an audit event.
4. SDK calls `client.setAuth(jwt)` and subscribes to the bundle query.
5. Server streams `{wrappedPDK, secrets[], epoch, revocationNotice?}`.
6. SDK derives `unwrapKey` locally, unwraps the PDK, decrypts each value in memory.

The server has now delivered production secrets to a machine while being cryptographically incapable of reading them. That is the claim you can make honestly, and very few competitors can.

### 3.5 Account recovery — do not skip this

Zero-knowledge means a forgotten password is permanent data loss. You need both:

- **Recovery kit**: a 128-bit code generated at signup, rendered as a printable PDF, which independently wraps the MUK. Users who lose it and their password lose the account. Say so in bold at signup.
- **Org break-glass**: Shamir's Secret Sharing over the org key, 3-of-5 among admins. Without this, one departing employee can lock out an entire company, and that single support ticket will cost you more than the feature costs to build.

---

## 4. The kill switch

### 4.1 Rotation vs revocation — different events

| Event | Meaning | Default behaviour |
|---|---|---|
| **Value rotation** | A secret's value changed | Push new value, fire `onChange`, app hot-swaps. **No crash.** |
| **Token revocation** | This machine identity is no longer trusted | Verify signature, drain, `process.exit(1)` |
| **Epoch bump** | PDK re-keyed (member removed) | Re-fetch bundle with new wrapped PDK |

If rotating a value crashes production, nobody rotates anything, and your product's entire premise collapses. Keep these separate.

### 4.2 Signed revocation notices

When an admin revokes a token:

1. The browser signs `{tokenId, epoch, revokedAt, reason}` with the **org revocation private key**, unwrapped from that admin's MUK.
2. The signed notice is uploaded and stored.
3. Convex pushes it down every live subscription for that token.
4. The SDK verifies the signature against the org public key embedded in its token bundle.
5. Only on a **valid signature** does the SDK enter shutdown.

This means neither you, nor a Convex compromise, nor a network attacker can mass-kill customer fleets. It is the single strongest argument in your security whitepaper. It also means automated revocation needs a dedicated automation identity holding its own signing key — design that in, don't bolt it on.

### 4.3 The availability trap

**Never treat connection loss as revocation.** Defaults:

```
Signed revocation received     → drain (default 5s), then exit(1)
WebSocket drops                → keep last-known-good, reconnect with backoff,
                                 emit metric + log WARN, DO NOT exit
Boot with no cache, no network → fail to start (nothing to run with anyway)
Boot with disk cache, no net   → start in degraded mode, alarm loudly
maxOfflineDuration             → default: unlimited. Opt-in only.
```

Make `onRevoke` a user-supplied handler so a customer can drain a connection pool, flush telemetry, and deregister from a load balancer before exiting. Default it to a clean exit, but let people own it.

---

## 5. Convex data model

```ts
// convex/schema.ts
users:          { email, authVerifier, publicKey, verifyKey,
                  wrappedPrivateKey, wrappedSigningKey, recoveryBlob }
orgs:           { name, slug, revocationPublicKey, wrappedRevocationKey }
orgMembers:     { orgId, userId, role }                    // .index(["orgId","userId"])
projects:       { orgId, name, slug }
environments:   { projectId, name, pdkVersion, epoch }
pdkGrants:      { environmentId, granteeType, granteeId, wrappedPDK, nonce }
secrets:        { environmentId, nameCiphertext, valueCiphertext,
                  nonce, pdkVersion, version, deletedAt }
serviceTokens:  { environmentId, tokenIdHash, publicKey, wrappedPDK,
                  scope, epoch, status, lastSeenAt, expiresAt }
revocations:    { tokenId, epoch, signature, signedBy, revokedAt, reason }
auditLog:       { orgId, actorType, actorId, action, targetId, ip, ts, metadata }
```

Store `tokenIdHash` rather than `tokenId` so a DB reader can't enumerate valid identifiers.

### Runtime split — this is forced on you

Verified constraints:

- The default Convex runtime exposes `crypto`, `CryptoKey` and `SubtleCrypto`, but coverage is incomplete. Real-world report: `crypto.subtle.deriveBits` for ECDH P-256 is unimplemented, with `"use node"` as the only workaround.
- Files carrying the `"use node"` directive **cannot contain any other Convex functions**. Your crypto module set will be physically separate from your queries and mutations whether you like it or not.
- Actions are not automatically retried, because they may have side effects. Every sync, rotation and webhook job needs its own idempotency key.
- Actions time out at 10 minutes; Node runtime gets 512MB, default runtime 64MB.

Layout:

```
convex/
  schema.ts
  queries/        # default runtime — bundle subscription, listing, RBAC reads
  mutations/      # default runtime — blob writes, epoch bumps, audit appends
  http.ts         # httpAction — token handshake, JWT issuance
  node/
    verify.ts     # "use node" — Ed25519 verification, Argon2id, OPAQUE
    jobs.ts       # "use node" — expiry sweeps, notifications
```

Server-side crypto here is only **verification** — signatures, password verifiers. The server performs no decryption, which is the whole point.

### Your own bootstrap secrets

Convex environment variables are listed in the dashboard under Deployment Settings, and an admin key grants complete control over a deployment while being an irrevocable secret baked in at creation. So: your JWT signing key and any pepper go in Convex env vars only because they are *not* secret-decrypting material. Nothing that could ever open customer data goes there. Document this distinction publicly.

---

## 6. SDK strategy

`ConvexClient` from `convex/browser` provides query subscriptions in Node.js and any JavaScript environment supporting WebSockets, and works identically in Bun. So JS/TS is a first-class citizen with almost no work.

Everything else is a problem. There is no official reactive Convex client for Python, Go, Rust, Ruby, Java or PHP. Community clients exist for Dart but you cannot build a product on that.

**Recommendation: build one hardened agent, then thin shims.**

```
sluice-agent (single static Go or Node binary)
  ├─ holds the WebSocket subscription
  ├─ performs all crypto
  ├─ serves plaintext over a local Unix domain socket (0600, owner-only)
  └─ sends SIGTERM/SIGKILL to the supervised child on signed revocation

Language shims (~200 LOC each): read from the socket at boot, subscribe to change events.
```

This is EnvKey's model and it's the right one. It gives you one codebase to audit instead of nine, and non-JS stacks get the same millisecond revocation. Ship shims in order: Node, Python, Go, Docker entrypoint, Kubernetes operator.

Also ship `sluice run -- npm start`, which injects and supervises. That's the command people will actually use daily and it's your best onboarding surface.

---

## 7. What zero-knowledge costs you

Be clear-eyed. Choosing full ZK means these are **permanently unbuildable server-side**:

- Secret scanning / leak detection on values
- Automatic rotation of third-party credentials (AWS, Stripe, Postgres) — server can't read the old one to call the provider's API
- Push sync to Vercel, Netlify, GitHub Actions, AWS Parameter Store
- Server-side search across secret values
- Rendering a secret in an email, a webhook payload, or a support tool
- Password reset without a recovery kit

Infisical faced exactly this fork and moved to a layered key hierarchy where a root encryption key plus storage-backend data are both required, precisely so they could ship integrations. You're choosing the harder path.

**Mitigation that preserves the guarantee:** build these as *client-side* features. Push sync runs in the CLI or the agent on the customer's own infrastructure, where plaintext already legitimately exists. It's more work and it's a worse UX, but the claim survives. Make this an explicit design principle: **anything requiring plaintext runs on the customer's machine, never yours.**

---

## 8. Build phases

### Phase 0 — Crypto core (2–3 weeks)
Standalone TypeScript package, zero Convex dependency. Key derivation, wrapping, token minting, sealed boxes, signature verification. Full test vectors. Published independently so it can be audited on its own.

**Do this first and separately.** If the crypto is wrong, everything built on top is wasted. A reviewable 800-line library is worth ten times a correct-looking 40,000-line app.

### Phase 1 — Core platform (4–6 weeks)
Convex schema, auth with OPAQUE or SRP, orgs, projects, environments, member invites with key re-wrapping and fingerprint verification, dashboard CRUD, recovery kit generation.

### Phase 2 — Delivery + kill switch (3–4 weeks)
Service token minting, handshake `httpAction`, bundle subscription query, Node SDK, signed revocation notices, `onRevoke` handling, the full availability-trap behaviour matrix. **Write chaos tests here**: kill the WebSocket mid-flight, replay old signatures, forge a revocation, revoke during a deploy.

### Phase 3 — Agent + CLI (3–4 weeks)
`sluice run`, the agent binary, Unix socket protocol, Python and Go shims, Docker entrypoint.

### Phase 4 — Operational maturity (4 weeks)
Audit log with tamper-evident hash chain, RBAC, secret versioning and rollback, org break-glass via Shamir, per-token rate limiting and brute-force lockout.

### Phase 5 — Open source launch (3 weeks)
Licence split, `SECURITY.md`, threat model doc, self-hosting guide, reproducible builds, npm provenance attestation, bug bounty.

### Phase 6 — Commercial tier
SSO/SCIM, audit retention, advanced RBAC, on-prem support, compliance reports.

---

## 9. Open source strategy

**Licence:** Apache-2.0 for core, `ee/` directory under a commercial licence. This is the Infisical and GitLab pattern and buyers understand it. Avoid AGPL — enterprise legal teams reflexively block it, and you're selling to enterprises.

Use a DCO rather than a CLA. A CLA on a security project reads as a prelude to a relicense and costs you contributor goodwill.

**The Convex self-host tax.** Convex self-hosting works via docker-compose with an admin key generated by a script, but it's meaningfully more friction than `docker compose up` on a Postgres app. For a secrets manager — where self-hosting is the *primary* reason people choose open source — this is a real adoption cost.

Two options, decide before Phase 1:

1. **Accept it.** Ship a polished one-command docker-compose bundling the Convex backend. Lean on Convex's reactivity as the thing that justifies the friction. Faster to build.
2. **Abstract the data layer.** Keep all Convex calls behind a repository interface so a Postgres + WebSocket adapter is possible later. Costs perhaps 20% more effort and you give up some Convex ergonomics, but you don't get trapped.

Given "open source for everyone," option 2 is probably correct. Making that choice in month nine costs ten times what it costs in week one.

---

## 10. The browser problem

Your biggest honest weakness: a compromised server can serve malicious dashboard JavaScript that steals the MUK. Every web-based E2EE product has this and none has fully solved it.

Do this:
- Strict CSP, Subresource Integrity on all assets
- Reproducible builds with published hashes
- A code transparency log (append-only, third-party-witnessed) so tampering is detectable after the fact
- **Make the CLI the trust anchor.** Published to npm with provenance attestation, version-pinnable, auditable. Document that security-critical operations — minting production tokens, break-glass recovery — should be done via CLI.
- State the limitation plainly in your threat model. Security buyers respect stated limitations far more than unqualified claims, and a single overclaim that gets disproven ends the product's credibility permanently.

---

## 11. Compliance

HIPAA is a regulatory framework for protected health information, not a security tier — "more secure than HIPAA" isn't a claim that parses to a buyer. What they actually ask for:

| Target | When | Cost |
|---|---|---|
| Third-party crypto review | After Phase 0 | $8–20k |
| Full pen test | After Phase 3 | $15–40k |
| SOC 2 Type I | Month 6 | $10–20k + tooling |
| SOC 2 Type II | Month 12+ (needs 6–12mo observation) | $25–50k |
| ISO 27001 | Year 2 | $30–60k |
| HIPAA BAA | Only if a customer stores PHI | Legal review |

Zero-knowledge architecture genuinely helps here. Many SOC 2 controls around data handling become trivially satisfiable when you hold no plaintext. Say this to auditors early.

---

## 12. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Fail-closed triggered by an outage, killing customer fleets | **Critical** | Signature-gated exit; connection loss never exits (§4.3) |
| Crypto implementation flaw | **Critical** | Phase 0 isolation + external review before launch |
| Malicious dashboard bundle | High | CLI as trust anchor, SRI, transparency log |
| Convex self-host friction kills OSS adoption | High | Decide §9 option 1 vs 2 in week one |
| No reactive client for non-JS stacks | High | Agent + shim architecture (§6) |
| Nonce reuse under a PDK | High | CSPRNG per write + counter safety net + fuzz tests |
| Users lose recovery kits, demand your help | Medium | Break-glass Shamir + very explicit signup UX |
| Crowded market (Doppler, Infisical, Vault, EnvKey) | Medium | Position on instant signed revocation, not storage |
| Convex vendor lock-in | Medium | Repository abstraction if §9 option 2 |

---

## 13. Decisions needed before Phase 1

1. **Data layer abstraction — yes or no?** (§9) Cheapest to decide now, most expensive to decide later.
2. **OPAQUE in v1, or Argon2-over-TLS with OPAQUE in v2?** OPAQUE is meaningfully harder and delays Phase 1 by ~2 weeks.
3. **Are secret *names* encrypted?** Better security, worse UX and no server-side search or sorting.
4. **Agent in Go or Node?** Go gives a static binary and better distribution; Node lets you reuse the Phase 0 crypto core directly.
5. **Do you need the multiplayer/team features at launch**, or is a single-user-per-org v1 enough to validate the revocation story?

---

## 14. Verified sources

- Convex default runtime crypto coverage and the `deriveBits` gap: PushForge issue #62
- `"use node"` cannot coexist with other Convex functions; action timeouts and memory limits: Convex docs, Actions
- Actions are not auto-retried: Convex docs, Actions
- `ConvexClient` subscriptions in Node.js and Bun: Convex docs, JavaScript / Bun clients
- Convex env vars visible in Deployment Settings; admin keys irrevocable and grant full control: Convex docs, Environment Variables & Deploy Key Types
- Infisical's layered key hierarchy requiring both root key and storage backend: Infisical security internals
- Convex self-hosting via docker-compose and `generate_admin_key.sh`: Convex Stack, self-hosting guide