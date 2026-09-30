# Sluice architecture

Status: approved 2026-09-30. Supersedes the product-shape assumptions in the
2026-09-16 foundation plan and the 2026-09-17 backend plan where they conflict.
Those plans remain the record of what was built and why.

## 1. The product in one paragraph

Sluice replaces the `.env` file. A developer runs `sluice run -- <command>` in
place of `<command>`, and the process starts with its secrets as ordinary
environment variables. Two properties set it apart. The server stores only
ciphertext and never holds a key that opens it. And revoking a token shuts down
every process already running with it, within seconds, because each process
verifies a revocation notice signed by a key the customer holds. The CLI works
with any language. The dashboard, which is fully usable from a phone, manages
secrets, teams and the audit log.

## 2. Components

```
                        ┌──────────────────────────────────────┐
                        │  CELL: one Convex deployment         │
                        │  packages/backend                    │
                        │  ciphertext, locked keys, public     │
                        │  keys, signed notices, audit log     │
                        └────────┬──────────────────┬──────────┘
                     websocket   │                  │  POST /handshake
                     (JS client) │                  │  + websocket (Rust client)
   ┌─────────────────────────────┴─────┐   ┌────────┴──────────────────────────────┐
   │  DASHBOARD   apps/dashboard       │   │  CLI   apps/cli   (Rust)              │
   │  TypeScript, Vite, PWA → Vercel   │   │  one binary per OS                    │
   │  secrets · team · audit · revoke  │   │  login · recover · import · token ·   │
   │                                   │   │  revoke · run                         │
   └───────────────────────────────────┘   └────────────────────┬──────────────────┘
                                                                │ starts · watches · kills
                                                        ┌───────┴────────┐
                                                        │  CUSTOMER      │
                                                        │  PROCESS       │
                                                        └────────────────┘
   MARKETING  apps/web (Next.js → Vercel)      NODE SDK  packages/sdk-node (npm)
   CRYPTO     packages/crypto: the reference implementation
```

| Component | Language | Deploys to | Role |
|---|---|---|---|
| `apps/web` | TypeScript, Next.js | Vercel | marketing site |
| `apps/dashboard` | TypeScript, Vite, React, PWA | Vercel | the product UI, mobile first |
| `apps/cli` | Rust | GitHub Releases, brew, scoop, winget, curl, npm, Docker | process wrapper and admin commands |
| `packages/backend` | TypeScript, Convex | Convex cloud, later self-hosted | storage, auth, delivery, push |
| `packages/crypto` | TypeScript | imported | reference crypto; generates test vectors |
| `packages/sdk-node` | TypeScript | npm | in-process revocation handling, serverless delivery |
| `packages/cli-npm` | generated | npm | installs the Rust binary for Node users |
| `spec/` | JSON, Markdown | none | the wire protocol and test vectors |

### Why Rust for the CLI

Revocation reaches a running process because Convex pushes a query result down
a websocket the moment a revocation row lands. Convex ships first-party
websocket clients for TypeScript, Python and Rust. It has none for Go, and its
HTTP API is not reactive. A Go CLI would have to poll, which multiplies function
calls by every running process and makes "instant" depend on a poll interval.
Rust keeps the push on a client Convex maintains, and produces a small static
binary.

Go was chosen first and withdrawn for this reason. TypeScript compiled with Bun
was rejected: it ships a 60 to 100 MB binary and inherits Node's Windows
process-spawning problems.

### Why the TypeScript crypto stays the reference

Two languages implementing one protocol will drift. `packages/crypto` writes
test vectors to `spec/vectors/`; the Rust crypto must reproduce every one byte
for byte, and CI fails otherwise. Every primitive in use (Argon2id, Ed25519,
X25519, SHA-256, HKDF, AES-GCM) has a mature Rust implementation.

## 3. Folder structure

```
sluice/
├── apps/
│   ├── web/                    Next.js marketing site
│   ├── dashboard/              Vite + React PWA          (renamed from admin)
│   └── cli/                    Rust                      (replaces packages/cli)
│       ├── src/
│       │   ├── main.rs         entry only
│       │   ├── commands/       login · recover · import · token · revoke · run
│       │   ├── crypto/         Rust port, tested against spec/vectors
│       │   ├── api/            Convex Rust client: handshake + subscription
│       │   ├── runner/         spawn · signal forwarding · reaping · kill · PATHEXT
│       │   ├── keystore/       OS keychain
│       │   └── config/
│       ├── tests/
│       ├── Cargo.toml          includes the `dist` release config
│       └── package.json        shim so `turbo test` runs `cargo test`
├── packages/
│   ├── backend/                Convex schema, functions, tests (moved from convex/)
│   ├── crypto/
│   ├── sdk-node/               (renamed from sdk)
│   └── cli-npm/
├── spec/
│   ├── protocol.md
│   └── vectors/
├── docs/
│   ├── architecture/           overview and decision records
│   └── plans/
└── .github/workflows/          ci.yml · release-cli.yml
```

Rust crypto stays a module inside the CLI until a second consumer, such as a
Python SDK, needs it as a crate. A shared `ui` package waits for real
duplication between web and dashboard.

## 4. Keys

| Key | Made from | Lives | Server holds |
|---|---|---|---|
| Master unlock key | password, Argon2id | device memory; CLI keychain for 15 min | nothing |
| Recovery copy of master key | locked by the recovery kit | server | a blob it cannot open |
| Environment data key | random, versioned | locked once per member and per token | locked blobs |
| Secret values | AES-GCM under the environment key, bound to the environment | server | ciphertext |
| Service token | random, split by HKDF into auth and unwrap halves | customer's CI or server | public half of auth |
| Org root key | random, Ed25519 | offline, in the org recovery kit | public key |
| Org revocation key | random, Ed25519, certified by the root | locked once per admin; used by dashboard and CLI | public key and certificate |

## 5. Flows

**Setup.** `sluice login`, `sluice import .env`, `sluice token create --env prod
--name github-deploy --expires 90d`. The token is one string: `slc_…`. It
carries the cell hostname, the pinned org root public key and the token secret.
It replaces the four environment variables the current CLI requires.

**Run.** `SLUICE_TOKEN=slc_… sluice run -- <command>`.

1. The CLI signs a challenge with the auth half. `POST /handshake` checks the
   signature, rejects replays and refuses revoked or expired tokens.
2. The server returns a short-lived bundle pass.
3. The CLI subscribes to `getBundle`, receives ciphertext and decrypts it with
   the unwrap half, which never leaves the machine.
4. It starts the child with the secrets in its environment.
5. It renews the pass before expiry, on a timer independent of the
   subscription, and holds the subscription for the life of the child.

**Revoke.** From the dashboard or `sluice revoke`.

1. The client signs a notice with the org revocation key.
2. Convex stores it; the row change re-runs `getBundle` for every subscriber.
3. Each CLI verifies the revocation key's certificate against its pinned root,
   then the notice against the revocation key.
4. Valid: shut the child down. Invalid: ignore and log.

**Recover.** `sluice recover`, or the dashboard, with the recovery kit.
Alternatively another admin re-grants keys to the user's new account.

## 6. Kill-switch correctness

### A. A revocation must reach a process whose pass expired

A process offline when a token is revoked, whose pass expires before it
reconnects, today hears only an unsigned "refused" from both `getBundle` and the
handshake. It cannot treat that as revocation, because a compromised server
could send it to anyone, so it runs on forever.

Decision:

1. `getBundle` accepts an authentic but expired pass and answers it with
   revocation notices only, never secrets. The notice is signed and reveals
   nothing beyond the revocation itself.
2. An optional per-environment **offline allowance** (section 6.B) fails closed
   for teams that prefer an outage to a revoked process running.
3. The Rust CLI ships a test: revoke while offline, let the pass expire,
   reconnect, observe the child exit.

### B. Offline allowance and the startup cache

Today a process cannot start while Convex is unreachable. A running process is
unaffected. Many workloads start on fresh disks, so a cache helps only
long-lived hosts.

Decision: one per-environment setting, **offline allowance**, meaning how long a
process may go without confirming its token with Sluice.

| Offline allowance | Running process loses contact | Start while Convex is down |
|---|---|---|
| not set (default) | keeps running | refuses |
| set, e.g. 1 h | shuts down after 1 h | starts from cache younger than 1 h |

The cache stores the server's response verbatim: ciphertext only, opened by the
token. Starting from cache logs its age, and the CLI connects as soon as it can,
where fix A delivers any pending notice.

### C. Root key over revocation key

The CLI pins the org key in its own configuration and never accepts it from the
server; a server that could supply it could forge revocations. That stays. What
changes is which key is pinned.

Decision: the TUF pattern. Processes pin the org **root** public key. The root,
kept offline, signs a certificate for the day-to-day **revocation key**. The
server may deliver certificates because it cannot forge them. Processes persist
the newest certificate version they have seen, as they persist the revocation
epoch floor, so an old certificate cannot be replayed.

| Event | Response |
|---|---|
| planned rotation | root signs a new certificate; processes switch in seconds |
| revocation key stolen or lost | same |
| root key stolen or lost | redeploy with a new pinned root; the one case needing config changes |

The pinned value becomes the root now, before users exist, so the rotation
feature can ship later without anyone changing their configuration.

A stolen revocation key alone cannot deliver a notice: that needs an admin
session or a compromised server. And a forged notice can stop processes but
cannot reveal a secret.

## 7. Unlocking and MFA

**Signed in** means holding a session; the server knows who you are. **Unlocked**
means holding the master key; the device can decrypt.

| Surface | Decision |
|---|---|
| Session | 12 h absolute, as today. Stored so it survives a PWA restart; `sessionStorage` does not. |
| Dashboard auto-lock | forget the master key after 15 min idle; orgs may shorten it |
| Fast unlock | passkey with the WebAuthn PRF extension unlocks the master key, only on a device already signed in with the password |
| CLI | session in the OS keychain; master key cached 15 min after last use. `sluice run` never needs it. |
| MFA | passkeys first; TOTP fallback; backup codes in the emergency kit. No SMS, no email codes. Orgs may require it. |

MFA protects the login. It cannot recover a key, because the server holds the
secret behind a TOTP code and could otherwise unlock the key itself.

## 8. Recovery

| Mechanism | Covers |
|---|---|
| Recovery kit, mandatory at signup; signup ends only after the user confirms it | a user who forgets the password |
| Multi-admin grants; the dashboard warns while an org has one admin | a user who loses password and kit |
| Org recovery kit holding the root private key | root key custody |
| Passkey unlock, later | lost device, when passkeys sync |

If every admin loses every password and kit, the data is unrecoverable, by the
operator included. Signup and `SECURITY.md` say so.

## 9. Teams

The server cannot grant access; access means holding a key, and only an existing
member's device can lock a key to a newcomer. So invites take two steps: the
newcomer accepts, then an admin's dashboard confirms them, automatically on its
next load.

**Invite links carry a secret after `#`.** Browsers never send the fragment to a
server. The newcomer's device uses it to vouch for its public key, and the
admin's device checks the vouch before locking anything to it. This defeats a
server that substitutes its own public key. Admins share links through their
own channels; no email service is needed. Future email is notification only.

| | Owner | Admin | Member |
|---|---|---|---|
| Read and edit secrets | all environments | all environments | granted environments only |
| Create projects and environments | yes | yes | no |
| Create tokens | yes | yes | in granted environments |
| Revoke tokens | yes | yes | no |
| Invite, confirm, remove, change roles | yes | yes | no |
| Org settings | yes | yes | no |
| Delete org; hold the root key | yes | no | no |

An org keeps at least one owner. Per-environment access is enforced by
cryptography: a member without a grant holds no key that opens the environment.

**Removing a member** deletes their grants, rotates the affected environment
keys on an admin's device (`pdkVersion` exists for this), and lists the secrets
they could read so the team can rotate them at the source.

## 10. Audit log

Existing events: `org.create`, `project.create`, `environment.create`,
`secret.create`, `secret.update`, `secret.delete`, `token.create`,
`token.handshake`, `token.revoke`.

To add: sign-in, failed sign-in, sign-out, MFA and passkey changes, recovery
use; invite, accept, confirm, role change, removal; key rotations and root use;
secret fetches per environment; settings changes. The server can record that a
user fetched an environment's ciphertext, not which secret they viewed.

**Tamper evidence.** Each entry includes the hash of its predecessor. Each
admin's device remembers the latest head it has seen and warns if the log no
longer extends it. This detects a server that edits or deletes history; it does
not prevent it.

Entries reference secrets by ID, never by name. Owners and admins read the log.
Default retention is 90 days, pruned nightly. CSV and JSON export ship first;
SIEM streaming comes later. A token used from a new IP, or a burst of failed
sign-ins, raises a PWA push notification with a Revoke action.

## 11. CI and platforms

| Platform | Integration | Kill switch |
|---|---|---|
| GitHub Actions | `setup-sluice` action installs the binary and registers secrets with log masking; `sluice run -- npm test` | full |
| Docker, Kubernetes | `COPY --from` the CLI image; `ENTRYPOINT ["sluice","run","--"]` | full |
| Railway, Render, Fly, Heroku, VMs | set `SLUICE_TOKEN`; change the start command | full |
| Vercel build | `sluice run -- next build` | build time only |
| Serverless functions | Node SDK fetches at cold start | partial: warm instances keep secrets until recycled |

As PID 1 in a container, the runner forwards signals and reaps children, or
`docker stop` waits out its timeout.

Token hygiene: one token per pipeline or target; expiry at creation, with a
dashboard warning; one environment per token. Later, a token may be bound to a
GitHub repository through OIDC as an extra check. OIDC cannot replace the
token, since the server would then have to release the decryption key.

## 12. Hosting and business

- Development runs on the Convex free plan. Production moves to self-hosted
  Convex.
- The crypto, CLI, SDK and backend core stay Apache-2.0 permanently. Enterprise
  extras such as SSO and SIEM streaming may later live in a commercially
  licensed `ee/` directory.
- No payment before a third-party crypto audit.
- The hosted beta enforces per-org limits, initially 3 members, 5 environments
  and 25 concurrent processes.
- Self-hosting is a documented path.
- Needed before public signups: terms of service, a privacy policy, rate
  limits, and a live status page.

Each running process holds one websocket. Convex cloud caps concurrent
connections per deployment at 1,000 on the free plan and 10,000 on
Professional. Connections, not function calls, are the binding constraint; at a
renewal every 2.5 minutes, 10,000 processes cost about 170M calls a month.

## 13. Scaling: cells

A **cell** is one Convex deployment. Every org lives in exactly one cell. A small
**directory** holds users, sessions and the org-to-cell map.

- Running processes never touch the directory. The token names the org's
  hostname, `<org>.api.sluice.dev`, a DNS record pointing at its cell. Moving an
  org means copying its rows and flipping that record.
- Trust comes from the pinned root key, not the hostname, so rerouting weakens
  nothing.
- Moving an org copies only ciphertext. The destination cell needs no more
  trust than the source.

Rules that apply from today, with one cell:

1. **Stable IDs.** Every org, user and environment gets a client-generated
   permanent ID. Encryption bindings and external references use it, never a
   Convex document ID. Today the secret binding uses the Convex environment ID
   and the key-grant binding uses the Convex user ID; both change on migration,
   and no server could re-encrypt the result. Protocol bindings move to `v2`.
2. Every org-owned row carries `orgId` directly.
3. No query spans two orgs, except in the directory.
4. Nothing long-lived contains a `*.convex.cloud` URL.
5. The dashboard learns each org's cell from the directory, not from its build.
6. Each cell enforces per-org quotas.

| Phase | Setup | Trigger |
|---|---|---|
| 0 | Convex free cloud; one cell; rules applied | now |
| 1 | one self-hosted Convex: Docker, a database, TLS through Caddy, nightly backups | free-plan limits |
| 2 | the first deployment becomes directory and cell 1; new orgs go to the least-loaded cell; a migration tool | a cell nears capacity |
| 3 | an EU cell; dedicated cells for large customers | customer demand |

Phase 2 requires sessions the cells can verify without calling the directory,
such as tokens the directory signs and cells check against its public key.

## 14. Rules CI enforces

1. Apps never import other apps.
2. `packages/crypto` depends only on `@noble`.
3. `apps/cli` depends on nothing in TypeScript; `spec/` is its only link.
4. The backend never decrypts.
5. The Rust crypto passes every vector in `spec/vectors/`.
6. The service worker caches the app shell only, never API responses, keys or
   secrets.

## 15. Changes to existing code

1. Move `convex/` to `packages/backend/`; move backend dependencies out of the
   root `package.json`.
2. Rename `apps/admin` to `apps/dashboard` and `packages/sdk` to
   `packages/sdk-node`; move `Implementation_Plan.md` into `docs/`.
3. Stable IDs, `orgId` on every org-owned row, protocol bindings `v2`.
4. `getBundle` serves notices on an authentic expired pass.
5. Org root key and revocation-key certificates; processes pin the root.
6. Single-string token format.
7. Recovery kit, emergency kit, org recovery kit.
8. Offline allowance setting and the startup cache.
9. Invites, confirmation, roles, removal with key rotation.
10. Audit events, hash chain, retention, export.
11. Session storage that survives a PWA restart; auto-lock; passkeys; MFA.
12. Write `spec/protocol.md`; generate vectors; port the CLI to Rust; delete
    `packages/cli` once the port passes its tests.
13. Update `SECURITY.md`: revocation from the browser, the PWA session
    trade-off, recovery limits, audit-log tamper evidence, serverless limits.

## 16. To verify before building on it

- The Convex Rust client's support for subscriptions and for the auth the
  handshake flow needs.
- Self-hosted Convex: hardware, connection capacity, upgrade and backup
  procedure.
- WebAuthn PRF support across iOS, Android, Windows and desktop browsers.
- `dist` support for every planned installer, npm included.
- The cost estimate's renewal-interval assumption.

## Decisions withdrawn during review

| Withdrawn | Replaced by | Reason |
|---|---|---|
| CLI-only org signing key | revoke from dashboard and CLI | the browser already holds the master key, which unlocks the signing key; the restriction protected nothing and blocked phone revocation |
| Go CLI | Rust CLI | no Go client for Convex websockets |
| TypeScript CLI on npm only | Rust binary on every channel | the audience is not limited to Node developers |
| Pinned revocation key | pinned root key | rotation without redeploying |
| Four environment variables | one token string | one secret to configure |
