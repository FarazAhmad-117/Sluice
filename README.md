# Sluice

Zero-knowledge environment variable delivery, with cryptographically signed
revocation of live processes.

Teams store environment variables in a dashboard and a stack-specific SDK
delivers them into running processes. The server never sees a plaintext secret
and holds no key that could decrypt one. When an admin revokes a service
token, every live process holding that token dies within milliseconds, and it
does so only because it verified a signature made by a customer-held key.

## Status: pre-release, do not store production secrets

This repository is early. Read this before you do anything with it:

- The protocol is frozen at `v2`. First versions of the crypto core, backend,
  dashboard, workload SDK core and a TypeScript CLI exist.
  Recovery, teams, an audit log reader and the Rust CLI are not built yet.
- There has been **no third-party cryptographic review**.
- There is no release, no published package and no upgrade path.
- **Do not put production secrets in Sluice yet.** This is not modesty, it is
  the accurate description of a security product that has not been reviewed.

See [`SECURITY.md`](./SECURITY.md) for the threat model and how to report a
vulnerability.

## What makes it different

Doppler, Infisical, 1Password, HashiCorp Vault and EnvKey all store secrets.
Storage is not the differentiator.

The four points below describe the design Sluice is being built to. They are
not a claim that the software is ready: it is pre-release and unreviewed.
They are here so you can judge the design before anyone asks you to trust it.

- **Revocation reaches running processes, not just the next fetch.** The
  delivery channel is a live subscription rather than a poll, so a revoked
  token stops a running workload rather than waiting out a refresh interval.
- **Revocation is signature-gated.** A shutdown notice is signed in the
  admin's browser with an organisation key that the server never holds. The
  SDK exits only on a valid signature. Neither the operator of Sluice, nor a
  compromise of the hosting platform, nor a network attacker can mass-kill a
  customer's fleet.
- **Losing the connection is never treated as revocation.** A dropped socket
  keeps the last known good values, logs, alarms and reconnects. If rotating a
  value or a network blip can crash production, nobody rotates anything, and
  the product's premise collapses.
- **Read access to an environment is a cryptographic boundary, not a
  permission flag.** Each project and environment pair has its own data key,
  wrapped separately to each member and each token, so "this developer can
  read `dev` but not `prod`" is not a server-side check that a server-side
  flaw could bypass.

The cost of that design is stated openly in section 7 of the implementation
plan: server-side secret scanning, server-side rotation of third-party
credentials and push sync to other platforms are permanently unbuildable on
the server. Anything needing plaintext has to run on the customer's own
machine.

## What exists today

| Path | What it is |
| --- | --- |
| `packages/crypto` | The cryptographic core, described below |
| `convex/` | The Convex backend: signup and two-call login, orgs, projects, environments, versioned secrets, service token creation and revocation, the handshake and the bundle subscription |
| `apps/admin` | The dashboard: signup, login, unlock, and creating orgs, projects, environments and secrets, encrypted in the browser. Minting and revoking tokens from the dashboard is not built yet |
| `packages/sdk` | The workload decision core: when a process installs secrets, keeps them, or shuts down |
| `packages/cli` | A TypeScript `sluice run`, which injects secrets into a child process and kills it on a signed revocation. No shipped client can yet mint a service token or sign a revocation (`createServiceToken` and `revokeServiceToken` are called only from tests, and the dashboard does not display the org revocation public key), so today it runs end to end only in the test suite, in `convex/bundle.contract.test.ts` |
| `apps/web` | The public website |

**`packages/crypto`** is a standalone TypeScript library with no dependency on
Convex, Next.js, React or Node built-ins, so it runs unchanged in a browser,
in Node and in Bun. It is built first and separately, so that the part
everything else rests on can be audited without reading an application. It
currently holds:

| Module | What it does |
| --- | --- |
| `bytes.ts` | Hex and UTF-8 conversion, concatenation, constant-time comparison, CSPRNG bytes |
| `aead.ts` | AES-256-GCM seal and unseal with associated data binding |
| `ids.ts` | Client-minted permanent ids (`org_`, `usr_`, `env_`, `sec_`) that encryption bindings name instead of database ids |
| `protocol.ts` | The `v2` associated data for secrets, key grants and revocation keys, and the token id hash |
| `token.ts` | Service token minting, the HKDF auth and unwrap key split, token parsing, handshake signing and verification |
| `revocation.ts` | Signed revocation notices over a canonical, domain-separated encoding |
| `muk.ts` | Argon2id master unlock key derivation under a random per-account salt, wrapped so it cannot be logged |
| `argon2.ts` | The Argon2id backend seam, with conformance checks for a faster backend |
| `identity.ts` | The auth verifier, the wrapped key blob format and the user key associated data |
| `email.ts` | The one email normalisation rule both ends use as the account lookup key |

**1,142 tests** across the workspace, run with Vitest: 305 in
`packages/crypto`, 406 for the backend, 172 in `packages/cli`, 158 in
`apps/admin`, 93 in `packages/sdk` and 8 in `apps/web`. The crypto suite pins
exact bytes against vectors computed outside the package rather than checking
the module against itself, so a change to a domain separator fails a test
instead of silently changing the protocol.

The package has two dependencies, `@noble/hashes` and `@noble/curves`, both
chosen because they are audited, dependency-free and short enough that a
reviewer can read them. It has no dependency on Convex, Next.js, React or Node
built-ins, and `@types/node` is deliberately absent so that a `node:` import
fails to compile.

Not built yet: wrapping a key to another member's public key, so there are no
teams; recovery; a reader for the audit log (audit events are recorded; nothing
reads them yet); and the Rust CLI. The plan is in
[`docs/plans/2026-09-30-roadmap.md`](./docs/plans/2026-09-30-roadmap.md).

## Architecture sketch

Two key hierarchies meet in the middle. This is the planned design, and only
the machine-side primitives listed above are implemented so far. Full detail
is in [`Implementation_Plan.md`](./Implementation_Plan.md) section 3.

**Human side.** A password goes through Argon2id to a master unlock key that
is never transmitted. That key wraps the user's X25519 private key and Ed25519
signing key. The server stores public keys, wrapped blobs and a separately
derived auth verifier. A project data key exists per project and environment
pair, wrapped to each member's public key. Adding a member is done client
side by an existing member, who fetches the new member's public key, verifies
its fingerprint and re-wraps the data key. The server only moves blobs.

**Machine side.** This is where a naive design stops being zero-knowledge, by
sending the whole token to the server and letting it derive the unwrap key. So
the token is split instead. At mint time, in the browser:

```
tokenSecret = 32 random bytes            (shown once, never uploaded)
tokenId     = 16 random bytes

authSeed  = HKDF-SHA256(tokenSecret, salt=tokenId, info="sluice/auth/v1")
unwrapKey = HKDF-SHA256(tokenSecret, salt=tokenId, info="sluice/unwrap/v1")
```

The server receives the Ed25519 public key derived from `authSeed`, plus the
project data key wrapped under `unwrapKey`. It gets a public key and a blob it
cannot open. At runtime the SDK signs a handshake with its Ed25519 key, gets a
short-lived JWT, subscribes to the bundle, then derives `unwrapKey` locally and
decrypts in memory.

`unwrapKey` is never transmitted and is not derivable from anything the server
holds. That is the whole claim, and it lives in one HKDF call in
`packages/crypto/src/token.ts`.

## Development

Node 22 and pnpm 10.

```bash
git clone https://github.com/FarazAhmad-117/Sluice.git
cd Sluice
pnpm install
pnpm test:all
pnpm typecheck:all
```

`pnpm -r` alone skips the root workspace, which is where the backend tests
live.

`@types/node` is deliberately absent from `packages/crypto`, so a stray `node:`
import fails typecheck rather than passing review. Test-driven development is
required for anything in that package. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Documentation

- [`Implementation_Plan.md`](./Implementation_Plan.md): threat model,
  cryptographic architecture, data model, kill switch behaviour, build phases,
  risk register.
- [`SECURITY.md`](./SECURITY.md): reporting a vulnerability, scope, and what
  Sluice does not defend against.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md): DCO sign-off, setup, and the rules
  for the crypto package.
- [`docs/plans/`](./docs/plans): the architecture design, the roadmap and
  each phase's plan.

## Licence

[Apache-2.0](./LICENSE). Copyright 2026 Faraz Ahmad.

Future commercial features will live in a separate `ee/` directory under a
commercial licence. That directory does not exist yet, and everything in this
repository today is Apache-2.0.

Contributions are accepted under a Developer Certificate of Origin sign-off,
not a contributor licence agreement.
