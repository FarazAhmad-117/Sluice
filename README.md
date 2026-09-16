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

- The crypto core is under construction. The rest of the platform, dashboard,
  backend and SDK, is not built yet.
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
not a description of shipped software: today only the crypto core exists, and
the delivery path is unwritten. They are here so you can judge the design
before anyone asks you to trust it.

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

One package.

**`packages/crypto`** is a standalone TypeScript library with no dependency on
Convex, Next.js, React or Node built-ins, so it runs unchanged in a browser,
in Node and in Bun. It is built first and separately, so that the part
everything else rests on can be audited without reading an application. It
currently holds:

| Module | What it does |
| --- | --- |
| `bytes.ts` | Hex and UTF-8 conversion, concatenation, constant-time comparison, CSPRNG bytes |
| `aead.ts` | AES-256-GCM seal and unseal with associated data binding |
| `token.ts` | Service token minting, the HKDF auth and unwrap key split, token parsing, handshake signing and verification |
| `revocation.ts` | Signed revocation notices over a canonical, domain-separated encoding |
| `muk.ts` | Argon2id master unlock key derivation, wrapped so it cannot be logged |

**187 tests** across seven test files, run with Vitest. The suite pins exact
signed bytes rather than checking the module against itself, so a change to a
domain separator fails a test instead of silently changing the protocol.

The package has two dependencies, `@noble/hashes` and `@noble/curves`, both
chosen because they are audited, dependency-free and short enough that a
reviewer can read them. It has no dependency on Convex, Next.js, React or Node
built-ins, and `@types/node` is deliberately absent so that a `node:` import
fails to compile.

Not built yet: sealed boxes for member key wrapping, the Convex backend and
schema, the web dashboard, the SDK, the agent and the CLI. Argon2id currently
runs in pure JavaScript and takes about eight seconds at the parameters in
use, so a WASM backend inside a Web Worker is required before any of this is
usable in a browser.

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
pnpm -r test
pnpm -r typecheck
```

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
- [`docs/plans/`](./docs/plans): design direction and the foundation plan.

## Licence

[Apache-2.0](./LICENSE). Copyright 2026 Faraz Ahmad.

Future commercial features will live in a separate `ee/` directory under a
commercial licence. That directory does not exist yet, and everything in this
repository today is Apache-2.0.

Contributions are accepted under a Developer Certificate of Origin sign-off,
not a contributor licence agreement.
