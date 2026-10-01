# Security Policy

Sluice is a secrets product. The honest description of its security posture
matters more than the marketing, so this document leads with the limits.

## Project status: pre-release

Read this before you put anything real into Sluice.

- Sluice is **pre-release**. There is no stable release, no versioned API and
  no upgrade path guarantee.
- The cryptographic core has **not had a third-party review**. It is written
  against published primitives and covered by tests, which is not the same
  thing as having been audited by someone who does this for a living. An
  external crypto review is planned and has not happened.
- **Do not store production secrets in Sluice yet.** Treat anything you put
  into it as recoverable by an attacker who finds a flaw nobody has looked
  for yet.

This section will change when the review happens, and not before.

## Reporting a vulnerability

Email **faraz@cupupmarketing.com**.

Please do **not** open a public GitHub issue, discussion or pull request for a
suspected vulnerability. Public reports are visible to everyone, including
anyone who would use the finding, before there is a fix.

Useful reports include:

- What you think the impact is, and who it affects.
- The steps to reproduce, or a proof of concept.
- The commit SHA or version you tested.
- Whether you have disclosed this anywhere else, and any deadline you intend
  to hold the project to.

If you want to encrypt the report, say so in a first email and a key will be
exchanged. There is no published PGP key yet.

## What to expect

This is a solo project. There is no security team, no pager and no service
level agreement, so here is what can actually be committed to rather than what
sounds reassuring:

- **Acknowledgement within 5 working days.** If you have not heard anything by
  then, send a follow up. It was missed, not ignored.
- An assessment of severity and a rough plan within 10 working days of
  acknowledgement.
- Regular updates while a fix is in progress.
- Credit in the release notes and in this repository, if you want it. Say so
  in your report, and say how you want to be named.

There is no bug bounty and no payment. That may change after launch.

On disclosure: coordinated disclosure is preferred, and a fix will be shipped
as fast as a solo maintainer reasonably can. If you set a disclosure deadline,
state it up front so it can be planned around rather than discovered late.

## Scope

### In scope

- The cryptographic core in `packages/crypto`: key derivation, wrapping,
  token minting, AEAD use, canonical encoding and signature verification.
- Anything that would let the server, its operator, or a party who has
  compromised the server read a plaintext secret value.
- Anything that would let a party other than an authorised customer admin
  cause a workload to accept a revocation notice, since a forged revocation
  is an outage.
- Anything that would let a revoked or expired service token continue to
  receive secrets.
- Authentication and authorisation flaws: privilege escalation between roles,
  cross-organisation or cross-environment data access, token scope bypass.
- Replay, nonce reuse, signature malleability and canonicalisation flaws in
  the protocol between the SDK and the server.
- Dependency vulnerabilities that are actually reachable from Sluice code.
  Please include the reachable path.

### Out of scope

- Findings against components that do not exist yet. Much of the system
  described in `Implementation_Plan.md` is not built. Reports about unwritten
  code are not useful.
- Automated scanner output with no demonstrated impact.
- Missing hardening headers, cookie flags or TLS configuration on
  infrastructure that is not yet deployed for production use.
- Denial of service through raw traffic volume, rate limiting gaps on
  pre-release infrastructure, or resource exhaustion that requires already
  holding valid credentials.
- Social engineering of the maintainer, physical attacks, and anything
  requiring a compromised end-user device. See the threat model below.
- Vulnerabilities in Convex, Vercel, npm or any other third-party platform.
  Report those to the platform. If a Sluice design choice makes a platform
  weakness worse, that part is in scope and worth reporting here.
- Missing features. An unimplemented control is a roadmap item, not a
  vulnerability. Open a normal issue.

## Threat model

The full threat model is section 2 of
[`Implementation_Plan.md`](./Implementation_Plan.md). A zero-knowledge claim
means nothing without naming the adversary, so the short version is here too.

### Defended against

| Adversary | Mitigation |
| --- | --- |
| Database dump or backup theft | Ciphertext only, no key material in the database |
| A malicious or legally compelled operator, including the maintainer | No decryption key ever reaches the server |
| Compromise of the Convex platform | Same as above |
| Network attacker with TLS stripped | Payloads are already encrypted end to end |
| Stolen service token | Instantly revocable, scoped to one environment |
| A malicious server pushing fake revocations | Revocation notices are signed by customer-held keys |
| An insider at a customer organisation | Per-environment key separation. Audit events are recorded, but nothing reads them yet. Roles and teams are planned: today every org has only its owner |

### Not defended against

These are real limits, stated plainly. They are not oversights and they are
not going to be quietly fixed later.

- **Account enumeration.** Signup rejects a duplicate email with a message
  saying so, so anyone can test any address and learn whether it has an
  account. Login deliberately returns an identical error for a wrong verifier
  and an unknown address, but that hardening buys nothing while signup answers
  the same question for free, and it would be dishonest to describe it as an
  anti-enumeration defence. Treat account existence as public. Closing this
  means signup succeeding unconditionally and sending the "you already have an
  account" notice by email, which needs email delivery that does not exist
  yet.

  Login is two calls, and the first, `auth.getLoginSalt`, is built not to add
  a second oracle. It returns the real salt for a known address and, for an
  unknown one, a decoy of the same width and alphabet: `HMAC-SHA256` under the
  deployment's `AUTH_PEPPER`, truncated to 16 bytes, the same answer on every
  call. What it still leaks:

  - **Timing.** The known-address path materialises a user document where
    the unknown path resolves an empty index range. That is the same cause as
    the login difference recorded below, which was measured on login, not on
    this endpoint. Here it sits on a cheaper endpoint: a query, with no
    verifier to supply and no Argon2 for the caller to run.
  - **No rate limit.** It is a query, and a query cannot write, so a limiter
    that counts attempts in a table cannot cover it. Limiting it means making
    it a mutation or an HTTP action first.
  - **A subscription is a signup watch.** Convex queries are reactive. A
    client subscribed to `getLoginSalt(address)` is pushed the real salt the
    moment that address signs up.
  - **A pepper rotation separates decoys from real salts.** Rotating
    `AUTH_PEPPER` changes every decoy and no real salt, so a prober holding
    answers from before and after the rotation can tell which addresses have
    accounts.
- **A measured timing difference on login.** A login for a known address is
  consistently 0.08 to 0.15 ms slower than one for an unknown address, about 5
  to 8 percent, because the known path materialises a user document while the
  unknown path resolves an empty index range. The error payload is byte
  identical in both cases, and the constant-time comparison and decoy hash do
  their jobs, but the document read is not something a mutation can hide. It
  sits far below network jitter, so it is not extractable from a single sample,
  and it is extractable with enough of them. Measured rather than assumed.
- **A compromised client device.** If an admin's laptop is owned, their keys
  are owned. Sluice cannot tell the difference between the admin and malware
  running as the admin.
- **Malicious JavaScript served to the web dashboard.** This is the unsolved
  problem of browser-based end-to-end encryption. A compromised server can
  serve a dashboard build that exfiltrates the master unlock key. Strict CSP,
  subresource integrity, reproducible builds and a code transparency log
  reduce the window and make tampering detectable after the fact. They do not
  eliminate the attack. The planned answer is to make the CLI the trust
  anchor and to document that security-critical operations, such as minting
  production tokens and break-glass recovery, belong there rather than in a
  browser.
- **A workload that has already decrypted a value.** Once a process decrypts
  a secret, that process can leak it, log it, or send it anywhere. Sluice
  controls delivery, not use.
- **A customer choosing a weak password.** The key hierarchy is rooted in a
  password-derived key, so a weak password is a weak root. The dashboard's
  signup refuses a password shorter than 12 characters or estimated below 60
  bits, but that check runs in the browser, and the server cannot enforce it
  because it never sees the password. SSO-backed key wrapping is planned.
  Neither it nor the strength check saves a password that is guessable: the
  salt is public (see "How the master key is salted" below), so the password
  is the only secret input to the key.
- **A malicious server choosing the salt.** The server supplies the salt every
  login derives under. A compromised server could hand every account the same
  salt, then grind one dictionary against every login verifier it receives,
  amortising the work across all of them instead of paying it per account.
  This is new with the random salt. Before it, the client computed the salt
  from the address the user typed, so the server could not choose it.

  What the change adds is the amortisation, not the offline attack itself. The
  server already holds each account's verifier hash and the pepper it is keyed
  under, so it can grind any one account's password offline, at full Argon2id
  cost per guess, with or without this. Nor is the attack silent: a user handed
  the wrong salt derives the wrong key and login fails. The verifier has
  already been sent by then, so the failure reveals the attack without
  preventing it.

  The planned mitigation is near-term: each device remembers the salt for
  every account that has logged in on it and refuses a different one, so a
  server can attempt this only on a device's first login. A client-held secret
  key in the 1Password style, so the password is never the only input, is
  further out.

If a report depends on one of these conditions, it is out of scope by
design. If you can break one of the defended-against rows, that is exactly
what this policy exists for.

## What the server holds

For completeness, because it is the claim most worth attacking: the server
stores public keys, wrapped key blobs it cannot open, and ciphertext. Sluice's
own bootstrap secrets, such as a JWT signing key and the password pepper, live
in deployment environment variables precisely because they are not
secret-decrypting material. Nothing that could open customer data is stored
server side. If you find a place where that is not true, that is a critical
finding and this project wants to hear about it before anyone else does.

### How the master key is salted

The master unlock key is Argon2id of the password, salted with
`sha256("sluice/muk-salt/v2" || accountSalt)`, where `accountSalt` is 16 random
bytes the client mints at signup and the server stores. The email is not an
input, so changing an account's email does not change its master key or orphan
anything wrapped under it.

The salt is public. `auth.getLoginSalt` returns it to anyone who asks to log in
as the account, so a targeted attacker can fetch one account's salt and
precompute against it before any breach. What a per-account salt buys is that
one table of guesses cannot be run against every account at once, and that no
table carries over between deployments. The password is the only secret input,
and the Argon2id cost is the only thing slowing an offline guess.

### What the encryption bindings protect

Every secret, key grant and wrapped revocation key is sealed with AES-GCM under
associated data that binds it to its slot by the permanent ids clients mint,
never a Convex document id:

- A secret's name and value: the environment's permanent id, the secret's
  permanent id, its version, and the field (`name` or `value`).
- A key grant, the environment key wrapped to a member or a token: the
  environment, the key version, and the grantee.
- A wrapped org revocation key: the org and the grantee.

The account's own two wrapped private keys are the exception. They are bound
only to their purpose, `x25519` or `ed25519` (see
`packages/crypto/src/identity.ts`), which stops the two being swapped, and are
kept apart from other accounts by being sealed under that account's own master
key.

The server checks every version a client states in the same transaction as
the write and refuses a mismatch, so a stale write fails while the writer can
still retry.

This stops a server or database writer from splicing ciphertext between slots.
Each of these now fails to open: moving a value between secrets or between
environments, moving a name ciphertext into a value slot, putting a superseded
value into the current row, and serving an old environment key labelled as the
current one.

It does not stop:

- **Wholesale rollback.** Serving an entire old row or grant together with its
  own old version opens, because the associated data is correct for that row.
  Detecting it needs a client-side ratchet on the highest version seen, which
  is future work.
- **Equivocation.** When two clients race to write the same next version and
  the server refuses one, the refused client still produced a valid
  ciphertext for that version. A server that kept it can show different valid
  versions to different readers. Detecting it needs a ratchet compared across
  clients, or a transparency log.
- **Omission and resurrection.** The server can leave a secret out of what it
  serves, or serve one that was deleted, because the deletion and supersession
  columns are not authenticated.
- **Lying about which environment a name means.** The environment uid a client
  binds to is supplied by the server, so a server can answer "production" with
  another environment's uid, and serve that environment's grant and secrets
  with it. The dashboard then shows the other environment's secrets as
  production's, and seals every secret it writes to "production" into the
  other environment, where that environment's grantees can read it. The
  planned single-string service token, minted on the client, carries the
  environment uid and pins it for the CLI only. Pinning the name to uid
  mapping in the dashboard is separate follow-up work.
- **Substituting the org revocation public key.** `orgs.revocationPublicKey`
  is a column, and no ciphertext binds it. A server could replace it with a
  key of its own, and every revocation-key grant would still open. The check
  that an unwrapped revocation seed matches the stored public key,
  `revocationKeyMatches` in `apps/admin/src/lib/orgs/revocation-key.ts`,
  exists but is not yet called, because no shipped client signs revocations
  yet. Verify the key you pin in `SLUICE_ORG_REVOCATION_PUBLIC_KEY` out of
  band, not by reading it back from the server.

### Deploy the backend and the CLI together

The CLI and the backend speak one protocol version, and there is no
compatibility layer. A CLI newer than the backend refuses a bundle that still
carries the old Convex environment id, logs "deploy the backend and the CLI
together", installs none of that bundle's secrets and keeps any last known good
set. It still reads and acts on a revocation notice in that bundle, because the
notice is read before any decryption.

The reverse direction fails the same way. A CLI from before Phase 1 requires
`environmentId` and treats the new bundle, which carries `environmentUid`
instead, as malformed: it installs none of its secrets and keeps any last known
good set. It still handles a revocation, because it reads the notice first and
the new backend sends `secrets: []` beside a notice, so the old CLI stops
before it reaches the decrypt.

### What revocation does and does not undo

Revoking a service token stops **delivery**. Every live process holding that
token receives a signed notice and shuts down, and the token can never fetch a
bundle again.

It does not undo **decryption**. A token that has fetched its bundle once has
already unwrapped the project data key for its environment, and revocation does
not re-key that environment. So an attacker who pulled the key before the
revocation, or who holds a copy of the database, can still open every secret in
that environment, including secrets written after the revocation, until someone
re-keys.

**No re-key exists yet.** When it does, rotating an environment's key must
re-wrap every grant on that environment in one transaction, and revocation
should trigger it.

The honest summary: revocation is an instant, cryptographically authenticated
stop on a machine identity. It is not a guarantee that the secrets that
identity could read are still secret. Rotate the underlying credentials at the
provider too, which is the same thing you would do after any credential leak.

### Where the dashboard session token lives

In `sessionStorage`, in plaintext, alongside the user id, the account's
permanent `userUid`, its `accountSalt`, the normalised email, both public keys
and both wrapped key blobs (see `apps/admin/src/lib/auth/session-store.ts`).
The uid and the salt are public: the server returns the uid at login and the
salt to anyone who asks to log in as the account. **Any script running on the
dashboard origin can read all of it.** One cross-site scripting flaw, in the
dashboard or in any dependency it loads, takes a live session for its full
lifetime.

This is architectural rather than unfinished work. Convex functions are called
from the browser and carry no headers, so the session token travels as a
function argument the server verifies against stored state, and an argument
has to be readable by the code that builds the call. A cookie the JavaScript
cannot read is a cookie the JavaScript cannot use. The only fix is proxying
every Convex call through a server route, which also discards the reactive
subscriptions that make instant revocation work.

What is never stored anywhere in the browser: the master unlock key, the
unwrapped private keys, the password, or any decrypted secret. A page refresh
leaves you signed in and locked, and unlocking needs the password again.

Unlock re-derives the master key from the password and the stored salt, without
asking the server. A script that tampers with the stored salt therefore makes
unlock derive the wrong key, fail to open the wrapped private keys, and stop
with an error. It sends nothing anywhere, so a tampered salt is a failed unlock,
not a leak.

No obfuscation has been applied to the stored token, deliberately. An encoding
that only looks like protection changes what a reviewer believes without
changing what an attacker gets.

### What the server can see, stated plainly

The claim above is about secret names and secret values. It is not a claim
that the operator can see nothing. The following are plaintext in the
database, by design, because the server has to route, authorise and index on
them:

- Organisation names and slugs
- Project names and slugs
- Environment names, such as `production`
- Email addresses
- Which users belong to which organisation, and with what role
- Audit metadata: who acted, when, from which address, and on what
- The existence, count and modification times of secrets, though not their
  names or values

So an operator, or anyone who compels one, can see that your company has a
project called `payments` with a `production` environment holding 34 secrets,
that a particular engineer read from it at 02:14, and that one of those
secrets changed an hour later. They cannot see what any of them are called or
what any of them contain.

That is a real metadata leak and it is not going away, because a server that
cannot index on any of it cannot route a request. Said here rather than
discovered later.

### A property of the hosting platform you should know

A Convex admin key grants complete control over a deployment, and it cannot be
revoked once created. That is a property of the platform rather than of
Sluice, and it constrains self-hosters as much as it constrains this project.
It does not let anyone decrypt customer secrets, because the material needed
to do that is never on the server. It does let the holder read everything in
the previous section, and change what the deployment serves.

## Disclosed and fixed

### 2026-10-01: a malformed bundle could orphan a `sluice run` child

Found in internal review before any release. No deployment held real data.

**What happened.** A bundle carrying a revocation notice beside a `secrets`
field of `null` made the `sluice run` supervisor throw inside the Convex
websocket callback: the old check was `raw.secrets === undefined ||
raw.secrets.length === 0`, and `null.length` throws. Nothing caught the
exception, and the supervisor process exited. Other non-array values fell
through to the asynchronous decrypt, which refused them. With a forged or replayed notice, which the supervisor correctly
refuses, the child process kept running with its secrets and could no longer
be revoked, because the only process that could act on a revocation was gone.
With a genuine notice, the SIGKILL escalation for a child that ignores SIGTERM
was lost.

**The fix, in layers.**

- A `secrets` field that is not an array, beside a notice, is treated as no
  secrets.
- Exceptions in the subscription handlers are contained at the subscription
  boundary and logged. The notice is queued and acted on before anything that
  could throw, so containing them never loses a shutdown.
- Any internal error in the shutdown logic itself fails closed: the
  supervisor tries to persist its revocation floor (best effort), then
  SIGKILLs the child and exits with code 70.
- A process-level last-resort handler for uncaught exceptions and unhandled
  rejections SIGKILLs the child and exits 70. It does not touch the floor.

**Residual.** Malformed websocket frames, from a compromised deployment or a
TLS man in the middle, can still make the Convex client throw outside any
Sluice guard. That now terminates the workload with exit code 70 rather than
orphaning it. A database writer cannot do this: they only shape the result of a
valid query, which arrives as well-formed JSON and takes the guarded path.
