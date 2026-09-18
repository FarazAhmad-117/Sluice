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
| An insider at a customer organisation | Role-based access control, audit log, per-environment key separation |

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
  password-derived key, so a weak password is a weak root. Nothing enforces a
  minimum today, because there is no signup path yet. A strength gate and
  SSO-backed key wrapping are both planned, and neither saves a password that
  is guessable: the salt is derived from a public user id, so the password is
  the only entropy in the key.

If a report depends on one of these four conditions, it is out of scope by
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

In `sessionStorage`, in plaintext, alongside the user id, the normalised email,
both public keys and both wrapped key blobs. **Any script running on the
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
