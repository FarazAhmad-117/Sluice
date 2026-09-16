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
  password-derived key. A weak password is a weak root. A minimum is enforced
  and SSO-backed key wrapping is planned, neither of which saves a password
  that is guessable.

If a report depends on one of these four conditions, it is out of scope by
design. If you can break one of the defended-against rows, that is exactly
what this policy exists for.

## What the server holds

For completeness, because it is the claim most worth attacking: the server
stores public keys, wrapped key blobs it cannot open, and ciphertext. Sluice's
own bootstrap secrets, such as a JWT signing key, live in deployment
environment variables precisely because they are not secret-decrypting
material. Nothing that could open customer data is stored server side. If you
find a place where that is not true, that is a critical finding and this
project wants to hear about it before anyone else does.
