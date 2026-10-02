# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Day one: a solo or indie developer replacing their own `.env` files across a
few projects. They live in a terminal and an editor, and they open the
dashboard to set things up, change a value, or deal with a leak. Teams (a lead
inviting other developers, CI tokens per pipeline) come later and must fit the
same structure without a redesign.

## Product Purpose

Sluice is an open-source, zero-knowledge replacement for `.env` files. Secrets
are encrypted in the browser before they leave it; the server stores
ciphertext it cannot read. A workload gets its secrets at start-up through
`sluice run -- <command>`, for any language, and they never touch disk.

Success for the dashboard: a new user goes from sign-up to a working
`sluice run` in minutes, and a user with a leaked token revokes it and sees it
take effect without hunting for the control.

## Positioning

Signed revocation that reaches processes already running. Revoking a token
stops a live `sluice run` within seconds, not on its next restart, and the
revocation is signed by a key the server never holds, so the server can
neither forge one nor suppress one silently.

## Operating Context

The four moments the dashboard must be best at, all equal in weight:

1. **First run to first `sluice run`:** sign up, save the recovery kit, create
   an org, a project and an environment, add secrets, copy the run command.
2. **Daily secret editing:** find, add, edit and compare secrets across
   environments (development, staging, production).
3. **Emergency revoke:** a token leaked; revoke it, often from a phone, from a
   cold start, and see running processes stop.
4. **Reviewing who did what:** audit log, which tokens exist, when they were
   last used.

Mobile is a first-class context, not a fallback: the dashboard ships as an
installable PWA, and the emergency revoke is expected to happen on a phone.

## Capabilities and Constraints

- Hierarchy: org → project → environment → secrets. Service tokens belong to
  an environment.
- Unlock: the password derives the master key in the browser (Argon2id, a few
  seconds on slow devices). There is no password reset; recovery is a recovery
  kit plus other admins. The UI must make the kit impossible to skip by
  accident and must never imply the server can recover an account.
- Secret values are decrypted only in the browser and only on demand.
- Concurrent edits are rejected, not merged: "Someone else just changed this
  secret. Reload to see their version."
- Built today: sign up, sign in, unlock, orgs, projects, environments, secrets.
  Planned, design must leave room for: service tokens and revocation screens,
  recovery kit, team invites and roles, audit log, passkeys and TOTP.
- Stack: React + Vite + Tailwind v4 in `apps/admin`, Convex backend.

## Brand Commitments

- Name: Sluice, lowercase wordmark `sluice`.
- The dashboard and the marketing site (`apps/web`) share theme colors only.
  The marketing site is not finalised, so its fonts, motifs and effects are
  not binding on the dashboard. Current shared colors live in
  `apps/web/src/app/globals.css`.
- Open source and public: nothing in the UI may overclaim security properties
  the code does not have (`SECURITY.md` is the source of truth).

## Evidence on Hand

No customers, testimonials, usage numbers or pricing exist. None may be
invented in UI copy or mock data presented as real.

## Product Principles

1. Get the user to a running process fast; explanation comes after success,
   not before it.
2. Revocation is the product's reason to exist; it is never more than two taps
   away from wherever a token appears.
3. Honest about what the server can and cannot do; never reassure with a claim
   the code does not back.
4. Same capability on a phone as on a desktop.

## Accessibility & Inclusion

WCAG 2.2 AA. Destructive actions (revoke, delete) must not rely on color
alone and must be reachable by keyboard and screen reader.
