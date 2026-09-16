# Contributing to Sluice

Thanks for looking. Sluice is pre-release and the crypto core is the part
under active construction, so the most valuable contributions right now are
review, test cases and reproductions rather than large features.

**Found a security vulnerability? Do not open an issue.** Read
[`SECURITY.md`](./SECURITY.md) and email faraz@cupupmarketing.com.

## Developer Certificate of Origin, not a CLA

Sluice uses the [Developer Certificate of Origin](https://developercertificate.org/)
version 1.1. There is no contributor licence agreement and there is not going
to be one. On a security project a CLA reads as a prelude to a relicence, and
that costs more in contributor goodwill than it is worth. The DCO gets the
same thing done: you state that you wrote the contribution, or have the right
to submit it, under the project's Apache-2.0 licence.

Every commit needs a sign-off line:

```
Signed-off-by: Your Name <your.email@example.com>
```

Git adds it for you:

```bash
git commit -s -m "fix: reject zero-length nonces"
```

The name and email must be real and must match your git author identity. Set
them once:

```bash
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

Forgot to sign off? Amend the last commit with `git commit --amend -s`, or
sign off a whole branch with `git rebase --signoff main`.

## Development setup

Requirements: **Node 22** and **pnpm 10**. The repository pins Node in
`.nvmrc` and pnpm in the root `package.json` `packageManager` field.

```bash
git clone https://github.com/FarazAhmad-117/Sluice.git
cd Sluice
pnpm install
pnpm -r test
pnpm -r typecheck
```

Both `pnpm -r test` and `pnpm -r typecheck` must pass before you open a pull
request. They are the same commands CI runs.

## Rules for `packages/crypto`

This package is the one that has to be auditable on its own. A reviewable
library is worth far more than a correct-looking application built on top of
it, so the constraints here are tighter than elsewhere in the repository.

### No platform dependencies

`packages/crypto` takes **no dependency on Convex, Next.js, React, or Node
built-ins**. It must run unchanged in a browser, in Node and in Bun.

`@types/node` is deliberately absent from the package. That is not an
oversight: without it, any `node:` import fails to compile, so the constraint
is enforced by `pnpm -r typecheck` rather than by reviewer memory. Do not add
it, and do not reach for `globalThis` casts to route around it. If you need a
platform capability, the caller passes it in.

Dependencies are limited to audited, dependency-light primitives. Today that
is `@noble/hashes` and `@noble/curves`. Adding another one is a discussion to
have in an issue before the pull request.

### Test-driven development is required

For anything under `packages/crypto`, the failing test comes first and you
must **observe it failing** before writing the implementation. An untested key
derivation that looks right is the most dangerous code in this repository.

In practice:

1. Write the test.
2. Run it. Watch it fail, and check it fails for the reason you expected
   rather than a typo or a bad import.
3. Write the smallest implementation that passes.
4. Run the full suite.

Tests that pin exact bytes are preferred over tests that compare a function
against itself. A test that signs with the module and verifies with the module
proves nothing about the format. Write the expected bytes out literally, as
`test/revocation.test.ts` does, so the domain separator cannot be changed
without a test going red.

### Adding an export is a deliberate act

`packages/crypto/src/index.ts` is the public surface of the library. Adding an
export to it is a decision, not a side effect of writing a new file. The file
stays small and explicit, one named export at a time, so that widening the
public surface is a one-line diff a reviewer cannot miss.

That surface is pinned by `packages/crypto/test/index.test.ts`, which asserts
the exact sorted list of exported names. Adding an export therefore fails the
suite until you extend that list, which is the point: on a security package an
accidentally exported internal is how key material escapes. If your change
widens the public surface, say why in the description. Internal helpers stay
unexported, and shared internals that no consumer should reach live in
`packages/crypto/src/internal.ts`, which no barrel re-exports.

## Pull requests

- One logical change per pull request. A crypto change and a dashboard change
  do not belong together.
- Small commits. Security review is tractable on a 40-line commit and is not
  tractable on a 4,000-line one.
- Explain the why in the description. The what is in the diff.
- Note anything you tried that did not work, and anything you are unsure of.
  Flagged uncertainty is useful. Smoothed-over uncertainty is a liability.

## Writing style

These apply to documentation, interface copy, commit messages and error
messages:

- **Zero em-dashes and zero en-dashes.** Use a hyphen, a comma, a colon, or
  two sentences.
- No invented precision. Do not claim metrics, benchmarks or guarantees the
  project cannot demonstrate today.
- Plain functional language. Skip filler verbs like "elevate", "seamless" and
  "unleash".

Overclaiming is the fastest way to lose a security project's credibility, so
understatement is the house style.

## Code of conduct

Be straightforward and assume good faith. Harassment, personal attacks and
bad-faith argument get you removed from the project. Report problems to
faraz@cupupmarketing.com.

## Licence

Contributions are accepted under [Apache-2.0](./LICENSE), the licence covering
the core of this repository.
