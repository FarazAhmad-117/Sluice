## What this changes

<!-- The what is in the diff. Explain the why. -->

## Why

## Checklist

- [ ] Every commit is signed off (`git commit -s`). See [CONTRIBUTING.md](../CONTRIBUTING.md).
- [ ] `pnpm -r test` passes.
- [ ] `pnpm -r typecheck` passes.
- [ ] One logical change. Unrelated work is in a separate pull request.
- [ ] No em-dashes or en-dashes in any text this adds.

## If this touches `packages/crypto`

- [ ] The failing test was written first and observed failing.
- [ ] No dependency on Convex, Next.js, React or Node built-ins was added.
- [ ] If this adds an export to `src/index.ts`, the description says why.

## Anything you are unsure about

<!-- Flagged uncertainty is useful. Leave this blank only if there is none. -->
