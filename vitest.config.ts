import { defineConfig } from "vitest/config";

// The Convex backend lives at `convex/` in the repository root, so its tests
// run from the root workspace project rather than from a package under
// `packages/`. `packages/crypto` has its own vitest instance and deliberately
// has no `@types/node`, which is why the repo discipline test, which needs
// `node:fs`, cannot live there.
export default defineConfig({
  test: { include: ["convex/**/*.test.ts"] },
});
