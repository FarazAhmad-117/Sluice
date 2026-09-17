import { defineConfig } from "vitest/config";

// The Convex backend lives at `convex/` in the repository root, so its tests
// run from the root workspace project rather than from a package under
// `packages/`. `packages/crypto` has its own vitest instance and deliberately
// has no `@types/node`, which is why the repo discipline test, which needs
// `node:fs`, cannot live there.
export default defineConfig({
  test: {
    include: ["convex/**/*.test.ts"],
    // Convex's default runtime is not Node, so tests run in an edge runtime to
    // match it. Running them under Node would let a file reach for `node:`
    // built-ins or a Node-only global, pass here, and fail on deployment.
    // `convex/repo/repo.test.ts` is the one file that genuinely needs Node,
    // because it reads the source tree from disk, and it opts back in with a
    // `@vitest-environment node` docblock.
    environment: "edge-runtime",
    server: { deps: { inline: ["convex-test"] } },
  },
});
