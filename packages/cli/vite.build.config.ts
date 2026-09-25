import { defineConfig } from "vite";

/**
 * THE ONE PACKAGE IN THIS REPOSITORY THAT NEEDS A BUILD STEP.
 *
 * `packages/crypto` and `packages/sdk` ship TypeScript SOURCE on purpose: their
 * consumers are bundlers, and a build artefact would put a compiled copy of the
 * highest-severity code in the project between the reader and what runs. This
 * package's consumer is `node`, which cannot load a `.ts` file from
 * `node_modules`, so the same choice would ship a binary that does not start.
 *
 * WHAT IS BUNDLED AND WHAT IS NOT. `@sluice/crypto`, `@sluice/sdk` and their
 * `@noble` dependencies are workspace source and are inlined, because that is
 * the only way this file becomes runnable JavaScript. `convex` and every
 * `node:` built-in stay external: `convex` is a published package with its own
 * resolution and platform conditions, and inlining it would freeze a copy of
 * somebody else's client into this artefact.
 *
 * Vite is already a devDependency at the workspace root, so this adds no new
 * dependency to the project. It adds one to this package's build, which is a
 * cost, and it is the smallest one available that produces a binary that runs.
 */
export default defineConfig({
  build: {
    ssr: "src/cli-entry.ts",
    outDir: "dist",
    emptyOutDir: true,
    target: "node20",
    minify: false,
    sourcemap: false,
    rollupOptions: {
      // `convex/browser` and `convex/server` are separate entry points on that
      // package, so the bare name is not enough to match them.
      external: [/^node:/, /^convex(\/.*)?$/],
      output: { entryFileNames: "sluice.js", format: "esm" },
    },
  },
});
