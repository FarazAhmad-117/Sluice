import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

/**
 * `test/` rather than colocated `src/**\/*.test.ts`, so nothing under `src` is
 * both a bundle entry and a test.
 *
 * This is a SEPARATE config from `vite.config.ts` on purpose. These tests are
 * plain Node modules that exercise key derivation, sealing and naming; loading
 * the React and Tailwind plugins to run them would only add startup cost and a
 * JSX transform nothing here needs. Tests reach into `src` by relative path.
 *
 * THE TWO ALIASES ARE RESTATED, not the plugins. Modules under `src` import
 * each other as `@/...` and the Convex codegen and shared error sentences as
 * `@convex/...`, so a test that loads `lib/auth/auth-flows.ts` needs both to
 * resolve exactly as `vite.config.ts` resolves them. They must stay identical
 * to the ones there.
 */
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "@convex": fileURLToPath(new URL("../../convex", import.meta.url)),
    },
  },
  test: { include: ["test/**/*.test.ts"] },
});
