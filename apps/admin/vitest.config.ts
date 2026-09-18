import { defineConfig } from "vitest/config";

/**
 * `test/` rather than colocated `src/**\/*.test.ts`, so nothing under `src` is
 * both a bundle entry and a test.
 *
 * This is a SEPARATE config from `vite.config.ts` on purpose. These tests are
 * plain Node modules that exercise key derivation, sealing and naming; loading
 * the React and Tailwind plugins to run them would only add startup cost and a
 * JSX transform nothing here needs. They reach into `src` by relative path for
 * the same reason, so no alias resolution has to be duplicated.
 */
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
