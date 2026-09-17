import { defineConfig } from "vitest/config";

/**
 * `apps/web` has tests for one reason: it owns the WASM Argon2 backend, and the
 * cross-backend agreement test cannot live in `packages/crypto`, which
 * deliberately has no WASM dependency.
 *
 * `test/` rather than colocated `src/**\/*.test.ts`, so nothing under `src` is
 * both a Next module graph entry and a test.
 */
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
