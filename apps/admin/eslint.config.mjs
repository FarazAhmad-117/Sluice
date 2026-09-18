import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";
import { defineConfig, globalIgnores } from "eslint/config";

/**
 * The Next application gets its rules from `eslint-config-next`, which is not
 * available to a Vite build. This is the equivalent set: the TypeScript rules,
 * the rules of hooks, and the Fast Refresh rule that catches a module exporting
 * a component alongside something else.
 *
 * `reactHooks.configs.recommended` is what enforces the dependency arrays that
 * several files in `lib/` argue about at length in their comments. It is not
 * relaxed anywhere, and the two suppressions in the tree are written with the
 * reason beside them.
 */
export default defineConfig([
  globalIgnores(["dist/**"]),
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
    },
  },
  {
    /**
     * THE FAST REFRESH RULE IS OFF UNDER `src/lib`, AND ONLY THERE.
     *
     * These modules export a provider component beside the hook that reads it:
     * `AuthProvider` with `useAuth`, `ThemeProvider` with `useTheme`,
     * `ConvexClientProvider` with the client itself. That pairing is the whole
     * point of a context module, and splitting each one into two files to
     * satisfy a heuristic would scatter three tightly coupled pairs across six
     * files for no reader's benefit.
     *
     * The cost is real and small: editing one of these four files remounts the
     * tree instead of patching it, which drops the in-memory vault and asks for
     * the password again. They are also the four files in this application that
     * are edited least.
     *
     * It stays ON everywhere else, where it catches the accidental version of
     * the same mistake -- a route or a component file that grew a helper
     * export. `lib/redirect.ts` exists because of exactly that.
     */
    files: ["src/lib/**/*.{ts,tsx}"],
    rules: { "react-refresh/only-export-components": "off" },
  },
  {
    // The build and test configs run in Node, not in a browser, and the worker
    // runs in neither.
    files: ["vite.config.ts", "vitest.config.ts", "test/**/*.ts"],
    languageOptions: { globals: globals.node },
  },
  {
    files: ["src/lib/crypto/muk.worker.ts"],
    languageOptions: { globals: globals.worker },
  },
]);
