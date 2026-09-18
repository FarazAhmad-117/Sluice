import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";
import type { Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { THEME_BOOT_SCRIPT } from "./src/lib/theme-storage.ts";

const here = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

/**
 * WHY THIS FILE HUNTS FOR THE CONVEX URL BY HAND.
 *
 * `npx convex dev` writes `CONVEX_URL` into the REPOSITORY ROOT `.env.local`.
 * Vite reads env files from THIS directory and only exposes a variable to the
 * browser when its name starts with `VITE_`, so the value the CLI wrote is
 * invisible twice over: wrong directory and wrong prefix.
 *
 * The failure that costs an afternoon is that nothing errors. The build
 * succeeds, the shell renders, and the first Convex call rejects at runtime
 * with a message about an undefined deployment URL. So the bridge is built
 * here, once, and `src/lib/convex-url.ts` turns a missing value into a visible
 * sentence on the page rather than a rejected promise nobody awaited.
 *
 * PRECEDENCE, highest first:
 *   1. `VITE_CONVEX_URL` in the process environment.
 *   2. `CONVEX_URL` in the process environment (CI, Vercel, Netlify).
 *   3. either name in this directory's env files for the active mode.
 *   4. either name in the repository root's env files for the active mode.
 *
 * `loadEnv` rather than a hand-rolled parser, because it already implements
 * the whole `.env` / `.env.local` / `.env.<mode>` / `.env.<mode>.local`
 * precedence ladder, and a second implementation of that ladder would disagree
 * with the first one eventually. The `""` prefix is what lets it see the
 * unprefixed `CONVEX_URL`; nothing it returns is exposed to the browser except
 * the single value defined below.
 *
 * The value is INLINED INTO THE CLIENT BUNDLE, which is correct and is not a
 * leak: a Convex deployment URL is a public address, the same one every
 * browser must dial. Nothing secret may ever be added to `define`.
 */
function readConvexUrl(mode: string): string | undefined {
  const candidates: Array<string | undefined> = [
    process.env.VITE_CONVEX_URL,
    process.env.CONVEX_URL,
  ];

  for (const dir of [here, repoRoot]) {
    const env = loadEnv(mode, dir, "");
    candidates.push(env.VITE_CONVEX_URL, env.CONVEX_URL);
  }

  for (const candidate of candidates) {
    const value = candidate?.trim();
    // The literal string "undefined" is a real value that reaches here: it is
    // what a shell writes when it interpolates an unset variable. Treating it
    // as configured means dialing a host that does not exist.
    if (value !== undefined && value.length > 0 && value !== "undefined") return value;
  }
  return undefined;
}

/**
 * Puts the pre-paint theme script into `<head>`, built from the same constant
 * `lib/theme.tsx` reads. See `lib/theme-storage.ts` for why it is not a
 * literal in `index.html`.
 *
 * `injectTo: "head-prepend"` so it runs before the stylesheet and before the
 * module preload, which is the only position at which it is still ahead of the
 * first paint.
 */
function themeBootScript(): Plugin {
  return {
    name: "sluice-theme-boot-script",
    transformIndexHtml() {
      return [
        {
          tag: "script",
          attrs: { "data-sluice": "theme-boot" },
          children: THEME_BOOT_SCRIPT,
          injectTo: "head-prepend",
        },
      ];
    },
  };
}

export default defineConfig(({ mode }) => {
  const convexUrl = readConvexUrl(mode);

  return {
    plugins: [react(), tailwindcss(), themeBootScript()],

    resolve: {
      alias: {
        "@": fileURLToPath(new URL("./src", import.meta.url)),
        // The Convex codegen output lives at the repository root, beside the
        // functions it describes, and is imported by the same `@convex/*`
        // specifier the Next application used. Keeping the specifier identical
        // is what made moving these files a rename rather than a rewrite.
        "@convex": fileURLToPath(new URL("../../convex", import.meta.url)),
      },
    },

    /**
     * `@sluice/crypto` publishes TypeScript SOURCE (`"main": "./src/index.ts"`)
     * rather than a build artefact, deliberately: an audited crypto package
     * that shipped a compiled bundle would be one whose reviewed code and
     * shipped code are different files.
     *
     * pnpm links it, so Vite already treats it as source and compiles it
     * instead of pre-bundling it. It is named here anyway, because the day
     * somebody runs this app against a non-linked copy of the package, the
     * optimizer would otherwise hand esbuild a directory of `.ts` files it has
     * been told to treat as a published dependency.
     */
    optimizeDeps: { exclude: ["@sluice/crypto"] },

    // The key derivation worker is `new Worker(new URL(...), { type: "module" })`.
    // Rollup must emit it as an ES module for that to survive a build; the
    // default `iife` format cannot carry the static imports inside it.
    worker: { format: "es" },

    // Only defined when a value was actually found. Defining `undefined` here
    // writes the literal text `undefined` into the bundle, which reads as a
    // configured value and then dials a host that does not exist.
    ...(convexUrl === undefined
      ? {}
      : { define: { "import.meta.env.VITE_CONVEX_URL": JSON.stringify(convexUrl) } }),

    /**
     * NOT 5173, AND NOT BECAUSE OF THE MARKETING SITE.
     *
     * 5173 is Vite's default, so it is the port every other Vite project on the
     * machine also asks for, and the first one started wins it. `strictPort` is
     * meant to turn that into a startup error rather than a silent move to
     * 5174 -- but it does not catch the case that actually happens here. A
     * server already holding `127.0.0.1:5173` does not stop this one binding
     * `[::1]:5173`: different address family, no conflict, no error, and
     * `http://localhost:5173` resolves to the IPv4 one. The developer then
     * reads somebody else's application and believes it is this one. That was
     * observed on this machine, not reasoned about.
     *
     * A port nothing else defaults to removes the collision instead of trying
     * to detect it. `strictPort` stays on for the ordinary case.
     */
    server: { port: 5180, strictPort: true },
    preview: { port: 5180, strictPort: true },

    build: {
      // Every browser this ships to supports modules, `import.meta` and top
      // level await. Naming the floor stops esbuild from quietly transpiling
      // the crypto package down to something slower than what was measured.
      target: "es2022",
      sourcemap: true,
    },
  };
});
