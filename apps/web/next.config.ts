import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /**
   * `@sluice/crypto` publishes TypeScript SOURCE (`"main": "./src/index.ts"`)
   * rather than a build artefact, which is deliberate -- an audited crypto
   * package that shipped a compiled bundle would be one whose reviewed code and
   * shipped code are different files. Next therefore has to compile it, in the
   * main bundle and in the key-derivation worker alike.
   *
   * This pairs with the extensionless relative imports inside that package: see
   * the note at the top of `packages/crypto/src/index.ts`. Turbopack applies
   * strict ESM resolution to a `"type": "module"` package, so `./bytes.js` in a
   * file that is really `bytes.ts` is an unresolvable specifier and no Next
   * config option fixes it -- `experimental.extensionAlias` is webpack-only.
   */
  transpilePackages: ["@sluice/crypto"],
};

export default nextConfig;
