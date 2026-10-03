/**
 * THE RELEASE THIS BUILD IS, AS `package.json` NAMES IT.
 *
 * Substituted at build time (`vite.build.config.ts` for the npm bundle,
 * `scripts/release/build-binaries.mjs` for the standalone executables), so a
 * shipped `sluice --version` names the release a bug report is about. Run
 * from source, nothing substitutes it and it reads "dev".
 */
declare const __SLUICE_RELEASE__: string | undefined;

export const RELEASE: string = typeof __SLUICE_RELEASE__ === "string" ? __SLUICE_RELEASE__ : "dev";
