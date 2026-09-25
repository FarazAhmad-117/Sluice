#!/usr/bin/env node
// The published entry point. Three lines on top of `dist/sluice.js`, which is
// the bundle `pnpm --filter @sluice/cli build` produces. See
// `vite.build.config.ts` for why this package builds and the others do not.
import "../dist/sluice.js";
