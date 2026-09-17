import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Resolved from this file rather than from process.cwd(), so the test means the
// same thing whether vitest is run from the repository root or from an editor.
const convexRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Every extension Convex will push as a module. Scanning only `.ts` would let
// a `.js` file sitting next to a `.ts` one run against the database unscanned.
const SOURCE = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

// Exempt by exact path, not by directory name. Matching on the name alone
// would also exempt `convex/anything/repo/`, which is not this layer.
const EXEMPT = new Set(
  ["_generated", "repo"].map((d) => resolve(convexRoot, d)),
);

/**
 * Every source file under `convex/` except the two directories that are
 * allowed to touch the database: `_generated/`, which Convex writes and which
 * defines `ctx.db` in the first place, and `repo/`, which is the point of the
 * rule.
 */
function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (!EXEMPT.has(resolve(full))) walk(full, out);
    } else if (SOURCE.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

/**
 * A plain `includes("ctx.db")` was the sketch, and it is defeatable by writing
 * idiomatic JavaScript rather than by trying: `const { db } = ctx` reaches the
 * database without the string `ctx.db` appearing anywhere. That is an accident
 * waiting to happen, not an attack, which is why it is worth closing. Indexed
 * access is covered for the same reason.
 *
 * What is NOT covered, and cannot be by grep: a non-repo file that takes a
 * `db` handle as a parameter. Whoever passed it had to reach it through one of
 * the forms below, so the caller is caught even when the callee is not.
 */
const REACHES_DB: RegExp[] = [
  /\bctx\s*\.\s*db\b/,
  /\bctx\s*\[\s*["']db["']\s*\]/,
  /\{[^{}]*\bdb\b[^{}]*\}\s*=\s*ctx\b/,
];

describe("repo discipline", () => {
  it("is the only place that touches ctx.db", () => {
    const offenders = walk(convexRoot)
      .filter((f) => {
        const source = readFileSync(f, "utf8");
        return REACHES_DB.some((pattern) => pattern.test(source));
      })
      .map((f) => relative(convexRoot, f).split("\\").join("/"));

    expect(offenders).toEqual([]);
  });

  // Guards the guard. If `walk` ever stops finding files, for example because a
  // path assumption breaks on another platform, the assertion above passes
  // vacuously and the discipline silently stops being enforced.
  it("actually reads files outside repo/", () => {
    expect(walk(convexRoot).length).toBeGreaterThan(0);
  });
});
