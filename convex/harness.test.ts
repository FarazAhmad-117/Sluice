import { describe, expect, it } from "vitest";
import { convexTest } from "convex-test";
import schema from "./schema";
import { getUser, insertUser } from "./repo/users";

/**
 * `convex-test` needs an explicit module map because vitest does not know
 * which files Convex would push. `import.meta.glob` is evaluated by vite at
 * transform time, so this has to be a literal pattern rather than a variable.
 */
export const modules = import.meta.glob("./**/*.ts");

/**
 * Task 4: prove the harness runs one round trip before anything is built on
 * it. A harness that silently does nothing would make every later test in this
 * milestone pass vacuously.
 *
 * The seeding goes through `repo/users.ts` rather than through the database
 * handle on the context, which is the idiom the convex-test documentation
 * shows. `repo/repo.test.ts` scans test files too, so that idiom would fail
 * the build. It is deliberate: a fixture that inserts through the real path
 * also proves the real path works.
 *
 * Note that the scan is a grep over source text, so it catches a comment that
 * merely quotes the forbidden expression. That is not a false positive worth
 * suppressing; it is the reason this paragraph is worded the long way round.
 */
describe("convex-test harness", () => {
  it("round trips a row through the repo layer", async () => {
    const t = convexTest(schema, modules);

    const id = await t.run(async (ctx) =>
      insertUser(ctx, {
        email: "harness@example.test",
        authVerifierHash: "hash",
        publicKey: "00",
        verifyKey: "01",
        wrappedPrivateKey: "02",
        wrappedSigningKey: "03",
      }),
    );

    const stored = await t.run(async (ctx) => getUser(ctx, id));

    expect(stored).not.toBeNull();
    expect(stored?.email).toBe("harness@example.test");
  });

  it("starts from an empty database in each test", async () => {
    const t = convexTest(schema, modules);
    const found = await t.run(async (ctx) => getUser(ctx, "nonexistent" as never));
    expect(found).toBeNull();
  });
});
