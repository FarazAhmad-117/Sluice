import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * RULES THIS PACKAGE CANNOT EXPRESS IN ITS TYPES, CHECKED BY READING ITS OWN
 * SOURCE.
 *
 * `convex/repo/repo.test.ts` does the same thing for the same reason. Some
 * invariants are about where code is allowed to appear, and a type system has
 * nothing to say about that. The alternative is a convention in a document,
 * which is a convention nobody runs.
 */

const SRC = fileURLToPath(new URL("../src", import.meta.url));

function sources(): { name: string; text: string }[] {
  return readdirSync(SRC)
    .filter((name) => name.endsWith(".ts"))
    .map((name) => ({ name, text: readFileSync(join(SRC, name), "utf8") }));
}

describe("the source of this package", () => {
  it("contains no em dash and no en dash anywhere", () => {
    for (const file of sources()) {
      const found = /[\u2013\u2014]/.exec(file.text);
      expect(found === null ? "" : `${file.name}: ${found[0]}`).toBe("");
    }
  });

  it("calls process.exit in exactly one file, the entry point", () => {
    for (const file of sources()) {
      if (file.name === "cli-entry.ts") continue;
      expect(`${file.name} ${String(file.text.includes("process.exit("))}`).toBe(
        `${file.name} false`,
      );
    }
  });

  it("never writes to the console directly", () => {
    for (const file of sources()) {
      expect(`${file.name} ${String(/\bconsole\.(log|error|warn|info|debug)\b/.test(file.text))}`)
        .toBe(`${file.name} false`);
    }
  });

  it("never hands anything cancellable to customer code", () => {
    for (const file of sources()) {
      expect(`${file.name} ${String(/\bAbort(Controller|Signal)\b/.test(file.text))}`).toBe(
        `${file.name} false`,
      );
    }
  });

  it("signals the child from exactly two places, and names both", () => {
    const counted: Record<string, number> = {};
    for (const file of sources()) {
      const hits = file.text.match(/\.signal\(/g);
      if (hits !== null) counted[file.name] = hits.length;
    }
    // Two in `shell.ts`, the SIGTERM and the SIGKILL of `#stopChild`, which is
    // reachable only from `host.exit`. One in `run.ts`, the relay of a signal
    // the operator sent, which originates nothing. `node-runtime.ts` defines
    // the method and does not call it.
    expect(counted).toEqual({ "shell.ts": 2, "run.ts": 1 });
  });

  it("never re-derives an associated data rule by hand", () => {
    // The whole failure class `packages/crypto/src/protocol.ts` exists to
    // close: a hand-copied literal that drifts by one character and produces
    // ciphertext nobody can read, with no error until somebody tries.
    for (const file of sources()) {
      for (const literal of [
        "sluice/secret/v1",
        "sluice/pdk/v1",
        "sluice/token-id/v1",
        "sluice/revocation/v1",
        "sluice/auth/v1",
        "sluice/unwrap/v1",
      ]) {
        expect(`${file.name} ${literal} ${String(file.text.includes(`"${literal}`))}`).toBe(
          `${file.name} ${literal} false`,
        );
      }
    }
  });

  it("decides a shutdown nowhere: every exit comes from a core decision", () => {
    const shell = readFileSync(join(SRC, "shell.ts"), "utf8");
    // `#exit` is the injected terminator and it is called from `#finish` and
    // nowhere else. `#finish` is reached five times: three inside `#stopChild`
    // (no child, the child died on SIGTERM, the child died on SIGKILL), which
    // is `host.exit` and therefore a core decision; and twice inside
    // `#onChildExit`, which is the supervised process ending by itself.
    // Neither of those invents a Sluice shutdown.
    expect(shell.match(/this\.#exit\(/g) ?? []).toHaveLength(1);
    expect(shell.match(/this\.#finish\(/g) ?? []).toHaveLength(5);
  });

  it("puts no secret-bearing field name into a template that could be logged", () => {
    // A cheap guard against the obvious accident: interpolating the thing
    // rather than its name. None of these may appear inside a template string.
    for (const file of sources()) {
      for (const forbidden of [
        "${bundle.secrets",
        "${secrets[",
        "${this.#identity.tokenSecret",
        "${identity.tokenSecret",
        "${identity.unwrapKey",
        "${credential.token",
        "${bundleToken",
        "${pdk",
      ]) {
        expect(`${file.name} ${forbidden} ${String(file.text.includes(forbidden))}`).toBe(
          `${file.name} ${forbidden} false`,
        );
      }
    }
  });
});
