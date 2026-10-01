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

/**
 * Any hand-written domain label owned by `@sluice/crypto`, at any version.
 * Built from split strings so this file, which has to describe the pattern,
 * cannot match it -- harmless today because only `src/` is scanned, but it
 * keeps the rule correct if the scan ever widens to `test/`.
 */
const OWNED_LABEL = new RegExp(
  "sluice" +
    "/(secret|pdk|revocation-key|revocation|user-key|token-id|auth|unwrap|auth-verifier|muk-salt|argon2-conformance)/v" +
    "\\d",
);

/**
 * The same domains, written out separately so the self-test is not merely the
 * pattern checked against itself: dropping a name from either list fails it.
 * NOTHING CHECKS THIS LIST AGAINST THE CRYPTO SOURCE. `convex/lib/protocol.test.ts`
 * keeps its own copy of the same list and checks THAT copy for exact equality
 * with every label `packages/crypto/src` defines; this one is not covered by
 * that check, so a label added to the crypto package must be added here by
 * hand as well.
 */
const OWNED_DOMAINS = [
  "secret",
  "pdk",
  "revocation-key",
  "revocation",
  "user-key",
  "token-id",
  "auth",
  "unwrap",
  "auth-verifier",
  "muk-salt",
  "argon2-conformance",
];

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
    // reachable only from `host.exit`. Two in `run.ts`: the relay of a signal
    // the operator sent, which originates nothing, and the SIGKILL in
    // `fatalHandler`, reachable only from an uncaught exception or unhandled
    // rejection on its way to an exit, which exists so the supervisor can never
    // die leaving the child running. Neither is a Sluice decision.
    // `node-runtime.ts` defines the method and does not call it.
    expect(counted).toEqual({ "shell.ts": 2, "run.ts": 2 });
  });

  it("never re-derives an associated data rule or a domain label by hand", () => {
    // The whole failure class `packages/crypto/src/protocol.ts` exists to
    // close: a hand-copied literal that drifts by one character and produces
    // ciphertext nobody can read, with no error until somebody tries.
    //
    // Version-agnostic: a copy written today would spell the current version,
    // a stale copy an old one, and a future version is banned before it
    // exists. Every label here belongs to `@sluice/crypto` and is reached only
    // through its functions.
    for (const file of sources()) {
      const found = OWNED_LABEL.exec(file.text);
      expect(found === null ? `${file.name} clean` : `${file.name}: ${found[0]}`).toBe(
        `${file.name} clean`,
      );
    }
  });

  it("bans the labels it means to, at any version", () => {
    for (const domain of OWNED_DOMAINS) {
      for (const version of ["1", "2", "9"]) {
        const spelled = `${"sluice"}/${domain}/v${version}|`;
        expect(`${spelled} ${String(OWNED_LABEL.test(spelled))}`).toBe(`${spelled} true`);
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
