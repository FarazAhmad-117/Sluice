# Phase 1: Freeze the Protocol — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make every value that becomes permanent at the first real signup portable and final: stable IDs, `v2` encryption bindings, a random account salt, and the dashboard's invented constants moved into `@sluice/crypto`.

**Architecture:** Clients mint permanent IDs (`org_…`, `usr_…`, `env_…`) before calling a creation mutation, so every encryption binding can name the thing it belongs to, which `v1` could not because Convex mints document IDs on insert. `v2` replaces `v1` outright: no real user data exists, so there is no dual-read path and no migration. Every renamed parameter makes each stale call site a compile error, which is how nothing is missed.

**Tech Stack:** TypeScript, `@noble/hashes`, Convex + `convex-test`, Vitest, React (dashboard), pnpm workspaces.

**Design reference:** `docs/plans/2026-09-30-sluice-architecture-design.md`, sections 13 (stable IDs) and 15 (change 3). Background on the account salt: `docs/plans/2026-09-17-sluice-backend.md`, "Decided 2026-09-18".

---

## Ground rules for whoever executes this

- **Known-answer vectors below were computed with `node:crypto` and `hash-wasm`, never with `@sluice/crypto`.** Paste them verbatim. If a test disagrees with a vector, the implementation is wrong, not the vector.
- **Run the whole workspace after every task:** `pnpm test:all` and `pnpm typecheck:all` from the repo root. `pnpm -r` alone skips the root workspace, which is where the Convex tests live.
- **Comments in this codebase explain why, at length.** When you rewrite a function, rewrite its header comment to match the new construction. A stale comment on a crypto binding is a defect.
- **Commit after every task** with the attribution line:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`

## The vectors

```
ENV                env_000102030405060708090a0b0c0d0e0f
USR                usr_101112131415161718191a1b1c1d1e1f
ORG                org_202122232425262728292a2b2c2d2e2f
TOKEN_ID_HASH      305ab71526b2c39b5c8daf6ec97b91af98247937c858f4fd3ee4cf1e8d97fcd9   (existing v1 KAT, unchanged)

secret AAD         736c756963652f7365637265742f76327c656e765f3030303130323033303430353036303730383039306130623063306430653066
pdk AAD, user      736c756963652f70646b2f76327c656e765f30303031303230333034303530363037303830393061306230633064306530667c757365727c7573725f3130313131323133313431353136313731383139316131623163316431653166
pdk AAD, token     736c756963652f70646b2f76327c656e765f30303031303230333034303530363037303830393061306230633064306530667c746f6b656e7c33303561623731353236623263333962356338646166366563393762393161663938323437393337633835386634666433656534636631653864393766636439
revocation AAD     736c756963652f7265766f636174696f6e2d6b65792f76327c6f72675f32303231323232333234323532363237323832393261326232633264326532667c7573725f3130313131323133313431353136313731383139316131623163316431653166

account salt       303132333435363738393a3b3c3d3e3f                                   (bytes 0x30..0x3f)
MUK salt v2        d32869c2b87cf09ad74dfeb60122cde4bf220d5c0f39e357b4e157d06d5950f3   sha256("sluice/muk-salt/v2" || account salt)
MUK v2             633977bb9b6fec724f6574028da06c834895735198e653c3f8a95cb28d70436c   Argon2id("correct horse battery staple, v2", MUK salt v2, m=65536 t=3 p=4 dkLen=32)

user key AAD x25519   736c756963652f757365722d6b65792f76317c783235353139
user key AAD ed25519  736c756963652f757365722d6b65792f76317c65643235353139
auth verifier         0abfe45dead6265934bc56753b7cd9f2f782e9f801e7279e4a5451453bcbff61   HMAC-SHA256(key = bytes 0x00..0x1f, "sluice/auth-verifier/v1")
decoy salt            3cdb14ca8f79ef0ce835b15f0cba7674   HMAC-SHA256(key = 32 bytes of 0xab, "sluice/decoy-salt/v1|nobody@example.com")[0..16]
```

---

### Task 0: Prepare

**Step 1: Branch.**

```bash
git checkout -b phase-1-freeze-protocol
```

**Step 2: Clear the dev Convex deployment. USER ACTION.**

The schema gains required fields. Convex refuses to push a schema that existing documents violate, and every existing document is test data. In the Convex dashboard for the dev deployment: **Data → each table → Clear table**, for every table.

Do not do this against any deployment holding real users. There is none today; confirm that before clearing.

**Step 3: Record the baseline.**

```bash
pnpm test:all 2>&1 | tail -5
pnpm typecheck:all 2>&1 | tail -5
```

Expected: all green. Note the test count; it is the floor for the end of the phase.

---

### Task 1: Stable IDs in `@sluice/crypto`

**Files:**
- Create: `packages/crypto/src/ids.ts`
- Test: `packages/crypto/test/ids.test.ts`

**Step 1: Write the failing test.**

```ts
// packages/crypto/test/ids.test.ts
import { describe, expect, it } from "vitest";
import { assertId, newId } from "../src/ids";

describe("newId", () => {
  it.each(["org", "usr", "env"] as const)("mints a %s id in the one canonical shape", (kind) => {
    expect(newId(kind)).toMatch(new RegExp(`^${kind}_[0-9a-f]{32}$`));
  });

  it("never repeats across a large sample", () => {
    const seen = new Set(Array.from({ length: 10_000 }, () => newId("env")));
    expect(seen.size).toBe(10_000);
  });
});

describe("assertId", () => {
  it("returns a well-formed id unchanged", () => {
    const id = "env_000102030405060708090a0b0c0d0e0f";
    expect(assertId("env", "environmentUid", id)).toBe(id);
  });

  /**
   * THE REASON THE PREFIX EXISTS. A user id passed where an environment id is
   * expected must fail at the call, not produce well-formed associated data
   * for the wrong thing.
   */
  it("rejects an id of another kind", () => {
    expect(() =>
      assertId("env", "environmentUid", "usr_101112131415161718191a1b1c1d1e1f"),
    ).toThrow("environmentUid must be an env id");
  });

  /**
   * THE REASON THIS PHASE EXISTS. A Convex document id is deployment-local and
   * changes when an org moves cells. It must never reach an encryption binding.
   */
  it("rejects a Convex document id", () => {
    expect(() => assertId("env", "environmentUid", "k17dn9q2x4m8p3v6b0zc5t7wgh")).toThrow();
  });

  it.each([
    ["uppercase hex", "env_000102030405060708090A0B0C0D0E0F"],
    ["short", "env_0001020304050607"],
    ["long", "env_000102030405060708090a0b0c0d0e0f00"],
    ["empty", ""],
    ["no separator", "env000102030405060708090a0b0c0d0e0f"],
    ["trailing newline", "env_000102030405060708090a0b0c0d0e0f\n"],
  ])("rejects %s", (_label, value) => {
    expect(() => assertId("env", "environmentUid", value)).toThrow();
  });

  it("rejects a non-string without echoing it", () => {
    expect(() => assertId("env", "environmentUid", 42 as unknown as string)).toThrow(
      "environmentUid must be an env id",
    );
  });
});
```

**Step 2: Run it and watch it fail.**

```bash
pnpm --filter @sluice/crypto test -- ids
```

Expected: FAIL, cannot resolve `../src/ids`.

**Step 3: Implement.**

```ts
// packages/crypto/src/ids.ts
import { randomBytes, toHex } from "./bytes";

/**
 * PERMANENT IDENTIFIERS, MINTED BY THE CLIENT.
 *
 * Every org, user and environment carries one of these alongside its Convex
 * document id, and every encryption binding and external reference uses THIS,
 * never the document id. Two reasons, both load bearing:
 *
 * 1. PORTABILITY. A Convex document id is local to one deployment. Moving an
 *    org to another cell re-mints every id it owns. Ciphertext bound to the old
 *    ids would stop opening, and no server could fix it, because no server holds
 *    a key. These ids travel with the rows unchanged.
 *
 * 2. ORDERING. Convex mints document ids on insert, after the client has
 *    already wrapped the keys a creation mutation takes. These ids exist BEFORE
 *    the mutation, so a wrap can bind the environment or org it belongs to,
 *    which the v1 constructions documented as impossible.
 *
 * THE KIND IS IN THE ID. `usr_…` passed where `env_…` is expected fails here,
 * at the call, instead of producing well-formed associated data for the wrong
 * thing. A Convex document id fails too, which is what stops one sneaking back
 * into a binding.
 *
 * 128 random bits, lowercase hex. Uniqueness is enforced again by the server's
 * `by_uid` index; the entropy makes a collision a bug rather than an event.
 */
export type IdKind = "org" | "usr" | "env";

const ID_BYTES = 16;

const PATTERNS: Readonly<Record<IdKind, RegExp>> = Object.freeze({
  org: /^org_[0-9a-f]{32}$/,
  usr: /^usr_[0-9a-f]{32}$/,
  env: /^env_[0-9a-f]{32}$/,
});

export function newId(kind: IdKind): string {
  return `${kind}_${toHex(randomBytes(ID_BYTES))}`;
}

/**
 * Checks shape and kind. The value is never echoed: an id is not a secret, but
 * this guard runs on the path into associated data, and the rest of this
 * package refuses to print its inputs on principle.
 */
export function assertId(kind: IdKind, field: string, value: string): string {
  if (typeof value !== "string" || !PATTERNS[kind].test(value)) {
    throw new Error(`${field} must be an ${kind} id`);
  }
  return value;
}
```

**Step 4: Run it and watch it pass.**

```bash
pnpm --filter @sluice/crypto test -- ids
```

Expected: PASS.

**Step 5: Commit.**

```bash
git add packages/crypto/src/ids.ts packages/crypto/test/ids.test.ts
git commit -m "Mint permanent ids on the client so bindings survive a cell move"
```

---

### Task 2: `v2` encryption bindings

**Files:**
- Modify: `packages/crypto/src/protocol.ts` (the three associated-data functions, their prefixes, and their header comments)
- Modify: `packages/crypto/test/protocol.test.ts`
- Modify: `convex/lib/protocol.test.ts` (it pins the v1 secret AAD)

**Step 1: Replace the v1 tests with v2 tests.**

In `packages/crypto/test/protocol.test.ts`, delete the `KAT_ENVIRONMENT_ID`, `KAT_AAD_BYTES` and `KAT_AAD_HEX` constants and every `describe` for the three AAD functions. Keep every `tokenIdHash` test unchanged. Add:

```ts
const ENV = "env_000102030405060708090a0b0c0d0e0f";
const USR = "usr_101112131415161718191a1b1c1d1e1f";
const ORG = "org_202122232425262728292a2b2c2d2e2f";
const TOKEN_HASH = "305ab71526b2c39b5c8daf6ec97b91af98247937c858f4fd3ee4cf1e8d97fcd9";

// Computed with node:crypto, never with this package. See the plan's vector table.
const SECRET_AAD =
  "736c756963652f7365637265742f76327c656e765f3030303130323033303430353036303730383039306130623063306430653066";
const PDK_AAD_USER =
  "736c756963652f70646b2f76327c656e765f30303031303230333034303530363037303830393061306230633064306530667c757365727c7573725f3130313131323133313431353136313731383139316131623163316431653166";
const PDK_AAD_TOKEN =
  "736c756963652f70646b2f76327c656e765f30303031303230333034303530363037303830393061306230633064306530667c746f6b656e7c33303561623731353236623263333962356338646166366563393762393161663938323437393337633835386634666433656534636631653864393766636439";
const REVOCATION_AAD =
  "736c756963652f7265766f636174696f6e2d6b65792f76327c6f72675f32303231323232333234323532363237323832393261326232633264326532667c7573725f3130313131323133313431353136313731383139316131623163316431653166";

describe("secretAssociatedData v2", () => {
  it("matches the independent vector", () => {
    expect(toHex(secretAssociatedData({ environmentUid: ENV }))).toBe(SECRET_AAD);
  });
  it("rejects a Convex document id", () => {
    expect(() => secretAssociatedData({ environmentUid: "k17dn9q2x4m8p3v6b0zc5t7wgh" })).toThrow();
  });
  it("rejects a user id in the environment slot", () => {
    expect(() => secretAssociatedData({ environmentUid: USR })).toThrow();
  });
});

describe("pdkAssociatedData v2", () => {
  it("binds environment and user grantee", () => {
    expect(
      toHex(pdkAssociatedData({ environmentUid: ENV, granteeType: "user", granteeId: USR })),
    ).toBe(PDK_AAD_USER);
  });
  it("binds environment and token grantee", () => {
    expect(
      toHex(pdkAssociatedData({ environmentUid: ENV, granteeType: "token", granteeId: TOKEN_HASH })),
    ).toBe(PDK_AAD_TOKEN);
  });
  it("differs across environments for the same grantee", () => {
    const other = "env_ffffffffffffffffffffffffffffffff";
    expect(
      toHex(pdkAssociatedData({ environmentUid: other, granteeType: "user", granteeId: USR })),
    ).not.toBe(PDK_AAD_USER);
  });
  it("rejects a token hash as a user grantee", () => {
    expect(() =>
      pdkAssociatedData({ environmentUid: ENV, granteeType: "user", granteeId: TOKEN_HASH }),
    ).toThrow();
  });
  it("rejects a user id as a token grantee", () => {
    expect(() =>
      pdkAssociatedData({ environmentUid: ENV, granteeType: "token", granteeId: USR }),
    ).toThrow();
  });
  it("rejects an unknown grantee type", () => {
    expect(() =>
      pdkAssociatedData({
        environmentUid: ENV,
        granteeType: "tokens" as "token",
        granteeId: TOKEN_HASH,
      }),
    ).toThrow();
  });
});

describe("revocationKeyAssociatedData v2", () => {
  it("binds org and grantee", () => {
    expect(toHex(revocationKeyAssociatedData({ orgUid: ORG, granteeUid: USR }))).toBe(
      REVOCATION_AAD,
    );
  });
  it("rejects swapped arguments", () => {
    expect(() => revocationKeyAssociatedData({ orgUid: USR, granteeUid: ORG })).toThrow();
  });
});

describe("no two constructions share bytes", () => {
  it("every v2 vector is distinct and none is a prefix of another", () => {
    const all = [SECRET_AAD, PDK_AAD_USER, PDK_AAD_TOKEN, REVOCATION_AAD];
    expect(new Set(all).size).toBe(all.length);
    for (const a of all) for (const b of all) if (a !== b) expect(b.startsWith(a)).toBe(false);
  });
});
```

In `convex/lib/protocol.test.ts`, replace every `secretAssociatedData({ environmentId: … })` with `secretAssociatedData({ environmentUid: "env_000102030405060708090a0b0c0d0e0f" })`, and replace the pinned v1 hex with the v2 secret AAD vector above. Delete cases that only made sense for free-form ids (lone surrogates, spaces): `assertId` now rejects everything outside the canonical shape, which is strictly tighter.

**Step 2: Run and watch it fail.**

```bash
pnpm --filter @sluice/crypto test -- protocol
```

Expected: FAIL on every v2 case (`environmentUid` is not a known field; labels still say v1).

**Step 3: Implement.** In `packages/crypto/src/protocol.ts`:

```ts
import { assertId } from "./ids";

const SECRET_AAD_PREFIX = "sluice/secret/v2|";
const PDK_AAD_PREFIX = "sluice/pdk/v2|";
const REVOCATION_KEY_AAD_PREFIX = "sluice/revocation-key/v2|";

/** A tokenIdHash: sha256 output, lowercase hex. */
const TOKEN_HASH_PATTERN = /^[0-9a-f]{64}$/;

export function secretAssociatedData(params: { environmentUid: string }): Uint8Array {
  const environmentUid = assertId("env", "environmentUid", params.environmentUid);
  return utf8.encode(SECRET_AAD_PREFIX + environmentUid);
}

export function pdkAssociatedData(params: {
  environmentUid: string;
  granteeType: PDKGranteeType;
  granteeId: string;
}): Uint8Array {
  const environmentUid = assertId("env", "environmentUid", params.environmentUid);
  const { granteeType } = params;
  if (typeof granteeType !== "string" || !GRANTEE_TYPES.includes(granteeType)) {
    throw new Error(`granteeType must be one of ${GRANTEE_TYPES.join(", ")}`);
  }
  // Each namespace has its own exact shape, so a value from one can never be
  // accepted in the other. v1 separated them only by the type column.
  const granteeId =
    granteeType === "user"
      ? assertId("usr", "granteeId", params.granteeId)
      : assertTokenHash(params.granteeId);
  return utf8.encode(
    PDK_AAD_PREFIX + environmentUid + SEPARATOR + granteeType + SEPARATOR + granteeId,
  );
}

export function revocationKeyAssociatedData(params: {
  orgUid: string;
  granteeUid: string;
}): Uint8Array {
  const orgUid = assertId("org", "orgUid", params.orgUid);
  const granteeUid = assertId("usr", "granteeUid", params.granteeUid);
  return utf8.encode(REVOCATION_KEY_AAD_PREFIX + orgUid + SEPARATOR + granteeUid);
}

function assertTokenHash(value: string): string {
  if (typeof value !== "string" || !TOKEN_HASH_PATTERN.test(value)) {
    throw new Error("granteeId must be a token id hash");
  }
  return value;
}
```

Delete `IDENTIFIER_FORBIDDEN` and `assertIdentifier`; nothing uses them now.

**Rewrite the three header comments.** Keep the arguments that still hold (why the version is inside the AAD, why arguments are objects, why nothing is fetched from a server). Replace both "WHY THE ENVIRONMENT/ORG ID IS NOT IN HERE … MUST NOT ADD" sections with the reverse: v1 could not bind them because Convex mints ids on insert; v2 ids exist before the mutation, so v2 binds them, and a grant or revocation-key blob copied into another environment's or org's row now fails to open. The `revocationKeyMatches` check in the dashboard stays: the AAD still cannot bind `orgs.revocationPublicKey`.

**Step 4: Run and watch it pass.**

```bash
pnpm --filter @sluice/crypto test
```

Expected: PASS. `pnpm typecheck:all` now FAILS at every caller of the three functions. That is intended: those failures are the checklist for Tasks 8 to 13. Do not fix them yet.

**Step 5: Commit.**

```bash
git add packages/crypto convex/lib/protocol.test.ts
git commit -m "Bind grants to their environment and revocation keys to their org"
```

---

### Task 3: Random account salt

**Files:**
- Modify: `packages/crypto/src/muk.ts`
- Modify: `packages/crypto/test/muk.test.ts`

**Step 1: Replace the v1 MUK tests.**

Delete the v1 known-answer MUK test and its constants in `muk.test.ts`; keep every parameter, freezing, redaction and backend-conformance test. Add:

```ts
import { fromHex, toHex } from "../src/bytes";
import { ACCOUNT_SALT_BYTES, deriveMUK, newAccountSalt } from "../src/muk";

const ACCOUNT_SALT = fromHex("303132333435363738393a3b3c3d3e3f");
// hash-wasm Argon2id over the v2 salt; independent of @noble/hashes.
const KAT_MUK_V2 = "633977bb9b6fec724f6574028da06c834895735198e653c3f8a95cb28d70436c";

describe("deriveMUK v2", () => {
  it("matches the independent vector", async () => {
    const muk = await deriveMUK("correct horse battery staple, v2", ACCOUNT_SALT);
    expect(toHex(muk.bytes)).toBe(KAT_MUK_V2);
  }, 60_000);

  it("rejects a salt of the wrong width before doing any work", async () => {
    await expect(deriveMUK("pw", new Uint8Array(15))).rejects.toThrow(
      `accountSalt must be ${ACCOUNT_SALT_BYTES} bytes`,
    );
  });

  it("rejects a string where bytes belong", async () => {
    await expect(deriveMUK("pw", "user@example.com" as unknown as Uint8Array)).rejects.toThrow();
  });
});

describe("newAccountSalt", () => {
  it("is 16 random bytes", () => {
    expect(newAccountSalt()).toHaveLength(16);
    expect(toHex(newAccountSalt())).not.toBe(toHex(newAccountSalt()));
  });
});
```

**Step 2: Run and watch it fail.**

```bash
pnpm --filter @sluice/crypto test -- muk
```

Expected: FAIL (`newAccountSalt` missing; `deriveMUK` still takes a string).

**Step 3: Implement.** In `muk.ts`:

```ts
import { concat, randomBytes, utf8 } from "./bytes";

const SALT_LABEL = "sluice/muk-salt/v2";

/** Random, per account, public. Minted at signup and never changed. */
export const ACCOUNT_SALT_BYTES = 16;

export function newAccountSalt(): Uint8Array {
  return randomBytes(ACCOUNT_SALT_BYTES);
}

function mukSalt(accountSalt: Uint8Array): Uint8Array {
  return sha256(concat(utf8.encode(SALT_LABEL), accountSalt));
}

export async function deriveMUK(
  password: string,
  accountSalt: Uint8Array,
  options?: DeriveMUKOptions,
): Promise<MasterUnlockKey> {
  if (password.length === 0) throw new Error("password must not be empty");
  if (!(accountSalt instanceof Uint8Array) || accountSalt.length !== ACCOUNT_SALT_BYTES) {
    throw new Error(`accountSalt must be ${ACCOUNT_SALT_BYTES} bytes`);
  }
  // … the rest unchanged: backend choice, conformance check, frozen params …
  const out = await backend(utf8.encode(password.normalize("NFC")), mukSalt(accountSalt), params);
  // … output check, `new MasterUnlockKey(out)` …
}
```

**Rewrite the `mukSalt` and `deriveMUK` comments.** The salt is now random per account rather than derived from an address: it adds real entropy against precomputation, and an email change no longer changes the key. Keep the explanation of why the salt is hashed with a label (fixed width, domain separation). Update the sentence on `ARGON2_PARAMS` that calls the MUK "a pure function of (password, userId, parameters)" to say account salt.

**Step 4: Run and watch it pass.** Expected: PASS (the KAT test takes a few seconds).

**Step 5: Commit.**

```bash
git add packages/crypto/src/muk.ts packages/crypto/test/muk.test.ts
git commit -m "Salt the master key with a random per-account value, not the email"
```

---

### Task 4: Move the dashboard's invented constants into `@sluice/crypto`

The Rust CLI's `sluice login` must reproduce these byte for byte, and it can only be tested against a single definition.

**Files:**
- Create: `packages/crypto/src/identity.ts`, `packages/crypto/src/email.ts`
- Test: `packages/crypto/test/identity.test.ts`, `packages/crypto/test/email.test.ts`
- Modify: `apps/admin/src/lib/auth/identity.ts`, `apps/admin/src/lib/auth/email.ts`, `convex/lib/email.ts`

**Step 1: Write the failing tests.**

```ts
// packages/crypto/test/identity.test.ts
import { describe, expect, it } from "vitest";
import { toHex } from "../src/bytes";
import { MasterUnlockKey } from "../src/muk";
import {
  decodeWrappedKey,
  deriveAuthVerifier,
  encodeWrappedKey,
  userKeyAssociatedData,
} from "../src/identity";

describe("userKeyAssociatedData", () => {
  it("matches the independent vectors", () => {
    expect(toHex(userKeyAssociatedData("x25519"))).toBe(
      "736c756963652f757365722d6b65792f76317c783235353139",
    );
    expect(toHex(userKeyAssociatedData("ed25519"))).toBe(
      "736c756963652f757365722d6b65792f76317c65643235353139",
    );
  });
});

describe("deriveAuthVerifier", () => {
  it("matches the independent HMAC vector", () => {
    const muk = new MasterUnlockKey(Uint8Array.from({ length: 32 }, (_, i) => i));
    expect(deriveAuthVerifier(muk)).toBe(
      "0abfe45dead6265934bc56753b7cd9f2f782e9f801e7279e4a5451453bcbff61",
    );
  });
});

describe("wrapped key codec", () => {
  const box = { nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array(16).fill(2) };

  it("round-trips", () => {
    expect(decodeWrappedKey(encodeWrappedKey(box))).toEqual(box);
  });
  it("uses the ratified format", () => {
    expect(encodeWrappedKey(box)).toBe(`sluice.k1.${"01".repeat(12)}.${"02".repeat(16)}`);
  });
  it.each(["", "sluice.k2.00.00", `sluice.k1.${"01".repeat(12)}.${"02".repeat(15)}`])(
    "rejects %j",
    (blob) => {
      expect(() => decodeWrappedKey(blob)).toThrow();
    },
  );
});
```

```ts
// packages/crypto/test/email.test.ts
import { describe, expect, it } from "vitest";
import { normaliseEmail } from "../src/email";

describe("normaliseEmail", () => {
  it("trims and lowercases without locale rules", () => {
    expect(normaliseEmail("  Ada@Example.COM ")).toBe("ada@example.com");
    expect(normaliseEmail("I@x.io")).toBe("i@x.io"); // never a Turkish dotless i
  });
  it.each(["", "a", "a@b@c", "a b@c.d", `${"a".repeat(250)}@b.io`])("rejects %j", (value) => {
    expect(() => normaliseEmail(value)).toThrow();
  });
});
```

**Step 2: Run and watch them fail.**

**Step 3: Implement.**

`packages/crypto/src/identity.ts`: move `BLOB_VERSION`, `BLOB_PATTERN`, `KEY_AAD_PREFIX`, `AUTH_VERIFIER_LABEL`, `keyAssociatedData` (exported as `userKeyAssociatedData`), and `encodeBlob`/`decodeBlob` (exported as `encodeWrappedKey`/`decodeWrappedKey`, throwing a `WrappedKeyFormatError` defined here), with their comments. Reimplement `deriveAuthVerifier` synchronously on `@noble/hashes`, because this package runs in Node, browsers and later the vector generator, and WebCrypto is not uniform across them:

```ts
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";

export function deriveAuthVerifier(muk: MasterUnlockKey): string {
  return toHex(hmac(sha256, muk.bytes, utf8.encode(AUTH_VERIFIER_LABEL)));
}
```

`packages/crypto/src/email.ts`: the dashboard's `normaliseEmail` verbatim, throwing a plain `EmailFormatError extends Error`, with the RFC 5321 length cap and the `toLowerCase`-not-`toLocaleLowerCase` comment.

`convex/lib/email.ts`: keep the `NormalisedEmail` brand; the body becomes

```ts
import { EmailFormatError, normaliseEmail as normalise } from "@sluice/crypto";

export function normaliseEmail(email: string): NormalisedEmail {
  try {
    return normalise(email) as NormalisedEmail;
  } catch (error) {
    if (error instanceof EmailFormatError) throw new ConvexError(error.message);
    throw error;
  }
}
```

`apps/admin/src/lib/auth/email.ts`: re-export `normaliseEmail` and `EmailFormatError` from `@sluice/crypto`; keep `isValidEmail` and `emailLocalPart`. Rewrite the header: it is no longer a duplicate, and with a random account salt an email change no longer changes the master key. The address is now only the lookup key.

`apps/admin/src/lib/auth/identity.ts`: import the moved pieces from `@sluice/crypto`. `deriveAuthVerifier` is now synchronous, so drop the `await` at its call sites in `auth-context.tsx`. Delete the test that pinned the two email copies against each other; there is one copy now.

**Step 4: Run.** `pnpm test:all`. The new tests pass. Typecheck still fails at the Task 2 call sites.

**Step 5: Commit.**

```bash
git add packages/crypto apps/admin/src/lib/auth convex/lib/email.ts apps/admin/test
git commit -m "Ratify the auth verifier, key blob and email rules in one package"
```

---

### Task 5: Export the new surface

**Files:**
- Modify: `packages/crypto/src/index.ts`
- Modify: `packages/crypto/test/index.test.ts` (it pins the export list)

**Step 1:** Add to the pinned export list in `index.test.ts`: `newId`, `assertId`, `newAccountSalt`, `ACCOUNT_SALT_BYTES`, `userKeyAssociatedData`, `deriveAuthVerifier`, `encodeWrappedKey`, `decodeWrappedKey`, `WrappedKeyFormatError`, `normaliseEmail`, `EmailFormatError`. Run: FAIL.

**Step 2:** Export them from `index.ts`, plus `export type { IdKind } from "./ids"`. Run: PASS.

**Step 3: Commit.**

```bash
git commit -am "Export ids, account salt, identity and email rules from @sluice/crypto"
```

---

### Task 6: Schema: permanent ids, account salt, `orgId` everywhere

**Files:**
- Modify: `convex/schema.ts`

**Step 1: Change the schema.**

| Table | Add | Index |
|---|---|---|
| `users` | `uid: v.string()`, `accountSalt: v.string()` | `by_uid` on `["uid"]` |
| `orgs` | `uid: v.string()` | `by_uid` |
| `environments` | `uid: v.string()`, `orgId: v.id("orgs")` | `by_uid`; `by_org` on `["orgId"]` |
| `secrets` | `orgId: v.id("orgs")` | `by_org` |
| `pdkGrants` | `orgId: v.id("orgs")` | `by_org` |
| `serviceTokens` | `orgId: v.id("orgs")` | `by_org` |
| `revocations` | `orgId: v.id("orgs")`, `environmentId: v.id("environments")` | `by_org` |

Comment each `uid` with one line pointing at `packages/crypto/src/ids.ts`. Comment each `orgId` with why: an org must be liftable into another cell in one indexed read, and per-org quotas need a direct count.

**Step 2:** `pnpm typecheck:all`. Expected: new failures at every insert and fixture now missing a field. Those, plus the Task 2 failures, are the full checklist for Tasks 7 to 13.

**Step 3: Commit.**

```bash
git commit -am "Give every tenant row a permanent id and a direct org reference"
```

---

### Task 7: Signup takes an id and a salt; login fetches the salt first

**Files:**
- Modify: `convex/auth.ts`, `convex/repo/users.ts`, `convex/lib/verifier.ts` (export its pepper reader)
- Create: `convex/lib/salt.ts`
- Test: `convex/auth.test.ts`, `convex/lib/salt.test.ts`

**Step 1: Write the failing tests.**

```ts
// convex/lib/salt.test.ts
import { afterEach, describe, expect, it } from "vitest";
import { decoySalt } from "./salt";

const previous = process.env.AUTH_PEPPER;
afterEach(() => {
  if (previous === undefined) delete process.env.AUTH_PEPPER;
  else process.env.AUTH_PEPPER = previous;
});

describe("decoySalt", () => {
  it("matches the independent vector", () => {
    process.env.AUTH_PEPPER = "ab".repeat(32);
    expect(decoySalt("nobody@example.com")).toBe("3cdb14ca8f79ef0ce835b15f0cba7674");
  });
  it("is stable per address and differs across addresses", () => {
    process.env.AUTH_PEPPER = "ab".repeat(32);
    expect(decoySalt("a@b.io")).toBe(decoySalt("a@b.io"));
    expect(decoySalt("a@b.io")).not.toBe(decoySalt("c@d.io"));
  });
});
```

Add to `convex/auth.test.ts`:

- `signup` rejects a missing or malformed `uid` (`usr_…` shape, via `assertId` from `@sluice/crypto`) and an `accountSalt` that is not 16 bytes of lowercase hex.
- `signup` rejects a second account with the same `uid`.
- `getLoginSalt` returns the stored salt for a known address.
- `getLoginSalt` returns a 32-hex-character salt for an unknown address, the same one on every call, and it is not the stored salt of any account.
- `login` returns `userUid`.

**Step 2:** Run: FAIL.

**Step 3: Implement.**

`convex/lib/salt.ts`: `decoySalt(email)` = the first 16 bytes of `HMAC-SHA256(fromHex(AUTH_PEPPER), "sluice/decoy-salt/v1|" + email)`, hex. Read the pepper through the existing reader in `convex/lib/verifier.ts`; export it from there rather than reading `process.env` a second time.

`convex/auth.ts`:

- `signup` args gain `uid: v.string()` and `accountSalt: v.string()`. Validate with `assertId("usr", "uid", …)` and `assertHexBytes("accountSalt", …, 16)`; reject a duplicate `uid` through a `by_uid` lookup, in the same mutation, before insert.
- New `getLoginSalt = query({ args: { email: v.string() }, returns: v.object({ accountSalt: v.string() }) })`: normalise, look up, return the stored salt or `decoySalt(email)`.
- `login` also returns `userUid: user.uid`.

Comment `getLoginSalt` with the enumeration consequence from the backend plan: account existence is already public through signup's duplicate message, and the decoy keeps this endpoint from making that easier to automate.

**Step 4:** Run: PASS for these; other suites still fail on fixtures.

**Step 5: Update the shared fixture.** `seedUser` in `convex/orgs.test.ts` is exported and reused across suites. Give it `uid: newId("usr")` and `accountSalt: "30".repeat(16)`, and return `uid` on the `Actor`. Fix every other direct `insertUser` the compiler flags.

**Step 6: Commit.**

```bash
git commit -am "Two-phase login: fetch the account salt, then derive"
```

---

### Task 8: `createOrg` takes its permanent id

**Files:**
- Modify: `convex/orgs.ts`, `convex/repo/orgs.ts`
- Test: `convex/orgs.test.ts`

**Step 1: Tests.** `createOrg` rejects a malformed `orgUid` and a duplicate one; `getOrg` and `listMyOrgs` return `uid`; `getMyRevocationGrant` returns the org's `uid`, so the client can rebuild the AAD.

**Step 2:** Run: FAIL.

**Step 3: Implement.** Arg `orgUid: v.string()`, validated with `assertId("org", …)`, uniqueness through `by_uid`, stored as `uid`. Rewrite the comment at the grant insert: the grant is still created in the same mutation for the atomicity reason, and it is now also bound to this org's `uid`, which the client knew before calling.

**Step 4:** Run: PASS. **Step 5: Commit.**

```bash
git commit -am "Create orgs under a client-minted permanent id"
```

---

### Task 9: `createEnvironment` takes its permanent id and records its org

**Files:**
- Modify: `convex/environments.ts`, `convex/repo/environments.ts`
- Test: `convex/environments.test.ts`

**Step 1: Tests.** Rejects a malformed or duplicate `environmentUid`; the environment row and its first grant both carry `orgId`; `getEnvironment` and `listEnvironments` return `uid`.

**Step 2:** Run: FAIL.

**Step 3: Implement.** Arg `environmentUid`; store `uid` and `orgId: org._id` on the environment; `orgId` on the grant. Rewrite the arg comment: the client wraps under `pdkAssociatedData({ environmentUid, granteeType: "user", granteeId: <caller's usr_ id> })`.

**Step 4:** Run: PASS. **Step 5: Commit.**

```bash
git commit -am "Create environments under a permanent id bound into their first grant"
```

---

### Task 10: Secrets, tokens, revocations and the bundle

**Files:**
- Modify: `convex/secrets.ts`, `convex/tokens.ts`, `convex/bundle.ts` and their `repo/` functions
- Test: `convex/secrets.test.ts`, `convex/tokens.test.ts`, `convex/bundle.test.ts`

**Step 1: Tests.**

- Every secret insert carries the environment's `orgId`, copied from the row and never from a caller.
- `createServiceToken` writes `orgId` on the token and on its grant.
- `revokeServiceToken` writes `orgId` and `environmentId` on the revocation row.
- `getBundle` returns `environmentUid` and no longer returns the Convex `environmentId`.

**Step 2:** Run: FAIL.

**Step 3: Implement.** Mechanical. Every `orgId` comes from a row the authorisation walk already loaded.

**Step 4:** `pnpm test:all` for the Convex suites: PASS. **Step 5: Commit.**

```bash
git commit -am "Record the owning org on every row and serve the environment's permanent id"
```

---

### Task 11: Dashboard signup and login

**Files:**
- Modify: `apps/admin/src/lib/auth/auth-context.tsx`, `apps/admin/src/lib/auth/session-store.ts`, `apps/admin/src/lib/auth/password.ts` (header only), `apps/admin/src/lib/crypto/derive.ts`, `apps/admin/src/lib/crypto/muk.worker.ts`, `apps/admin/src/lib/crypto/worker-protocol.ts`
- Test: `apps/admin/test/` (argon2 agreement, session store, identity)

**Step 1: Tests first.** The worker protocol carries `accountSalt` (hex) instead of `userId`; the argon2 agreement test derives with the v2 KAT salt and expects `KAT_MUK_V2`; the persisted session round-trips `userUid` and `accountSalt` and rejects a stored session missing either.

**Step 2:** Run: FAIL.

**Step 3: Implement.**

- **Signup:** `const accountSalt = newAccountSalt(); const uid = newId("usr");`, derive with `accountSalt`, send `uid` and `toHex(accountSalt)`.
- **Login:** `getLoginSalt({ email })` first, then derive, then `login`. Keep the phase indicator honest: add a `"fetching-salt"` phase before deriving.
- **Session:** persist `userUid` and `accountSalt`. Both are public; the salt is needed to re-derive after a reload.
- `password.ts` lines 6 to 11 claim the salt is the email. Rewrite them: the salt is now random and public, so the password remains the only secret input and the strength gate stays exactly as strict.

**Step 4:** Run: PASS. **Step 5: Commit.**

```bash
git commit -am "Dashboard: random account salt at signup, salt lookup before login"
```

---

### Task 12: Dashboard key operations use permanent ids

**Files:**
- Modify: `apps/admin/src/lib/secrets/pdk.ts`, `seal.ts`, `decrypt.ts`, `use-project-data-key.ts`, `apps/admin/src/lib/orgs/revocation-key.ts`, `apps/admin/src/components/app/create-forms.tsx`
- Test: `apps/admin/test/revocation-key.test.ts`, `apps/admin/test/identity.test.ts`, and any secrets tests

**Step 1: Tests first.**

- `wrapProjectDataKey` then `unwrapProjectDataKey` with the same `{ environmentUid, granteeType, granteeId }` round-trips; unwrapping under a different `environmentUid` fails with `PdkUnwrapError`.
- `wrapRevocationKey`/`unwrapRevocationKey` take `{ orgUid, granteeUid }`; a different `orgUid` fails with `RevocationKeyUnwrapError`.
- A secret sealed under one `environmentUid` fails to open under another.

**Step 2:** Run: FAIL.

**Step 3: Implement.**

- `PdkGrantee` becomes `{ environmentUid, granteeType, granteeId }`; `RevocationGrantee` becomes `{ orgUid, granteeUid }`.
- `create-forms.tsx`: mint `newId("org")` / `newId("env")` before wrapping, wrap with it, pass it to the mutation. The grantee is `session.userUid`, never `session.userId`.
- `seal.ts` / `decrypt.ts`: the AAD comes from the environment's `uid`, passed in by the caller from `getEnvironment`, never from a secret row's own columns.
- Rewrite the file headers of `pdk.ts` and `revocation-key.ts`: the environment and org are now bound. Keep `revocationKeyMatches` and its reason (the AAD still cannot bind the published public key).

**Step 4:** `pnpm --filter admin test` and `pnpm --filter admin typecheck`: PASS. **Step 5: Commit.**

```bash
git commit -am "Dashboard: wrap and seal under permanent ids"
```

---

### Task 13: The TypeScript CLI

**Files:**
- Modify: `packages/cli/src/bundle.ts`
- Test: `packages/cli/test/bundle.test.ts`, `packages/cli/test/fakes.ts`

**Step 1:** Update the fixtures in `fakes.ts` and `bundle.test.ts` to `ENVIRONMENT_UID = "env_000102030405060708090a0b0c0d0e0f"` and the v2 functions. Run: FAIL.

**Step 2:** In `bundle.ts`, read `raw.environmentUid` and pass it to both `pdkAssociatedData({ environmentUid, granteeType: "token", granteeId: identity.tokenIdHashHex })` and `secretAssociatedData({ environmentUid })`. A bundle without `environmentUid` is unreadable and returns `undefined` like every other malformed bundle; it must not throw on the shutdown path.

**Step 3:** `pnpm --filter @sluice/cli test`: PASS. **Step 4: Commit.**

```bash
git commit -am "CLI: open bundles under the environment's permanent id"
```

---

### Task 14: Documentation

**Files:** `SECURITY.md`, `docs/plans/2026-09-17-sluice-backend.md`, `docs/plans/2026-09-30-sluice-architecture-design.md`

- `SECURITY.md`: the salt is random per account; changing an email no longer changes the key; `getLoginSalt` and its decoy, under account enumeration.
- Backend plan, "Decided 2026-09-18" and "Three invented constants": append **Implemented 2026-09-30 in Phase 1**, with the commit range.
- Architecture design, section 13 rule 1: mark done.

```bash
git commit -am "Record that the protocol is frozen"
```

---

### Task 15: Verify

**Step 1: The whole workspace.**

```bash
pnpm typecheck:all
pnpm test:all
pnpm build
```

Expected: all green, and the test count at or above the Task 0 baseline.

**Step 2: No Convex id reaches a binding.**

```bash
git grep -nE "(secretAssociatedData|pdkAssociatedData|revocationKeyAssociatedData)\(" -- ':!*.md'
```

Every hit must pass a `*Uid` field. `assertId` already rejects Convex ids at runtime; this is the review-time check.

**Step 3: End to end, by hand, against the cleared dev deployment.** USER ACTION, with Claude driving where it can.

1. `pnpm dev:backend` and `pnpm --filter admin dev`.
2. Sign up. Sign out. Sign in. Reload and unlock.
3. Create an org, a project, an environment. Add two secrets. Reload; both decrypt.
4. Mint a token for the environment; run `sluice run -- node -e "console.log(process.env.YOUR_SECRET_NAME)"` with the token's environment variables set, and see the value arrive.
5. Revoke the token in the dashboard; the process exits within seconds.

**Step 4:** If all five pass, open a pull request from `phase-1-freeze-protocol` into `foundation`.
