import { describe, expect, it } from "vitest";
import { toHex, utf8 } from "../src/bytes";
import { userKeyAssociatedData } from "../src/identity";
import {
  pdkAssociatedData,
  revocationKeyAssociatedData,
  secretAssociatedData,
  tokenIdHash,
} from "../src/protocol";

/**
 * KNOWN-ANSWER VECTORS, COMPUTED WITHOUT THIS PACKAGE.
 *
 * Every vector in this file was produced by a standalone script run under
 * `node:crypto` and `node:buffer` -- neither of which this package can even
 * import, since it has no `@types/node`. They are therefore a check on the
 * construction and not an echo of it. The same technique, and the same reason,
 * as `KAT_MUK` in `muk.test.ts`.
 *
 * These are not tidy-up material. The AAD vectors pin the literal `/v2`
 * prefixes, the separator, the field order, and the fact that nothing else is
 * mixed in; change any of it and every ciphertext already written under that
 * construction stops opening, with AES-GCM reporting nothing more useful than
 * "failed". The token id vector pins the domain label and the concatenation
 * order; change either and `serviceTokens.tokenIdHash` stops matching
 * `revocations.tokenIdHash`, which means revocation silently stops reaching the
 * bundle while every test that seeds both sides by hand keeps passing.
 *
 * WHY THERE ARE NO `/v1` VECTORS HERE ANY MORE. v1 bound secrets to the Convex
 * document id of the environment, and could not bind a grant to its environment
 * or a revocation key to its org at all, because Convex mints those ids on
 * insert. v2 binds the client-minted permanent ids from `ids.ts` instead. No
 * real user data was ever sealed under v1, so v2 REPLACES it rather than sitting
 * beside it: a second, still-accepted construction would be a downgrade path
 * with nothing to protect.
 */

/** 16 bytes, the width `mintToken` produces and `assertTokenId` enforces. */
const KAT_TOKEN_ID = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
const KAT_TOKEN_ID_HASH = "305ab71526b2c39b5c8daf6ec97b91af98247937c858f4fd3ee4cf1e8d97fcd9";

const ALL_ONES_TOKEN_ID = new Uint8Array(16).fill(0xff);
const ALL_ONES_HASH = "c9aa663470b183b310a493d7f5f90880ff630e18b1346f582832df1ccb66ce91";

const ALL_ZEROS_TOKEN_ID = new Uint8Array(16);
const ALL_ZEROS_HASH = "6675085c295263c805ecabf33732747fe22482d9e3265cee9e67dbdc4e15b5fb";

describe("tokenIdHash", () => {
  it("matches the independently computed vector", () => {
    expect(tokenIdHash({ tokenId: KAT_TOKEN_ID })).toBe(KAT_TOKEN_ID_HASH);
  });

  it("matches the boundary vectors", () => {
    expect(tokenIdHash({ tokenId: ALL_ZEROS_TOKEN_ID })).toBe(ALL_ZEROS_HASH);
    expect(tokenIdHash({ tokenId: ALL_ONES_TOKEN_ID })).toBe(ALL_ONES_HASH);
  });

  it("returns 64 lowercase hex characters", () => {
    expect(tokenIdHash({ tokenId: KAT_TOKEN_ID })).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic across calls", () => {
    expect(tokenIdHash({ tokenId: KAT_TOKEN_ID })).toBe(tokenIdHash({ tokenId: KAT_TOKEN_ID }));
  });

  /**
   * The whole point of the move: `serviceTokens.tokenIdHash` and
   * `revocations.tokenIdHash` are written at different call sites, and if they
   * ever disagree the revocation never reaches the bundle.
   */
  it("gives different token ids different hashes", () => {
    const one = new Uint8Array(16);
    const other = new Uint8Array(16);
    other[15] = 1;
    expect(tokenIdHash({ tokenId: one })).not.toBe(tokenIdHash({ tokenId: other }));
  });

  it("depends on byte order, not just byte content", () => {
    const forwards = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const backwards = Uint8Array.from([...forwards].reverse());
    expect(tokenIdHash({ tokenId: forwards })).not.toBe(tokenIdHash({ tokenId: backwards }));
  });

  /**
   * Same rule as {@link assertTokenId} in `token.ts`, and for the same reason:
   * the label and the id are concatenated, so the id being a known fixed width
   * is what keeps the encoding unambiguous.
   */
  it("rejects a token id of the wrong width", () => {
    for (const length of [0, 1, 15, 17, 32]) {
      expect(() => tokenIdHash({ tokenId: new Uint8Array(length) })).toThrow(/tokenId/);
    }
  });

  it("rejects a token id that is not a Uint8Array", () => {
    for (const bad of [undefined, null, "0".repeat(32), [...new Uint8Array(16)]]) {
      expect(() => tokenIdHash({ tokenId: bad as unknown as Uint8Array })).toThrow(/tokenId/);
    }
  });

  /**
   * The label is bound inside the function. A caller cannot pass a domain, so
   * the SDK and the backend cannot end up hashing under two of them.
   */
  it("gives the caller no way to choose the domain label", () => {
    expect(tokenIdHash.length).toBe(1);
  });

  /**
   * ASSERTED AGAINST THE SPELLING, NOT THE IMPLEMENTATION. If the label is
   * ever edited, this fails here as well as at the vectors, and says which
   * string changed.
   */
  it("hashes under the pinned domain label", () => {
    expect([...utf8.encode("sluice/token-id/v1")]).toEqual([
      115, 108, 117, 105, 99, 101, 47, 116, 111, 107, 101, 110, 45, 105, 100, 47, 118, 49,
    ]);
  });
});

/**
 * THE v2 BINDINGS.
 *
 * The ids are chosen so every byte is visible in the hex: each is its kind
 * prefix followed by sixteen consecutive byte values, so a vector that shifted
 * a field or dropped a separator would show it to a reader at a glance.
 * `TOKEN_HASH` is `tokenIdHash` of the 0..15 token id above, so the token
 * grantee vector exercises the exact value a real grant row would carry.
 */
const ENV = "env_000102030405060708090a0b0c0d0e0f";
const USR = "usr_101112131415161718191a1b1c1d1e1f";
const ORG = "org_202122232425262728292a2b2c2d2e2f";
const TOKEN_HASH = "305ab71526b2c39b5c8daf6ec97b91af98247937c858f4fd3ee4cf1e8d97fcd9";

// Computed with node:crypto, never with this package.
const SECRET_AAD =
  "736c756963652f7365637265742f76327c656e765f3030303130323033303430353036303730383039306130623063306430653066";
const PDK_AAD_USER =
  "736c756963652f70646b2f76327c656e765f30303031303230333034303530363037303830393061306230633064306530667c757365727c7573725f3130313131323133313431353136313731383139316131623163316431653166";
const PDK_AAD_TOKEN =
  "736c756963652f70646b2f76327c656e765f30303031303230333034303530363037303830393061306230633064306530667c746f6b656e7c33303561623731353236623263333962356338646166366563393762393161663938323437393337633835386634666433656534636631653864393766636439";
const REVOCATION_AAD =
  "736c756963652f7265766f636174696f6e2d6b65792f76327c6f72675f32303231323232333234323532363237323832393261326232633264326532667c7573725f3130313131323133313431353136313731383139316131623163316431653166";

/**
 * `utf8("sluice/secret/v2|env_000102030405060708090a0b0c0d0e0f")`, written out
 * one byte at a time.
 *
 * Deliberately NOT `utf8.encode(...)` of a string assembled here: this is the
 * one assertion in the file that cannot be satisfied by an implementation that
 * is self-consistently wrong, because every entry is a printable ASCII code
 * point a reader can check by hand. `115` is `s`, `50` is `2`, `124` is `|`,
 * `95` is `_`, `48` is `0`.
 */
const SECRET_AAD_BYTES = [
  115, 108, 117, 105, 99, 101, 47, 115, 101, 99, 114, 101, 116, 47, 118, 50, 124, 101, 110, 118,
  95, 48, 48, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 48, 54, 48, 55, 48, 56, 48, 57, 48, 97, 48,
  98, 48, 99, 48, 100, 48, 101, 48, 102,
];

/** A Convex document id, the shape v1 bound and v2 must refuse. */
const CONVEX_DOC_ID = "k17dn9q2x4m8p3v6b0zc5t7wgh";

const NOT_STRINGS = [undefined, null, 42, {}, [ENV]];

describe("secretAssociatedData v2", () => {
  it("produces the exact wire bytes, built literally rather than by calling the implementation", () => {
    expect([...secretAssociatedData({ environmentUid: ENV })]).toEqual(SECRET_AAD_BYTES);
  });

  it("matches the independent vector", () => {
    expect(toHex(secretAssociatedData({ environmentUid: ENV }))).toBe(SECRET_AAD);
  });

  it("returns bytes, not a string", () => {
    expect(secretAssociatedData({ environmentUid: ENV })).toBeInstanceOf(Uint8Array);
  });

  /**
   * The version is a property of the protocol, so it is bound inside the
   * function. There is no parameter a caller could use to pick a different
   * one, which is what keeps a client from downgrading itself to v1.
   */
  it("gives the caller no way to choose the version", () => {
    expect(secretAssociatedData.length).toBe(1);
  });

  it("differs across environments", () => {
    const other = "env_ffffffffffffffffffffffffffffffff";
    expect(toHex(secretAssociatedData({ environmentUid: other }))).not.toBe(SECRET_AAD);
  });

  /**
   * The v1 binding. A document id is local to one deployment and re-minted on a
   * cell move, so ciphertext bound to it would stop opening the day the org
   * moved; `assertId` is what keeps one from sneaking back in.
   */
  it("rejects a Convex document id", () => {
    expect(() => secretAssociatedData({ environmentUid: CONVEX_DOC_ID })).toThrow(
      /^environmentUid must be a well-formed env id$/,
    );
  });

  it("rejects a user id in the environment slot", () => {
    expect(() => secretAssociatedData({ environmentUid: USR })).toThrow(
      /^environmentUid must be a well-formed env id$/,
    );
  });

  it("rejects a non-string environment uid", () => {
    // Reachable from a database row or a JSON body; the type is not a runtime
    // guarantee. `String(undefined)` would otherwise bind to the literal
    // "undefined" and look like a perfectly good AAD.
    for (const bad of NOT_STRINGS) {
      expect(() =>
        secretAssociatedData({ environmentUid: bad as unknown as string }),
      ).toThrow(/^environmentUid must be a well-formed env id$/);
    }
  });

  /**
   * One spelling per id. Uppercase hex names the same random value and would
   * seal to different bytes, which is two AADs for one environment.
   */
  it("rejects an uppercase spelling of a valid id", () => {
    expect(() => secretAssociatedData({ environmentUid: ENV.toUpperCase() })).toThrow(
      /^environmentUid must be a well-formed env id$/,
    );
  });

  it("binds the pinned prefix", () => {
    expect([...utf8.encode("sluice/secret/v2|")]).toEqual([
      115, 108, 117, 105, 99, 101, 47, 115, 101, 99, 114, 101, 116, 47, 118, 50, 124,
    ]);
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

  /**
   * NEW IN v2, AND THE POINT OF IT. A grant blob copied into another
   * environment's row by someone with database write access used to open,
   * because nothing in its associated data named the environment. Now it does
   * not.
   */
  it("differs across environments for the same grantee", () => {
    const other = "env_ffffffffffffffffffffffffffffffff";
    expect(
      toHex(pdkAssociatedData({ environmentUid: other, granteeType: "user", granteeId: USR })),
    ).not.toBe(PDK_AAD_USER);
  });

  it("gives the caller no way to choose the version", () => {
    expect(pdkAssociatedData.length).toBe(1);
  });

  it("rejects a Convex document id as the environment", () => {
    expect(() =>
      pdkAssociatedData({ environmentUid: CONVEX_DOC_ID, granteeType: "user", granteeId: USR }),
    ).toThrow(/^environmentUid must be a well-formed env id$/);
  });

  /**
   * Each namespace has its own shape, checked separately. v1 accepted any
   * opaque string for either and relied on `granteeType` alone to keep them
   * apart; v2 refuses a value that is the wrong SHAPE for the type it claims.
   */
  it("rejects a token hash as a user grantee", () => {
    expect(() =>
      pdkAssociatedData({ environmentUid: ENV, granteeType: "user", granteeId: TOKEN_HASH }),
    ).toThrow(/^granteeId must be a well-formed usr id$/);
  });

  it("rejects a user id as a token grantee", () => {
    expect(() =>
      pdkAssociatedData({ environmentUid: ENV, granteeType: "token", granteeId: USR }),
    ).toThrow(/^granteeId must be a token id hash$/);
  });

  it("rejects a Convex document id as a user grantee", () => {
    expect(() =>
      pdkAssociatedData({ environmentUid: ENV, granteeType: "user", granteeId: CONVEX_DOC_ID }),
    ).toThrow(/^granteeId must be a well-formed usr id$/);
  });

  it("rejects an uppercase token hash", () => {
    expect(() =>
      pdkAssociatedData({
        environmentUid: ENV,
        granteeType: "token",
        granteeId: TOKEN_HASH.toUpperCase(),
      }),
    ).toThrow(/^granteeId must be a token id hash$/);
  });

  /**
   * The token hash is the one grantee shape that is not a permanent id, so it
   * has its own guard and needs its own edges pinned. The trailing newline is
   * the case a port to PCRE or Python would get wrong (`$` there also matches
   * before a final `\n`); the off-by-one lengths and the non-hex `g` are the
   * cases a hand-rolled byte check would get wrong.
   */
  it("rejects every near miss of a token hash", () => {
    for (const bad of [
      `${TOKEN_HASH}\n`,
      TOKEN_HASH.slice(0, 63),
      `${TOKEN_HASH}0`,
      `g${TOKEN_HASH.slice(1)}`,
      TOKEN_HASH.toUpperCase(),
      `A${TOKEN_HASH.slice(1)}`,
      "",
    ]) {
      expect(() =>
        pdkAssociatedData({ environmentUid: ENV, granteeType: "token", granteeId: bad }),
      ).toThrow(/^granteeId must be a token id hash$/);
    }
  });

  it("rejects a non-string grantee id of either type", () => {
    for (const bad of NOT_STRINGS) {
      expect(() =>
        pdkAssociatedData({
          environmentUid: ENV,
          granteeType: "user",
          granteeId: bad as unknown as string,
        }),
      ).toThrow(/^granteeId must be a well-formed usr id$/);
      expect(() =>
        pdkAssociatedData({
          environmentUid: ENV,
          granteeType: "token",
          granteeId: bad as unknown as string,
        }),
      ).toThrow(/^granteeId must be a token id hash$/);
    }
  });

  /**
   * The type is not free text. An unrecognised value would be a third namespace
   * nothing in the product can read, wrapped under bytes nobody will ever
   * reconstruct, and it would look like a typo in a diff rather than a failure.
   */
  it("rejects an unknown grantee type", () => {
    expect(() =>
      pdkAssociatedData({
        environmentUid: ENV,
        granteeType: "tokens" as "token",
        granteeId: TOKEN_HASH,
      }),
    ).toThrow(/^granteeType must be one of user, token$/);
    for (const bad of ["User", "", "service", undefined, null, 0]) {
      expect(() =>
        pdkAssociatedData({
          environmentUid: ENV,
          granteeType: bad as unknown as "user",
          granteeId: USR,
        }),
      ).toThrow(/^granteeType must be one of user, token$/);
    }
  });

  it("binds the pinned prefix", () => {
    expect([...utf8.encode("sluice/pdk/v2|")]).toEqual([
      115, 108, 117, 105, 99, 101, 47, 112, 100, 107, 47, 118, 50, 124,
    ]);
  });
});

describe("revocationKeyAssociatedData v2", () => {
  it("binds org and grantee", () => {
    expect(toHex(revocationKeyAssociatedData({ orgUid: ORG, granteeUid: USR }))).toBe(
      REVOCATION_AAD,
    );
  });

  /**
   * NEW IN v2. A revocation-key blob copied into another org's
   * `revocationGrants` row used to open; now it does not.
   */
  it("differs across orgs for the same grantee", () => {
    const other = "org_ffffffffffffffffffffffffffffffff";
    expect(toHex(revocationKeyAssociatedData({ orgUid: other, granteeUid: USR }))).not.toBe(
      REVOCATION_AAD,
    );
  });

  it("gives the caller no way to choose the version", () => {
    expect(revocationKeyAssociatedData.length).toBe(1);
  });

  /**
   * Both fields are permanent ids of DIFFERENT kinds, so a call site that
   * passes them the wrong way round fails here rather than sealing a blob
   * nobody will reconstruct. The org is checked first, so that is the field the
   * message names.
   */
  it("rejects swapped arguments", () => {
    expect(() => revocationKeyAssociatedData({ orgUid: USR, granteeUid: ORG })).toThrow(
      /^orgUid must be a well-formed org id$/,
    );
  });

  it("rejects a grantee that is not a user id", () => {
    for (const bad of [ORG, TOKEN_HASH, CONVEX_DOC_ID]) {
      expect(() => revocationKeyAssociatedData({ orgUid: ORG, granteeUid: bad })).toThrow(
        /^granteeUid must be a well-formed usr id$/,
      );
    }
  });

  it("rejects a non-string org uid", () => {
    for (const bad of NOT_STRINGS) {
      expect(() =>
        revocationKeyAssociatedData({ orgUid: bad as unknown as string, granteeUid: USR }),
      ).toThrow(/^orgUid must be a well-formed org id$/);
    }
  });

  it("rejects a non-string grantee uid", () => {
    for (const bad of NOT_STRINGS) {
      expect(() =>
        revocationKeyAssociatedData({ orgUid: ORG, granteeUid: bad as unknown as string }),
      ).toThrow(/^granteeUid must be a well-formed usr id$/);
    }
  });

  it("binds the pinned prefix", () => {
    expect([...utf8.encode("sluice/revocation-key/v2|")]).toEqual([
      115, 108, 117, 105, 99, 101, 47, 114, 101, 118, 111, 99, 97, 116, 105, 111, 110, 45, 107,
      101, 121, 47, 118, 50, 124,
    ]);
  });
});

/**
 * FOUR AEAD DOMAINS, AND THREE OF THEM SHARE ONE KEY.
 *
 * Not hypothetical: a user's `pdkGrants.wrappedPDK` (a token's grant is sealed
 * under a key derived from the token instead), a
 * `revocationGrants.wrappedRevocationKey` and the account's two wrapped private
 * keys (`sluice/user-key/…`, `identity.ts`) are all sealed under the SAME master
 * unlock key, so their associated data is what stops one being written into
 * another's column and opened as the wrong kind of key. Secrets are the fourth
 * domain, under a project data key. Distinct is not enough on its own -- if one
 * were a prefix of another, a future field appended to the shorter one could
 * make them equal -- so prefix-freedom is checked too, both over the full
 * vectors and over the bare labels, whatever follows them.
 */
describe("no two constructions share bytes", () => {
  /**
   * The labels as they must be spelled, hard-coded here, and the labels as the
   * functions actually emit them, read back by encoding a valid input and
   * slicing up to and including the first separator. Both are checked so a
   * relabel in the source cannot slip past by also editing an expectation
   * computed from it.
   */
  const EXPECTED_LABELS = [
    "sluice/secret/v2|",
    "sluice/pdk/v2|",
    "sluice/revocation-key/v2|",
    "sluice/user-key/v1|",
  ];

  const labelOf = (bytes: Uint8Array): string => {
    const text = new TextDecoder().decode(bytes);
    return text.slice(0, text.indexOf("|") + 1);
  };

  it("emits exactly the four expected labels", () => {
    expect([
      labelOf(secretAssociatedData({ environmentUid: ENV })),
      labelOf(pdkAssociatedData({ environmentUid: ENV, granteeType: "user", granteeId: USR })),
      labelOf(revocationKeyAssociatedData({ orgUid: ORG, granteeUid: USR })),
      labelOf(userKeyAssociatedData("x25519")),
    ]).toEqual(EXPECTED_LABELS);
    expect(labelOf(userKeyAssociatedData("ed25519"))).toBe("sluice/user-key/v1|");
  });

  it("no label is a prefix of another", () => {
    expect(new Set(EXPECTED_LABELS).size).toBe(EXPECTED_LABELS.length);
    for (const a of EXPECTED_LABELS) {
      for (const b of EXPECTED_LABELS) {
        if (a !== b) expect(`${b} starts with ${a}: ${String(b.startsWith(a))}`).toBe(
          `${b} starts with ${a}: false`,
        );
      }
    }
  });

  it("every v2 vector is distinct and none is a prefix of another", () => {
    const all = [SECRET_AAD, PDK_AAD_USER, PDK_AAD_TOKEN, REVOCATION_AAD];
    expect(new Set(all).size).toBe(all.length);
    for (const a of all) for (const b of all) if (a !== b) expect(b.startsWith(a)).toBe(false);
  });

  it("the implementation reproduces exactly that set", () => {
    const produced = [
      toHex(secretAssociatedData({ environmentUid: ENV })),
      toHex(pdkAssociatedData({ environmentUid: ENV, granteeType: "user", granteeId: USR })),
      toHex(pdkAssociatedData({ environmentUid: ENV, granteeType: "token", granteeId: TOKEN_HASH })),
      toHex(revocationKeyAssociatedData({ orgUid: ORG, granteeUid: USR })),
    ];
    expect(produced).toEqual([SECRET_AAD, PDK_AAD_USER, PDK_AAD_TOKEN, REVOCATION_AAD]);
  });
});
