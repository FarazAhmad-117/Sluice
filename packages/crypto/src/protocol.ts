import { sha256 } from "@noble/hashes/sha256";
import { concat, toHex, utf8 } from "./bytes";
import { assertId } from "./ids";

/**
 * THE RULES BOTH ENDS OF THE WIRE MUST AGREE ON, BYTE FOR BYTE.
 *
 * Nothing else belongs in this file. These are not helpers and not utilities:
 * they are the four constructions where the backend and the SDK computing
 * slightly different bytes produces a silent, unrecoverable failure rather than
 * an error anybody can act on. They live in `@sluice/crypto` because it is the
 * ONE module both sides already depend on, and because the alternative -- a
 * literal in `convex/` and a hand-copied literal in `packages/sdk` -- is two
 * things that can drift apart by one character.
 *
 * WHAT DRIFT COSTS, CONCRETELY, so nobody edits any constant casually.
 *
 * The associated data: AES-GCM authenticates it. A single wrong byte and
 * `unseal` fails, and it fails the way AEAD is DESIGNED to fail -- opaquely,
 * with no indication of which input was wrong. An SDK that computes a different
 * AAD from the dashboard writes ciphertext the dashboard cannot open and cannot
 * open anything the dashboard wrote. Neither side errors at write time. The
 * failure surfaces the first time somebody reads a secret, which may be in
 * production, months later, and the error message will say nothing useful.
 *
 * The token id hash: `serviceTokens.tokenIdHash` and `revocations.tokenIdHash`
 * are written at different call sites and joined on equality. If the two ever
 * disagree, the join returns nothing, the revocation notice never reaches the
 * bundle, and a revoked token keeps working. Nothing throws. Every test that
 * seeds both rows by hand still passes, because a hand-seeded fixture agrees
 * with itself.
 *
 * The revocation key wrap: `revocationGrants.wrappedRevocationKey` holds the
 * only thing in the product that can sign a notice an SDK will honour. A client
 * that wrapped it under associated data the next client does not reproduce
 * produces an org whose kill switch cannot be armed, and nothing says so until
 * somebody tries to use it, during the incident it exists for.
 *
 * NO PARAMETER HERE SELECTS A VERSION OR A DOMAIN. Every label is bound inside
 * its function. A version a caller can pass is a version a caller can get
 * wrong, and on the AAD it would additionally be a downgrade a client could
 * perform on itself. A new construction gets a new label and replaces the
 * function's body; it does not get an argument.
 *
 * NONE OF THESE MAY BE FETCHED FROM A SERVER AT RUNTIME. They are pinned in
 * client code. A server that could choose the associated data could hand a
 * client the AAD of a different environment and undo the environment binding
 * entirely, which is the one thing that binding exists to prevent.
 *
 * WHAT PINNING THE CONSTRUCTION DOES NOT PIN: THE INPUTS. The rule is fixed in
 * client code, but the environment uid fed into it is not -- today it comes
 * from the server (`getBundle` returns `environmentUid`, and the dashboard reads
 * it off the environment row). So the binding stops a row being MOVED between
 * environments in the database: a blob copied from `dev` into `prod` names
 * `dev` and will not open as `prod`. It does NOT stop a malicious server lying
 * about which uid a NAME maps to: told that "prod" is `env_…` of some other
 * environment whose grant the caller also holds, a client will faithfully open
 * that environment's secrets and believe they are prod's -- and, worse, will
 * SEAL every secret it writes to "prod" into that other environment, where
 * everyone holding a grant there can read it. Closing that needs the
 * client to pin name -> uid itself rather than trusting the server's answer each
 * time. That is follow-up work; the planned single-string service token is
 * minted client-side and can carry the environment uid, which pins it for the
 * SDK at the moment the token is issued.
 *
 * WHY THE ASSOCIATED DATA IS `/v2` AND THERE IS NO `/v1` PATH BESIDE IT.
 *
 * v1 bound a secret to the Convex document id of its environment, and could not
 * bind a key grant to its environment or a revocation key to its org at all:
 * Convex mints document ids on insert, and every one of those wraps happens in
 * the client BEFORE the creating mutation runs. Both problems had the same root,
 * and `ids.ts` removes it: every org, user and environment now carries a
 * permanent id minted by the client, so the id exists before the wrap, and it
 * travels unchanged when an org moves between cells, where a document id would
 * be re-minted and every ciphertext bound to it would stop opening.
 *
 * v2 therefore binds those permanent ids, and binds them everywhere v1 had to
 * leave a gap. It REPLACES v1 rather than sitting beside it, because no real
 * user data was ever sealed under v1: a second construction still accepted on
 * read would be a downgrade path protecting nothing.
 *
 * EVERY ID IS SHAPE-CHECKED BY KIND before it is concatenated. `assertId`
 * accepts exactly `<kind>_` followed by 32 lowercase hex characters, so none of
 * these inputs can contain the separator, whitespace, a control character, a
 * lone surrogate (which `TextEncoder` would fold onto U+FFFD), or a second
 * spelling of the same value. That is what keeps every concatenation below
 * injective, and it is strictly tighter than the free-form guard v1 needed for
 * opaque document ids. It also means an id of the wrong kind -- `usr_…` where
 * `env_…` belongs, or a Convex document id at all -- fails at the call instead
 * of producing well-formed associated data for the wrong thing.
 */

/**
 * The associated data prefix for secret ciphertext. NOT exported.
 *
 * Exporting it would hand a caller the two halves of the construction and
 * invite them to join the string themselves, which is the drift this module
 * exists to remove. The only way to obtain these bytes is
 * {@link secretAssociatedData}.
 */
const SECRET_AAD_PREFIX = "sluice/secret/v2|";

/**
 * The domain label for {@link tokenIdHash}. NOT exported, for the same reason.
 *
 * Domain-separated so that this digest can never collide with any other
 * SHA-256 in the system over the same 16 bytes -- the handshake signature
 * message, a future nonce digest, an id hashed by some other subsystem. Without
 * a label, two subsystems that both "just hash the token id" would produce the
 * same string and silently share an index.
 */
const TOKEN_ID_HASH_LABEL = "sluice/token-id/v1";

/**
 * The associated data prefix for a wrapped project data key. NOT exported, for
 * the same reason as the two above: reaching it means calling
 * {@link pdkAssociatedData}.
 */
const PDK_AAD_PREFIX = "sluice/pdk/v2|";

/**
 * The associated data prefix for a wrapped organisation revocation signing
 * key. NOT exported, for the same reason as the three above: reaching it means
 * calling {@link revocationKeyAssociatedData}.
 */
const REVOCATION_KEY_AAD_PREFIX = "sluice/revocation-key/v2|";

/** The separator, written once so no call site spells it. */
const SEPARATOR = "|";

/**
 * The two grantee namespaces, and there are exactly two.
 *
 * A third value would be a namespace nothing in the product can read, wrapped
 * under bytes nobody will ever reconstruct, and in a diff it would look like a
 * typo rather than a failure. `"token"` is not `"tokens"` and `"user"` is not
 * `"User"`; both near misses are rejected rather than folded, for the reason
 * `convex/lib/hex.ts` gives for rejecting uppercase hex.
 */
export type PDKGranteeType = "user" | "token";
const GRANTEE_TYPES: readonly string[] = ["user", "token"];

/** The width `mintToken` produces. Identical to `token.ts`'s `TOKEN_ID_BYTES`. */
const TOKEN_ID_BYTES = 16;

/**
 * The shape of a `tokenIdHash`: SHA-256 output as {@link tokenIdHash} spells
 * it, 64 lowercase hex characters, anchored at both ends.
 *
 * NEW IN v2, AND IT IS WHY THE TWO GRANTEE NAMESPACES ARE NOW SEPARATED BY
 * SHAPE AS WELL AS BY TYPE. v1 accepted any opaque string as a grantee id of
 * either kind and relied on `granteeType` alone to keep them apart. v2 checks
 * each namespace against its own shape -- `usr_` plus 32 hex for a person, 64
 * bare hex for a token -- and the two cannot overlap, so a value that is the
 * wrong shape for the type it claims fails at the call instead of sealing a
 * grant no reader will ever look up. Lowercase only, for the reason `ids.ts`
 * gives: two spellings of one digest would be two AADs for one grantee.
 *
 * No flags: `$` without `m` matches only at end of input, so a trailing
 * newline is rejected, and without `g` there is no `lastIndex` to carry
 * between calls.
 *
 * FOR A PORT (the Rust SDK, or anything else): these shape checks, and the ones
 * in `ids.ts`, are BYTE RULES, not regexes. Exact length; every character in
 * the lowercase hex alphabet `0-9a-f`; for a permanent id, the literal kind
 * prefix (`env_`, `usr_`, `org_`) first. Implement them as byte comparisons. A
 * regex is only safe where `$` means end of input, which is true in JavaScript
 * and in Rust's `regex` crate but NOT in PCRE or Python, where `$` also matches
 * just before a trailing newline -- so a ported `^[0-9a-f]{64}$` would accept
 * `hash + "\n"` and seal a second, different AAD for the same grantee.
 */
const TOKEN_HASH_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The guard for a token grantee id, the one input here that is not a permanent
 * id and so cannot go through `assertId`.
 *
 * `typeof` is checked even though the type says string: the value arrives from
 * a database row or a JSON body, and `String(undefined)` would otherwise be
 * rejected only by luck of the pattern. The value is never echoed, matching
 * every other guard in this package.
 */
function assertTokenHash(value: string): string {
  if (typeof value !== "string" || !TOKEN_HASH_PATTERN.test(value)) {
    throw new Error("granteeId must be a token id hash");
  }
  return value;
}

/**
 * THE ASSOCIATED DATA RULE FOR SECRETS. READ THIS BEFORE WRITING A CLIENT.
 *
 * Every secret ciphertext in Sluice, both the name and the value, is sealed
 * with AES-GCM under associated data of exactly:
 *
 *     utf8("sluice/secret/v2|" + environmentUid)
 *
 * where `environmentUid` is the permanent `env_` id of the environment the row
 * belongs to (see `ids.ts`), spelled exactly as stored. NOT its Convex document
 * id: that is local to one deployment and is re-minted when an org moves cells,
 * and ciphertext bound to it would stop opening on the day of the move with no
 * server able to repair it, because no server holds a key.
 *
 * WHY THE VERSION IS IN HERE AND NOT IN A COLUMN. Associated data is
 * authenticated: change one byte of it and decryption fails. A column is not.
 * If the algorithm version sat in `secrets.algorithmVersion`, someone with write
 * access to the database could edit it independently of the ciphertext it
 * describes, and roll a row back to a weaker version while the ciphertext stayed
 * intact and still decrypted. Putting it inside the AAD means the version and
 * the ciphertext cannot be separated: a row whose version is altered simply
 * stops decrypting, loudly, which is the correct failure.
 *
 * WHY THE ENVIRONMENT IS IN HERE. Without it, a `dev` row could be copied into
 * `prod` by anyone with write access to the table and would decrypt perfectly,
 * because the project data key is per environment but the AAD would bind
 * nothing. The server's half of this defence is that no mutation accepts an
 * environment for a row that already has one, so a secret cannot be moved
 * between environments through the API either. Both halves are needed: this one
 * stops the database operator, the other stops the API caller.
 *
 * THE ARGUMENT IS AN OBJECT, NOT A STRING, AND CERTAINLY NOT A JOINED ONE. A
 * function taking the finished string would let a caller build
 * `"sluice/secret/v2|" + id` themselves, which is the hand-copied literal this
 * module was created to delete. Naming the field at every call site is also what
 * makes a diff that swaps a project id for an environment id visible -- and the
 * field is named `environmentUid`, not `environmentId`, so that every v1 call
 * site passing a document id fails to compile rather than silently binding the
 * wrong thing.
 */
export function secretAssociatedData(params: { environmentUid: string }): Uint8Array {
  const environmentUid = assertId("env", "environmentUid", params.environmentUid);

  // Unambiguous by construction: the prefix is fixed and `assertId` admits
  // exactly one fixed-width shape. No two distinct inputs produce one string.
  return utf8.encode(SECRET_AAD_PREFIX + environmentUid);
}

/**
 * THE ASSOCIATED DATA RULE FOR A WRAPPED PROJECT DATA KEY. READ THIS BEFORE
 * WRITING A CLIENT THAT CREATES OR OPENS A GRANT.
 *
 * Every `pdkGrants.wrappedPDK` in Sluice is sealed with AES-GCM under
 * associated data of exactly:
 *
 *     utf8("sluice/pdk/v2|" + environmentUid + "|" + granteeType + "|" + granteeId)
 *
 * where `environmentUid` is the permanent `env_` id of the environment whose
 * project data key this is, `granteeType` is `"user"` or `"token"`, and
 * `granteeId` is the user's permanent `usr_` id for a user and the
 * {@link tokenIdHash} for a token, spelled exactly as they are stored on the
 * row.
 *
 * WHY THE ENVIRONMENT IS IN HERE NOW, WHEN v1 DOCUMENTED AT LENGTH THAT IT
 * COULD NOT BE.
 *
 * The v1 constraint was real. A grant is written in the same transaction that
 * creates its environment, for the reason `convex/environments.ts` states at
 * that call site: an environment with no grant is an environment whose secrets
 * nobody can ever read, discovered long after creation with no error at any
 * point. The server never sees a plaintext project data key, so the wrap
 * happens in the client BEFORE that mutation runs -- and in v1 the only
 * environment id was the one Convex mints on insert, which did not exist yet.
 *
 * The permanent id removes the constraint without touching the transaction:
 * the client mints `env_…` first, wraps under it, and passes both into the
 * same single mutation. So v2 binds it, and a grant blob copied into another
 * environment's row by someone with database write access now FAILS TO OPEN.
 *
 * THE STRONGEST REASON IS ON WRITES, NOT READS, and it is why v1's claim that
 * the binding was "not needed" was wrong. v1 reasoned that a grant moved from
 * environment A into B's row yields A's key, which opens none of B's existing
 * secrets -- a read that fails, loudly, and no harm done. But a client does not
 * only read with the key a grant gives it; it also SEALS with it. Handed A's
 * key under B's row, a v1 client would encrypt every NEW secret it wrote to B
 * under A's project data key, and those secrets would then be readable by
 * everyone who holds a grant in A -- a confidentiality failure on the write
 * path, silent, with nothing on B's side ever failing to open. Binding the
 * environment into the grant makes the swapped row refuse to unwrap at all, so
 * no client ever holds a key for B that is really A's.
 *
 * WHY THE GRANTEE IS IN HERE. `granteeType` and `granteeId` are COLUMNS, and a
 * column is not authenticated. Naming the grantee inside the associated data is
 * what makes a row whose grantee fields were edited stop opening instead of
 * claiming to belong to somebody it does not. It also separates the two
 * namespaces: one wrapping key can hold grants of both kinds. In v2 they are
 * separated twice -- by the type literal, and by a per-type shape check that
 * {@link TOKEN_HASH_PATTERN} documents -- where v1 had only the first.
 *
 * WHY `pdkVersion` IS NOT IN HERE. It is the same call `secrets` makes: the
 * version bound into associated data is the PROTOCOL version, `/v2`, and the
 * key version lives in a column. Binding `pdkVersion` would buy nothing against
 * the only rollback that works anyway -- restoring the whole earlier row, whose
 * associated data was correct for its own version -- while forcing every client
 * to predict the version the server will assign to an environment it has not
 * created yet.
 *
 * THE ARGUMENT IS AN OBJECT, NOT A JOINED STRING, for the reason above: naming
 * the fields at every call site is what makes a diff that swaps a user id for a
 * token hash, or one environment for another, visible.
 */
export function pdkAssociatedData(params: {
  environmentUid: string;
  granteeType: PDKGranteeType;
  granteeId: string;
}): Uint8Array {
  const environmentUid = assertId("env", "environmentUid", params.environmentUid);
  const { granteeType } = params;

  // Checked against the closed set rather than merely for being a string. An
  // unrecognised type is not a wrong value that fails later, it is a further
  // construction that succeeds and produces bytes no reader will reconstruct.
  if (typeof granteeType !== "string" || !GRANTEE_TYPES.includes(granteeType)) {
    throw new Error(`granteeType must be one of ${GRANTEE_TYPES.join(", ")}`);
  }

  // The shape is chosen BY the type, so a token hash passed as a user (or a
  // user id passed as a token) fails here rather than sealing a grant filed
  // under the wrong namespace.
  const granteeId =
    granteeType === "user"
      ? assertId("usr", "granteeId", params.granteeId)
      : assertTokenHash(params.granteeId);

  // Unambiguous by construction: the prefix is fixed, `environmentUid` is a
  // fixed-width shape with no separator in it, `granteeType` is one of two
  // known literals, and `granteeId` is a separator-free shape fixed by that
  // literal. No two distinct inputs produce one string.
  return utf8.encode(
    PDK_AAD_PREFIX + environmentUid + SEPARATOR + granteeType + SEPARATOR + granteeId,
  );
}

/**
 * THE ASSOCIATED DATA RULE FOR A WRAPPED ORGANISATION REVOCATION SIGNING KEY.
 * READ THIS BEFORE WRITING A CLIENT THAT CREATES AN ORG OR SIGNS A NOTICE.
 *
 * Every `revocationGrants.wrappedRevocationKey` in Sluice is sealed with
 * AES-GCM under associated data of exactly:
 *
 *     utf8("sluice/revocation-key/v2|" + orgUid + "|" + granteeUid)
 *
 * where `orgUid` is the permanent `org_` id of the org whose key this is, and
 * `granteeUid` is the permanent `usr_` id of the person the key is wrapped to,
 * spelled exactly as they are stored.
 *
 * WHAT IS WRAPPED IS THE ED25519 SEED, 32 bytes, the private half of
 * `orgs.revocationPublicKey`. It is generated in a browser, it is the one thing
 * that can sign a revocation notice any SDK will honour, and this server has
 * never held it. That is the product's wedge.
 *
 * WHY THE ORG IS IN HERE NOW, WHEN v1 DOCUMENTED AT LENGTH THAT IT COULD NOT
 * BE. It is the identical change {@link pdkAssociatedData} documents for the
 * environment, for the identical reason.
 *
 * The v1 constraint was real. The grant is written in the same transaction
 * that creates its org, because `convex/orgs.ts` says at that call site that
 * an org without one is an org for which no revocation notice can ever be
 * signed -- the wedge broken at creation time, discovered during the incident
 * it exists for. The server never sees the plaintext signing key, so the wrap
 * happens in the CLIENT before that mutation runs, and in v1 the only org id
 * was the one Convex mints on insert. The permanent `org_` id exists before
 * the mutation, so v2 binds it without splitting creation in two, and a
 * revocation-key blob copied into another org's row now FAILS TO OPEN.
 *
 * The slug is still NOT a substitute, and v1's reason still holds: it is the
 * one field `createOrg` can reject after the wrap has happened -- two people
 * creating `acme` at once means one of them retries under a different slug --
 * and it is renameable in a way a permanent id is not.
 *
 * WHAT THIS STILL DOES NOT BIND, and why `revocationKeyMatches` in the
 * dashboard is still needed. The associated data names the org, but it cannot
 * name `orgs.revocationPublicKey`: that is a column, and a database writer who
 * swapped it would leave every grant opening perfectly while the SDKs verified
 * notices against a key the org's admins do not hold. Checking the unwrapped
 * seed against the stored public key is the only thing that catches that, and
 * `verifyRevocation` checking every notice against the org's own stored key
 * remains the binding SDKs rely on.
 *
 * WHY THE GRANTEE IS IN HERE. `granteeId` is a COLUMN, and a column is not
 * authenticated. Naming the grantee inside the associated data is what makes a
 * row whose grantee was edited stop opening instead of claiming to belong to
 * somebody it does not.
 *
 * WHY THERE IS NO `granteeType`. Unlike `pdkGrants`, only a person can sign a
 * revocation, so there is one namespace and nothing for a type to separate,
 * and the grantee is checked as a `usr_` id outright. A service token that
 * could sign its own revocation would be a kill switch the compromised party
 * holds.
 *
 * THE DOMAIN IS WHAT KEEPS THIS BLOB APART FROM EVERYTHING ELSE UNDER THE SAME
 * KEY, and that matters more here than domain separation usually does. Three
 * kinds of blob are sealed directly under one master unlock key: this one, a
 * user's `pdkGrants.wrappedPDK` (`sluice/pdk/…`; a token's grant is sealed
 * under a key derived from the token, not the MUK), and the account's own two
 * private keys (`sluice/user-key/…`, in `identity.ts`). The label is the first
 * and most general thing keeping any one of them from being written into
 * another's column and opened as the wrong kind of key -- a project data key
 * opened as a signing seed, or this seed opened as the account's X25519 key.
 * In v2 the
 * kind-prefixed ids after the label differ too, but that is a second line, not
 * a substitute. Secrets (`sluice/secret/…`) are the fourth AEAD domain; they
 * sit under a project data key rather than the MUK, but a key that is
 * mislabelled once can sit anywhere, so the test suite asserts all FOUR labels
 * are pairwise non-prefix, and no future field appended to one can make it
 * collide with another.
 *
 * THE ARGUMENT IS AN OBJECT, and the two fields are ids of DIFFERENT kinds, so
 * a call site that passes them the wrong way round fails at the call rather
 * than sealing a blob nobody will reconstruct.
 */
export function revocationKeyAssociatedData(params: {
  orgUid: string;
  granteeUid: string;
}): Uint8Array {
  const orgUid = assertId("org", "orgUid", params.orgUid);
  const granteeUid = assertId("usr", "granteeUid", params.granteeUid);

  // Unambiguous by construction: the prefix is fixed and both ids are
  // fixed-width shapes that cannot contain the separator. No two distinct
  // inputs produce one string.
  return utf8.encode(REVOCATION_KEY_AAD_PREFIX + orgUid + SEPARATOR + granteeUid);
}

/**
 * The stored form of a service token id: `sha256("sluice/token-id/v1" || id)`,
 * lowercase hex.
 *
 * WHY THE ID IS STORED HASHED AT ALL. `serviceTokens` holds one row per live
 * token. Storing the plaintext id would let anyone who reads the database --- a
 * backup, a support query, a compromised read replica --- enumerate every valid
 * identifier in the fleet. The hash is a one-way index key: the server can find
 * a token given its id, and cannot produce the ids from the table.
 *
 * WHY THIS IS NOT KEYED, WHEN `hashAuthVerifier` IS. That one hashes a
 * password-adjacent value under a server-held pepper, precisely so a database
 * dump alone cannot confirm a candidate. This one CANNOT be keyed, because the
 * SDK has to compute the same value and a secret the SDK holds is not a secret.
 * It does not need to be: the input is 128 bits from `randomBytes`, so there is
 * no candidate set to confirm against and nothing to brute-force. The property
 * being bought is non-enumerability, and an unkeyed digest over full-entropy
 * input buys exactly that.
 *
 * WHY PLAIN SHA-256 IS SAFE HERE DESPITE LENGTH EXTENSION. The output is an
 * index key, not a MAC: nothing authenticates anything on the strength of it,
 * and an attacker who could extend it would produce a digest that matches no
 * row. The input is also fixed-width in both halves, so `label || id` has its
 * boundary at a known offset and the concatenation is unambiguous -- the same
 * argument `handshakeMessage` makes in `token.ts`, and the reason
 * {@link TOKEN_ID_BYTES} is enforced below rather than assumed.
 *
 * WHY THE ARGUMENT IS BYTES AND NOT HEX. Hex has two spellings per byte and
 * `fromHex` accepts both, so a hex-taking version would hash `AB` and `ab` to
 * two different strings and put one token in two index buckets --- the exact
 * split identity `PUBLIC_KEY_HEX_PATTERN` exists to stop. `Uint8Array` has one
 * spelling. It is also what `parseToken` and `mintToken` already hand back, so
 * the SDK path involves no conversion at all.
 *
 * THIS FUNCTION IS NEW. Nothing in `convex/` computed a token id hash: the
 * schema declares the column and the repository functions take one already
 * computed, so both call sites were free to invent their own. That is the
 * divergence this exists to close, and because no value has ever been stored
 * under any other rule, this construction is a free choice rather than a
 * migration. It will not be free a second time.
 */
export function tokenIdHash(params: { tokenId: Uint8Array }): string {
  const { tokenId } = params;

  // Reached from the wire and from database rows, so the runtime check is real.
  // Note that a plain array of 16 numbers would satisfy `.length` and be
  // silently mis-hashed by `concat`, which is why this tests the constructor
  // rather than the length alone.
  if (!(tokenId instanceof Uint8Array)) {
    throw new Error("tokenId must be a Uint8Array");
  }
  // Identical rule to `assertTokenId` in `token.ts`, and load-bearing for the
  // same reason: the fixed width is what keeps `label || id` unambiguous.
  if (tokenId.length !== TOKEN_ID_BYTES) {
    throw new Error(`tokenId must be ${TOKEN_ID_BYTES} bytes, got ${tokenId.length}`);
  }

  return toHex(sha256(concat(utf8.encode(TOKEN_ID_HASH_LABEL), tokenId)));
}
