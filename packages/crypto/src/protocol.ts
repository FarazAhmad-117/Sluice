import { sha256 } from "@noble/hashes/sha256";
import { concat, toHex, utf8 } from "./bytes";

/**
 * THE RULES BOTH ENDS OF THE WIRE MUST AGREE ON, BYTE FOR BYTE.
 *
 * Nothing else belongs in this file. These are not helpers and not utilities:
 * they are the three constructions where the backend and the SDK computing
 * slightly different bytes produces a silent, unrecoverable failure rather than
 * an error anybody can act on. They live in `@sluice/crypto` because it is the
 * ONE module both sides already depend on, and because the alternative -- a
 * literal in `convex/` and a hand-copied literal in `packages/sdk` -- is two
 * things that can drift apart by one character.
 *
 * WHAT DRIFT COSTS, CONCRETELY, so nobody edits either constant casually.
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
 * NO PARAMETER HERE SELECTS A VERSION OR A DOMAIN. Both labels are bound inside
 * their function. A version a caller can pass is a version a caller can get
 * wrong, and on the AAD it would additionally be a downgrade a client could
 * perform on itself. A new construction gets a new `/v2` label and a new
 * function; it does not get an argument.
 *
 * NEITHER OF THESE MAY BE FETCHED FROM A SERVER AT RUNTIME. They are pinned in
 * client code. A server that could choose the associated data could hand a
 * client the AAD of a different environment and undo the environment binding
 * entirely, which is the one thing that binding exists to prevent.
 */

/**
 * The associated data prefix for secret ciphertext. NOT exported.
 *
 * Exporting it would hand a caller the two halves of the construction and
 * invite them to join the string themselves, which is the drift this module
 * exists to remove. The only way to obtain these bytes is
 * {@link secretAssociatedData}.
 */
const SECRET_AAD_PREFIX = "sluice/secret/v1|";

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
const PDK_AAD_PREFIX = "sluice/pdk/v1|";

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
 * Characters an environment id may not contain.
 *
 * `\p{Cs}` -- LONE SURROGATES -- is the one that is a real collision and not a
 * tidiness rule. `TextEncoder` does not throw on an unpaired surrogate, it
 * SUBSTITUTES U+FFFD. So the three distinct strings `"\uD800"`, `"\uDC00"` and
 * `"�"` all encode to the same three bytes, which means three environment
 * ids -- three distinct rows, three distinct keys in an exact-match index --
 * would share one associated data and each could open the others' ciphertext.
 * That is the exact cross-environment binding failure the AAD exists to
 * prevent, arriving through the encoder rather than through the concatenation.
 * Under the `u` flag a surrogate PAIR is a single non-Cs code point, so real
 * astral characters are unaffected; only the unpaired form is rejected.
 *
 * `|` is the separator and is RESERVED. Today the prefix is fixed-width, so the
 * map from id to AAD is injective whatever the id contains. The moment a `/v2`
 * appends a second field after the id, an id containing `|` shifts the parse
 * and two different structures share one AAD. Reserving it now costs nothing --
 * a Convex id is lowercase alphanumeric -- and reserving it later is impossible,
 * because by then the ciphertext is on disk under the old rule.
 *
 * Control and separator categories are rejected on the same grounds as
 * `revocation.ts` pins `tokenId`: an id that can carry a newline is an id that
 * can shift a field boundary in any line-oriented encoding this ever grows
 * into, and an id with leading or trailing whitespace is two ids that look like
 * one in a log.
 *
 * This is a TIGHTENING of `convex/lib/aad.ts`, which checks only for empty. It
 * changes no bytes: every input the Convex version accepts AND that is a real
 * Convex id produces identical output here. It only refuses inputs that were
 * already ambiguous.
 *
 * No `g` flag, deliberately: a global regex carries `lastIndex` across `.test`
 * calls and would alternate between pass and fail on the same input.
 */
const IDENTIFIER_FORBIDDEN = /[\p{Cs}\p{Cc}\p{Zs}\p{Zl}\p{Zp}|]/u;

/**
 * The one guard for every opaque identifier that gets concatenated into
 * associated data, applied to the environment id and to the grantee id alike.
 *
 * It is a function rather than two copies of three checks because this file is
 * the single definition of these constructions, and a file that defines one
 * rule twice is the failure mode it was created to delete. The field name is a
 * parameter so the message still names the argument that was wrong, which is
 * the only thing a caller can act on; the VALUE is never echoed, because a lone
 * surrogate does not survive a log line intact and every other guard in this
 * package refuses to print its input.
 */
function assertIdentifier(field: string, value: string): string {
  // `typeof` on a field the type already declares is not redundant. These
  // values reach this from a database row, a URL segment or a JSON body, and a
  // type is not a runtime guarantee. Without this check `undefined` would
  // concatenate to the literal "undefined" and produce a perfectly well-formed,
  // completely wrong AAD.
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  // An empty id would bind the ciphertext to the version and to NOTHING else,
  // and the call would look exactly like a correct one.
  if (value.length === 0) {
    throw new Error(`${field} must not be empty`);
  }
  if (IDENTIFIER_FORBIDDEN.test(value)) {
    throw new Error(
      `${field} must not contain the separator, whitespace, control characters or lone surrogates`,
    );
  }
  return value;
}

/**
 * THE ASSOCIATED DATA RULE FOR SECRETS. READ THIS BEFORE WRITING A CLIENT.
 *
 * Every secret ciphertext in Sluice, both the name and the value, is sealed
 * with AES-GCM under associated data of exactly:
 *
 *     utf8("sluice/secret/v1|" + environmentId)
 *
 * where `environmentId` is the Convex id of the environment the row belongs to,
 * spelled exactly as the server returns it.
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
 * WHY THE ENVIRONMENT ID IS IN HERE. Without it, a `dev` row could be copied
 * into `prod` by anyone with write access to the table and would decrypt
 * perfectly, because the project data key is per environment but the AAD would
 * bind nothing. The server's half of this defence is that no mutation accepts an
 * environment id for a row that already has one, so a secret cannot be moved
 * between environments through the API either. Both halves are needed: this one
 * stops the database operator, the other stops the API caller.
 *
 * THE ARGUMENT IS AN OBJECT, NOT A STRING, AND CERTAINLY NOT A JOINED ONE. A
 * function taking the finished string would let a caller build
 * `"sluice/secret/v1|" + id` themselves, which is the hand-copied literal this
 * module was created to delete. Naming the field at every call site is also what
 * makes a diff that swaps a project id for an environment id visible.
 */
export function secretAssociatedData(params: { environmentId: string }): Uint8Array {
  const environmentId = assertIdentifier("environmentId", params.environmentId);
  return utf8.encode(SECRET_AAD_PREFIX + environmentId);
}

/**
 * THE ASSOCIATED DATA RULE FOR A WRAPPED PROJECT DATA KEY. READ THIS BEFORE
 * WRITING A CLIENT THAT CREATES OR OPENS A GRANT.
 *
 * Every `pdkGrants.wrappedPDK` in Sluice is sealed with AES-GCM under
 * associated data of exactly:
 *
 *     utf8("sluice/pdk/v1|" + granteeType + "|" + granteeId)
 *
 * where `granteeType` is `"user"` or `"token"`, and `granteeId` is the `users`
 * document id for a user and the {@link tokenIdHash} for a token, spelled
 * exactly as they are stored on the row.
 *
 * WHY THE ENVIRONMENT ID IS NOT IN HERE, WHICH IS THE FIRST THING A READER OF
 * `secretAssociatedData` WILL EXPECT AND MUST NOT ADD.
 *
 * It CANNOT be. A grant is written in the same transaction that creates its
 * environment, for the reason `convex/environments.ts` states at that call
 * site: an environment with no grant is an environment whose secrets nobody can
 * ever read, discovered long after creation with no error at any point. The
 * server never sees a plaintext project data key, so the wrap happens in the
 * client BEFORE that mutation runs, at which point the environment has no id.
 * The only way to bind one would be to split creation into two mutations, and
 * the state between them is precisely the un-openable environment this design
 * exists to make unrepresentable. A worse failure, bought with a weaker one.
 *
 * AND IT IS NOT NEEDED, which is why the trade is acceptable rather than merely
 * forced. A project data key IS the environment: it is minted per environment
 * and opens nothing else. The environment binding that matters is carried by
 * {@link secretAssociatedData}, which binds EVERY ciphertext this key opens to
 * the environment it belongs to. A grant blob moved into another environment's
 * row by someone with database write access yields a key that opens none of
 * that environment's secrets. That is a failure, loudly, and not an escalation:
 * the mover cannot produce a wrap the target's grantee can open without already
 * holding the grantee's key, and if they held that they would not need the row.
 *
 * WHY THE GRANTEE IS IN HERE. `granteeType` and `granteeId` are COLUMNS, and a
 * column is not authenticated. Naming the grantee inside the associated data is
 * what makes a row whose grantee fields were edited stop opening instead of
 * claiming to belong to somebody it does not. It also separates the two
 * namespaces: a `users` document id and a `tokenIdHash` are both opaque
 * strings, and one wrapping key can hold grants of both kinds.
 *
 * WHY `pdkVersion` IS NOT IN HERE. It is the same call `secrets` makes: the
 * version bound into associated data is the PROTOCOL version, `/v1`, and the
 * key version lives in a column. Binding `pdkVersion` would buy nothing against
 * the only rollback that works anyway -- restoring the whole earlier row, whose
 * associated data was correct for its own version -- while forcing every client
 * to predict the version the server will assign to an environment it has not
 * created yet.
 *
 * THE ARGUMENT IS AN OBJECT, NOT A JOINED STRING, for the reason above: naming
 * the fields at every call site is what makes a diff that swaps a user id for a
 * token hash visible.
 */
export function pdkAssociatedData(params: {
  granteeType: PDKGranteeType;
  granteeId: string;
}): Uint8Array {
  const { granteeType } = params;

  // Checked against the closed set rather than merely for being a string. An
  // unrecognised type is not a wrong value that fails later, it is a fourth
  // construction that succeeds and produces bytes no reader will reconstruct.
  if (typeof granteeType !== "string" || !GRANTEE_TYPES.includes(granteeType)) {
    throw new Error(`granteeType must be one of ${GRANTEE_TYPES.join(", ")}`);
  }
  const granteeId = assertIdentifier("granteeId", params.granteeId);

  // Unambiguous by construction: the prefix is fixed, `granteeType` is one of
  // two known literals, and `granteeId` cannot contain the separator. No two
  // distinct inputs produce one string.
  return utf8.encode(PDK_AAD_PREFIX + granteeType + SEPARATOR + granteeId);
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
