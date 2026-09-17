import { ConvexError, v } from "convex/values";
import { query } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import { verifyBundleToken } from "./lib/jwt";
import { getEnvironment } from "./repo/environments";
import { listCurrentSecretsByEnvironment } from "./repo/secrets";
import {
  getServiceToken,
  listRevocationsByTokenIdHash,
  normaliseServiceTokenId,
} from "./repo/tokens";

/**
 * THE REACTIVE SUBSCRIPTION THAT MAKES INSTANT REVOCATION REAL.
 *
 * This is a QUERY, and that is the whole product. Convex re-runs a query when a
 * row it read changes and pushes the new result to every live subscriber, so
 * the moment a `revocations` row lands, every process holding a subscription
 * for that token receives the signed notice without asking for it. Nothing here
 * polls, and no interval bounds how long a revoked workload keeps running.
 *
 * FOUR THINGS ABOUT THIS FUNCTION ARE LOAD BEARING. Changing any of them
 * silently breaks the kill switch, which is the failure this product cannot
 * have.
 *
 * ONE: A REVOKED TOKEN IS STILL SERVED. Refusing it looks like obvious
 * hardening and is the worst thing this query could do. The signed notice is
 * the only thing that makes a workload shut itself down, and this query is how
 * it gets there. Slam the door and every revoked process keeps running, holding
 * the secrets it already had, never told. What a revoked token stops receiving
 * is SECRETS, which is the server's half of the defence against an SDK that
 * ignores the notice; the notice itself always goes out.
 *
 * TWO: THE JOIN IS ON `tokenIdHash`, NOT ON THE PLAINTEXT TOKEN ID.
 * `serviceTokens` stores only the hash, so an authenticated token is knowable
 * to this server only by its hash. The alternative was carrying the plaintext
 * id in the bundle token, which would push the very identifier the hash exists
 * to protect into a bearer credential, into SDK memory, and into every log that
 * prints a JWT. The hash is read off the row this query already loaded, so the
 * join costs nothing extra. `tokens.ts` writes both sides with `tokenIdHash`
 * from `@sluice/crypto`; if they ever disagreed, NOTHING WOULD THROW and the
 * notice would silently never arrive.
 *
 * THREE: THE ENVIRONMENT COMES FROM THE ROW, NEVER FROM AN ARGUMENT. This
 * query takes exactly one argument, the credential. There is no environment id
 * to tamper with, so a token cannot address an environment other than its own
 * however it is presented.
 *
 * FOUR: EVERYTHING RETURNED IS CIPHERTEXT OR PUBLIC MATERIAL. The server never
 * decrypts and cannot: the project data key reaches the client only as
 * `wrappedPDK`, sealed to a key derived from the token secret, which never
 * leaves the customer's process.
 *
 * A KNOWN LIMIT, recorded because it is invisible at the call site and is the
 * same one `authz.ts` records for sessions. Convex re-runs a query when a row
 * it read changes, not when the clock moves, so a live subscription whose
 * bundle token has expired is not re-evaluated at the instant of expiry. That
 * bounds how long a stale credential keeps a subscription open; it does NOT
 * delay a revocation, because a revocation is a row change and re-runs this
 * query immediately, which is the direction that matters. The five minute
 * lifetime is enforced on every new subscription and on every re-run.
 */

/**
 * One string for every refusal: a forged credential, an expired one, one whose
 * service token has been deleted, and a malformed one. The caller learns that
 * it failed and nothing else, and in particular cannot use the pair of messages
 * to discover which `serviceTokens` ids exist.
 *
 * It does not name the token, and nothing below interpolates it. The bundle
 * token is a bearer credential, so the rule `authz.ts` states for session
 * tokens applies unchanged: it never appears in a log line, an error message,
 * an audit row or a URL.
 */
const REFUSED = "Bundle refused.";

function refuse(): never {
  throw new ConvexError(REFUSED);
}

const secretShape = {
  secretId: v.id("secrets"),
  lineageId: v.string(),
  version: v.number(),
  // Which project data key version opened this row. The bundle can legitimately
  // contain rows at more than one version during a re-key, and the client has
  // no other way to tell which key to use.
  pdkVersion: v.number(),
  nameCiphertext: v.string(),
  nameNonce: v.string(),
  valueCiphertext: v.string(),
  valueNonce: v.string(),
};

/**
 * The notice, in the exact field set `verifyRevocation` signs over, plus the
 * signature.
 *
 * It carries the PLAINTEXT token id, and that is correct rather than an
 * inconsistency with everything above. The signature covers the plaintext id,
 * so an SDK that received the hash could not verify anything, and the only
 * party this is ever sent to is the holder of that very token. The hash exists
 * to keep the id out of the DATABASE and out of bearer credentials, not out of
 * the hands of the one process that already has it.
 */
const revocationShape = {
  tokenId: v.string(),
  epoch: v.number(),
  revokedAt: v.number(),
  reason: v.string(),
  signature: v.string(),
};

export const getBundle = query({
  // One argument, and it is the credential. See THREE above.
  args: { token: v.string() },
  returns: v.object({
    // The client needs this to compute the secret associated data. See
    // `secretAssociatedData` in `@sluice/crypto`, which is the one definition
    // of that rule.
    environmentId: v.id("environments"),
    epoch: v.number(),
    pdkVersion: v.number(),
    wrappedPDK: v.string(),
    pdkNonce: v.string(),
    secrets: v.array(v.object(secretShape)),
    revocationNotice: v.optional(v.object(revocationShape)),
  }),
  handler: async (ctx, args) => {
    const claims = verifyBundleToken({ token: args.token, now: Date.now() });
    if (claims === null) refuse();

    // The subject is a document id this deployment signed, so it is not
    // attacker chosen. It is normalised anyway: a get on a malformed id throws
    // rather than returning null, and a crash is a second, observably
    // different refusal path. A string that is not an id and one that names no
    // row get the same answer as a deleted token.
    const subject = normaliseServiceTokenId(ctx, claims.subject);
    if (subject === null) refuse();

    const token = await getServiceToken(ctx, subject);
    if (token === null) refuse();

    const environment = await getEnvironment(ctx, token.environmentId);
    if (environment === null) refuse();

    // THE JOIN. On the hash, off the row. See TWO above.
    const revocationNotice = highestEpoch(
      await listRevocationsByTokenIdHash(ctx, token.tokenIdHash),
    );

    // A revoked token gets the notice and no secrets. See ONE above.
    const secrets =
      revocationNotice === undefined
        ? await listCurrentSecretsByEnvironment(ctx, environment._id)
        : [];

    return {
      environmentId: environment._id,
      // The ENVIRONMENT's epoch, which is the counter that moves when the
      // project data key is re-keyed, and the one `SecretBundle.epoch` in
      // `packages/sdk` is defined as. It is NOT the revocation epoch, which
      // lives per token id on the notice below. Two different numbers in two
      // different namespaces, and conflating them breaks the kill switch.
      epoch: environment.epoch,
      pdkVersion: environment.pdkVersion,
      // Sealed to a key derived from the token secret, which this server has
      // never held and cannot derive from anything it stores.
      wrappedPDK: token.wrappedPDK,
      pdkNonce: token.nonce,
      secrets: secrets.map(view),
      ...(revocationNotice === undefined ? {} : { revocationNotice }),
    };
  },
});

function view(secret: Doc<"secrets">) {
  return {
    secretId: secret._id,
    lineageId: secret.lineageId,
    version: secret.version,
    pdkVersion: secret.pdkVersion,
    nameCiphertext: secret.nameCiphertext,
    nameNonce: secret.nameNonce,
    valueCiphertext: secret.valueCiphertext,
    valueNonce: secret.valueNonce,
  };
}

/**
 * The newest notice, by epoch rather than by insertion order or by `revokedAt`.
 *
 * The SDK keeps a floor on the highest revocation epoch it has acted on and
 * ignores anything at or below it, so shipping an older notice would be
 * shipping one the SDK is required to discard, and a token could appear
 * un-revokable. `revokeServiceToken` already refuses a non-increasing epoch, so
 * in practice there is one candidate; this picks correctly anyway rather than
 * depending on a rule enforced somewhere else.
 */
function highestEpoch(revocations: Doc<"revocations">[]) {
  let newest: Doc<"revocations"> | undefined;
  for (const row of revocations) {
    if (newest === undefined || row.epoch > newest.epoch) newest = row;
  }
  if (newest === undefined) return undefined;
  return {
    tokenId: newest.tokenId,
    epoch: newest.epoch,
    revokedAt: newest.revokedAt,
    reason: newest.reason,
    signature: newest.signature,
  };
}
