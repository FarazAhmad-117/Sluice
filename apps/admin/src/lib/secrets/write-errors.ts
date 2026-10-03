import { ConvexError } from "convex/values";

/**
 * WHAT A PERSON IS TOLD WHEN A WRITE IS REFUSED, AND WHETHER RELOADING HELPS.
 *
 * Every write this dashboard makes is sealed for an exact slot: a secret's
 * permanent id and the version the new ciphertext IS, under the environment
 * key generation this tab opened. The server refuses a write whose slot is no
 * longer the next one, and it has exactly two sentences for that:
 *
 *   - somebody else saved a newer version of this secret first, so this tab's
 *     "version N+1" is stale and the ciphertext is bound to the wrong version;
 *   - the environment was re-keyed, so this tab sealed under a key generation
 *     the environment has moved on from.
 *
 * Neither is an error the user can fix by trying again. Retrying would send
 * the same stale slot and be refused the same way, for ever, because the key
 * and the version this tab holds are fetched once (see
 * `environment-key.ts`). What fixes it is reloading, which fetches the
 * current version and re-opens the current key. So both sentences are shown
 * EXACTLY AS WRITTEN, because the server wrote them for a person and they say
 * what happened, and they come with a reload control. Swallowing them into a
 * generic "that did not work" would leave somebody pressing Save on a form
 * that can never succeed.
 *
 * BOTH CAN HAPPEN NOW. The edit drawer (`edit-secret.ts`) calls
 * `updateSecret` and `updateSharedSecret`, which refuse a stale version; and
 * `updateSharedSecret` also refuses a row set that is no longer the share's
 * (a third sentence, below), which a reload fixes the same way.
 *
 * MATCHED BY EXACT TEXT, which is a coupling, and it is pinned from the server
 * side: `convex/secrets.test.ts` (end to end) provokes both refusals through
 * the real secret mutations, and `convex/tokens.test.ts` provokes the key
 * refusal through the real `createServiceToken`, each asserting this module
 * recognises what came back. The sentences are not imported from `convex/`
 * because that would pull server modules into the browser bundle.
 */

/** `convex/secrets.ts`, `STALE_VERSION`. */
export const STALE_SECRET_VERSION =
  "This secret changed since you opened it. Reload to see the latest version.";

/** `convex/secrets.ts` and `convex/tokens.ts`, `STALE_PDK_VERSION`, one sentence in both. */
export const STALE_ENVIRONMENT_KEY =
  "This environment's key changed since you opened it. Reload and try again.";

/**
 * `convex/lib/errors.ts`, `SHARED_ROWS_MISMATCH`: a shared write named a set
 * of rows that is no longer the share's (an environment was added, or a row
 * was overridden or deleted, since this tab listed it).
 */
export const SHARED_ROWS_CHANGED =
  "This project's environments changed since you opened it. Reload and try again.";

const RELOAD_FIXES: readonly string[] = [STALE_SECRET_VERSION, STALE_ENVIRONMENT_KEY, SHARED_ROWS_CHANGED];

export interface WriteFailure {
  /** A sentence for a person. Never a raw transport error, never a ciphertext. */
  readonly message: string;
  /** True when the only thing that can make the write succeed is a reload. */
  readonly reload: boolean;
}

/**
 * Turns anything a write throws into a sentence, and says whether to offer a
 * reload.
 *
 * `ConvexError.data` carries the server's own message, which is already written
 * for a person and deliberately says nothing it should not. Everything else
 * gets a generic line: a raw transport error is noise, and a thrown value on
 * these paths can carry ciphertext.
 */
export function describeWriteFailure(cause: unknown): WriteFailure {
  if (cause instanceof ConvexError && typeof cause.data === "string" && cause.data.length > 0) {
    return { message: cause.data, reload: RELOAD_FIXES.includes(cause.data) };
  }
  if (cause instanceof Error && cause.name === "PdkUnwrapError") {
    return { message: cause.message, reload: false };
  }
  return { message: "That did not work. Try again.", reload: false };
}
