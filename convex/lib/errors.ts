/**
 * SERVER ERROR SENTENCES THAT A CLIENT MATCHES ON.
 *
 * Convex errors cross the wire as a `ConvexError` whose `data` is a sentence,
 * not a code. When a client must react to one specific refusal, it can only do
 * so by comparing that sentence, and a sentence restated on both sides is one
 * edit away from drifting: the server rewords it, the client's match silently
 * stops firing, and nobody notices. Each such sentence is therefore defined
 * once, here, and imported by both the mutation that throws it and the client
 * that recognises it.
 *
 * THIS FILE MUST NOT IMPORT ANYTHING. The dashboard pulls it into the browser
 * bundle through the `@convex` alias, so an import of `./_generated/server`,
 * a repo module or any server-only library here would ship server code to the
 * browser. Plain string constants only.
 */

/**
 * `auth.signup`'s refusal when the client-minted `usr_` uid is already held by
 * another account. With 128 random bits this should never happen honestly; if
 * it does, it is a broken random source or a replayed request, and submitting
 * again, which mints a fresh uid, is the correct remedy.
 */
export const DUPLICATE_UID = "An account already exists with that uid.";

/**
 * `secrets.createSharedSecret`'s refusal when the rows it was handed are not
 * exactly one per environment of the project: one missing, one extra, one
 * from another project, or one environment named twice. The honest cause is a
 * dashboard that loaded the environment list before somebody added or removed
 * one, so the remedy is to reload and seal again.
 */
export const SHARED_ROWS_MISMATCH =
  "This project's environments changed since you opened it. Reload and try again.";

/**
 * `secrets.createSharedSecret`'s refusal when every row is marked overridden.
 * A shared secret whose shared value no environment uses is N unrelated
 * secrets wearing a group label, and the dashboard would show "All
 * environments" over a value nobody reads.
 */
export const SHARED_NEEDS_SHARED_ROW =
  "A secret for all environments needs at least one environment using the shared value.";

/**
 * `secrets.createSharedSecret`'s refusal when the client-minted `shr_` id is
 * already carried by any row. Accepting it would fold the new rows into an
 * existing group, which the dashboard would then label and delete together.
 * Minting a fresh id and submitting again is the remedy.
 */
export const DUPLICATE_SHARE_UID = "That shared secret id is already in use.";
